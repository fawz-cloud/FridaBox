#include <sys/system_properties.h>
#include <cstring>
#include <cstdint>
#include "./xdl.h"
#include <android/log.h>
#include <dlfcn.h>
#include "Dobby/dobby.h"


#define LOG_TAG "VirtualSpoof"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

struct SpoofedProp {
    const char* key;
    const char* value;
};

SpoofedProp spoofed_props[] = {
        {"ro.product.model", "Pixel 6"},
        {"ro.product.brand", "google"},
        {"ro.product.manufacturer", "Google"},
        {"ro.product.device", "oriole"},
        {"ro.build.fingerprint", "google/oriole/oriole:12/SP1A.210812.015/7679548:user/release-keys"},
        {"ro.build.version.release", "12"},
        {"ro.build.version.security_patch", "2022-01-05"},
        {"ro.serialno", "1A2B3C4D5E6F"},
        {"ro.hardware", "qcom"},
        {"ro.boot.hardware", "qcom"},
        {"ro.product.board", "lahaina"},
        {"ro.product.cpu.abi", "arm64-v8a"},
        {"ro.build.type", "user"},
        {"ro.build.tags", "release-keys"},
        {"ro.kernel.qemu", "0"},
        {"ro.kernel.android.qemud", ""},
        {"ro.hardware.egl", "adreno"},
        {"ro.boot.qemu", "0"},
        // Debug / tamper signals apps check for a developer or rooted device.
        {"ro.debuggable", "0"},
        {"ro.secure", "1"},
        {"ro.build.selinux", "1"},
        // Verified-boot / locked-bootloader signals.
        {"ro.boot.verifiedbootstate", "green"},
        {"ro.boot.flash.locked", "1"},
        {"ro.boot.veritymode", "enforcing"},
        {"ro.boot.vbmeta.device_state", "locked"},
        {"sys.oem_unlock_allowed", "0"},
    {nullptr, nullptr}
};


static const char* spoof_lookup(const char* name) {
    if (name == nullptr) return nullptr;
    for (int i = 0; spoofed_props[i].key != nullptr; ++i) {
        if (strcmp(name, spoofed_props[i].key) == 0) {
            return spoofed_props[i].value;
        }
    }
    return nullptr;
}


static int (*orig_system_property_get)(const char *name, char *value) = nullptr;


int my_system_property_get(const char *name, char *value) {
    const char* spoofed = spoof_lookup(name);
    if (spoofed != nullptr) {
        strcpy(value, spoofed);
        LOGD("[spoof] %s = %s", name, value);
        return (int) strlen(value);
    }
    if (orig_system_property_get) {
        return orig_system_property_get(name, value);
    }
    value[0] = '\0';
    return 0;
}


// Android 8+ routes SystemProperties.get() (and Build.TAGS/TYPE init) through
// __system_property_read_callback, not __system_property_get, so the callback
// path must be spoofed too.
typedef void (*prop_read_cb)(void *cookie, const char *name, const char *value, uint32_t serial);
static void (*orig_read_callback)(const prop_info *pi, prop_read_cb cb, void *cookie) = nullptr;

struct SpoofCookie {
    prop_read_cb cb;
    void *cookie;
};

static void spoof_trampoline(void *cookie, const char *name, const char *value, uint32_t serial) {
    SpoofCookie *sc = (SpoofCookie *) cookie;
    const char *spoofed = spoof_lookup(name);
    if (spoofed != nullptr) {
        LOGD("[spoof-cb] %s = %s", name, spoofed);
        sc->cb(sc->cookie, name, spoofed, serial);
    } else {
        sc->cb(sc->cookie, name, value, serial);
    }
}

static void my_read_callback(const prop_info *pi, prop_read_cb cb, void *cookie) {
    if (orig_read_callback == nullptr) return;
    SpoofCookie sc{cb, cookie};
    orig_read_callback(pi, spoof_trampoline, &sc);
}


void install_property_get_hook() {
    void* handle = xdl_open("libc.so", XDL_DEFAULT);
    if (handle == nullptr) {
        LOGD("xdl_open libc.so failed");
        return;
    }

    void* target = xdl_dsym(handle, "__system_property_get", nullptr);
    if (target) {
        if (DobbyHook(target, (void*)my_system_property_get, (void**)&orig_system_property_get) == 0) {
            LOGD("__system_property_get hook installed");
        } else {
            LOGD("__system_property_get hook failed");
        }
    }

    // Present on API 26+; absent on older libc (xdl_dsym returns null -> skip).
    void* cb_target = xdl_dsym(handle, "__system_property_read_callback", nullptr);
    if (cb_target) {
        if (DobbyHook(cb_target, (void*)my_read_callback, (void**)&orig_read_callback) == 0) {
            LOGD("__system_property_read_callback hook installed");
        } else {
            LOGD("__system_property_read_callback hook failed");
        }
    }

    xdl_close(handle);
}


__attribute__((constructor)) void init_virtual_spoof()
{
    install_property_get_hook();
    LOGD("VirtualSpoof: property hooks loaded");
}
