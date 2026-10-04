#include <android/log.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "Dobby/dobby.h"
#include "xdl.h"

#define LOG_TAG "AntiDetection"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Root binaries / directories apps probe for with access()/stat()/File.exists().
// Deliberately conservative: only system / sbin / data-adb / data-local paths.
// Never anything under /data/data or /data/user (that is app data for the guest
// and for FridaBox itself — blocking it would break the sandbox).
static const char* blocked_paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/.ext/.su",
        "/system/xbin/daemonsu",
        "/system/xbin/mu",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/bin/magisk",
        "/system/xbin/magisk",
        "/sbin/magisk",
        "/sbin/.magisk",
        "/sbin/.core/mirror",
        "/dev/.magisk",
        "/cache/.disable_magisk",
        "/data/adb/magisk",
        "/data/adb/modules",
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/system/bin/busybox",
        "/system/xbin/busybox",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/data/local/tmp/su",
        nullptr
};

static bool is_blocked(const char* path) {
    if (path == nullptr) return false;
    // Never touch app-data paths — the guest and FridaBox live there.
    if (strncmp(path, "/data/data/", 11) == 0) return false;
    if (strncmp(path, "/data/user/", 11) == 0) return false;
    for (int i = 0; blocked_paths[i] != nullptr; ++i) {
        if (strcmp(path, blocked_paths[i]) == 0) {
            return true;
        }
    }
    return false;
}

static int (*orig_access)(const char*, int) = nullptr;
static int (*orig_stat)(const char*, struct stat*) = nullptr;
static int (*orig_lstat)(const char*, struct stat*) = nullptr;
static FILE* (*orig_fopen)(const char*, const char*) = nullptr;

static int my_access(const char* pathname, int mode) {
    if (is_blocked(pathname)) { errno = ENOENT; return -1; }
    return orig_access ? orig_access(pathname, mode) : -1;
}

static int my_stat(const char* pathname, struct stat* buf) {
    if (is_blocked(pathname)) { errno = ENOENT; return -1; }
    return orig_stat ? orig_stat(pathname, buf) : -1;
}

static int my_lstat(const char* pathname, struct stat* buf) {
    if (is_blocked(pathname)) { errno = ENOENT; return -1; }
    return orig_lstat ? orig_lstat(pathname, buf) : -1;
}

static FILE* my_fopen(const char* pathname, const char* mode) {
    if (is_blocked(pathname)) { errno = ENOENT; return nullptr; }
    return orig_fopen ? orig_fopen(pathname, mode) : nullptr;
}

static void hook_one(void* handle, const char* sym, void* replace, void** orig) {
    void* target = xdl_dsym(handle, sym, nullptr);
    if (!target) target = xdl_sym(handle, sym, nullptr);
    if (!target) { LOGD("symbol not found: %s", sym); return; }
    if (DobbyHook(target, replace, orig) == 0) {
        LOGD("hooked %s", sym);
    } else {
        LOGD("hook failed: %s", sym);
    }
}

// Hook only the existence-check calls (access/stat/lstat/fopen). open/opendir are
// left alone to keep the guest's hot IO path untouched.
static void install_file_hooks() {
    void* handle = xdl_open("libc.so", XDL_DEFAULT);
    if (!handle) { LOGD("xdl_open libc.so failed"); return; }
    hook_one(handle, "access", (void*) my_access, (void**) &orig_access);
    hook_one(handle, "stat", (void*) my_stat, (void**) &orig_stat);
    hook_one(handle, "lstat", (void*) my_lstat, (void**) &orig_lstat);
    hook_one(handle, "fopen", (void*) my_fopen, (void**) &orig_fopen);
    xdl_close(handle);
    LOGD("root-path file hooks installed");
}

__attribute__((constructor)) void install_antidetection_hooks() {
    install_file_hooks();
}
