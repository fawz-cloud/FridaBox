// P1 /proc maps mediation (gated off by default).
//
// Mediates the /proc maps family via memfd substitution: when the guest opens
// one of the maps views, the real file is read through the original libc call,
// run through a pure line filter that drops instrumentation-owned mappings, and
// the filtered bytes are served from an anonymous memfd. Any failure anywhere
// falls through to the original fd/stream, so the hook can never crash or loop.
//
// This is a fidelity/fingerprint experiment, not an app-specific bypass. It
// cannot be device-tested from the maintainer's build host, so the hook install
// is gated behind an off-by-default system property (palka.procmaps=1). With the
// property unset the constructor returns immediately and this file has zero
// runtime effect, which makes it safe to merge. The pure filter carries a
// host-compilable self-check under -DPROCMAPS_SELFTEST.
//
// Covered views and residual leaks are documented in
// docs/research/PROC_MAPS_MEDIATION_IMPL.md.

#include <cstring>
#include <string>

// --------------------------------------------------------------------------
// Pure, host-compilable core (compiled in both the Android build and the
// -DPROCMAPS_SELFTEST host build).
// --------------------------------------------------------------------------

// Pathname substrings whose presence marks a mapping as instrumentation-owned.
// Deliberately broad (short tokens like "gum"/"inject" can match coincidental
// names such as libgumbo.so); see the residual-tradeoffs note in the doc.
static const char *kHiddenMarkers[] = {
        "libblackbox",
        "inject",
        "frida",
        "gum",
        "gadget",
        "guest-runtime",
        "guest-agents",
        "com.qm4rs.fridabox",
        "linjector",
        nullptr,
};

static inline bool is_ws(char c) { return c == ' ' || c == '\t'; }

static bool all_digits(const char *s, const char *end) {
    if (s == end) return false;
    for (const char *p = s; p < end; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

// Matches exactly the maps family: /proc/self/maps, /proc/<pid>/maps,
// /proc/self/task/<tid>/maps, /proc/<pid>/task/<tid>/maps. Only absolute
// /proc paths match (openat with a path relative to a /proc dirfd is not
// mediated — documented as a residual gap).
static bool is_maps_path(const char *path) {
    if (!path) return false;
    if (strncmp(path, "/proc/", 6) != 0) return false;

    const char *p = path + 6;             // first component start
    const char *slash = strchr(p, '/');   // first component end
    if (!slash) return false;

    bool c1_ok = (slash - p == 4 && strncmp(p, "self", 4) == 0) || all_digits(p, slash);
    if (!c1_ok) return false;

    const char *rest = slash;             // "/maps" or "/task/<tid>/maps"
    if (strcmp(rest, "/maps") == 0) return true;

    if (strncmp(rest, "/task/", 6) != 0) return false;
    const char *t = rest + 6;             // tid start
    const char *tslash = strchr(t, '/');
    if (!tslash) return false;
    if (!all_digits(t, tslash)) return false;
    return strcmp(tslash, "/maps") == 0;
}

// Returns the pathname field of one maps line: everything after the fifth
// whitespace-delimited field (addr perms offset dev inode). Empty for an
// anonymous mapping.
static std::string maps_pathname(const std::string &line) {
    const size_t n = line.size();
    size_t i = 0;
    for (int fields = 0; fields < 5 && i < n; ++fields) {
        while (i < n && !is_ws(line[i])) ++i;   // skip token
        while (i < n && is_ws(line[i])) ++i;     // skip separators
    }
    if (i >= n) return std::string();
    return line.substr(i);
}

static bool pathname_is_hidden(const std::string &pathname) {
    if (pathname.empty()) return false;
    for (int k = 0; kHiddenMarkers[k]; ++k) {
        if (pathname.find(kHiddenMarkers[k]) != std::string::npos) return true;
    }
    return false;
}

// Drops every line whose pathname field contains a hidden marker, preserving
// all other lines (and the trailing newline) byte-for-byte.
static std::string filter_maps_buffer(const char *buf) {
    std::string out;
    if (!buf) return out;
    const std::string input(buf);
    size_t start = 0;
    while (start <= input.size()) {
        const size_t nl = input.find('\n', start);
        const bool last = (nl == std::string::npos);
        const std::string line = input.substr(start, last ? std::string::npos : nl - start);
        if (!pathname_is_hidden(maps_pathname(line))) {
            out += line;
            if (!last) out += '\n';
        }
        if (last) break;
        start = nl + 1;
    }
    return out;
}

#ifndef PROCMAPS_SELFTEST

// --------------------------------------------------------------------------
// Android install side. Skeleton modeled on Utils/VirtualSpoof.cpp:
// xdl_open("libc.so") -> resolve -> DobbyHook -> xdl_close.
// --------------------------------------------------------------------------

#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <android/log.h>
#include "./xdl.h"
#include "Dobby/dobby.h"

#define LOG_TAG "ProcMaps"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static int (*orig_open)(const char *, int, ...) = nullptr;
static int (*orig_open64)(const char *, int, ...) = nullptr;
static int (*orig_openat)(int, const char *, int, ...) = nullptr;
static int (*orig_openat64)(int, const char *, int, ...) = nullptr;
static FILE *(*orig_fopen)(const char *, const char *) = nullptr;
static FILE *(*orig_fopen64)(const char *, const char *) = nullptr;

// Reads the real maps file via the original open, filters it, and serves the
// result from a fresh memfd positioned at offset 0. Returns -1 on any error so
// the caller falls through to the unmediated original (bounded failure).
static int build_filtered_memfd(const char *path) {
    if (!orig_open) return -1;
    int rfd = orig_open(path, O_RDONLY | O_CLOEXEC);
    if (rfd < 0) return -1;

    std::string raw;
    char tmp[8192];
    ssize_t n;
    while ((n = read(rfd, tmp, sizeof(tmp))) > 0) raw.append(tmp, static_cast<size_t>(n));
    close(rfd);
    if (n < 0) return -1;

    const std::string filtered = filter_maps_buffer(raw.c_str());

    int mfd = static_cast<int>(syscall(__NR_memfd_create, "palka-maps", 0));
    if (mfd < 0) return -1;

    const char *p = filtered.data();
    size_t left = filtered.size();
    while (left > 0) {
        ssize_t w = write(mfd, p, left);
        if (w <= 0) {
            close(mfd);
            return -1;
        }
        p += w;
        left -= static_cast<size_t>(w);
    }
    if (lseek(mfd, 0, SEEK_SET) < 0) {
        close(mfd);
        return -1;
    }
    return mfd;
}

static int open_common(int (*orig)(const char *, int, ...), const char *path,
                       int flags, mode_t mode, bool has_mode) {
    if (path && is_maps_path(path)) {
        int fd = build_filtered_memfd(path);
        if (fd >= 0) return fd;
    }
    if (!orig) {
        errno = ENOSYS;
        return -1;
    }
    return has_mode ? orig(path, flags, mode) : orig(path, flags);
}

static int openat_common(int (*orig)(int, const char *, int, ...), int dirfd,
                         const char *path, int flags, mode_t mode, bool has_mode) {
    if (path && is_maps_path(path)) {
        int fd = build_filtered_memfd(path);
        if (fd >= 0) return fd;
    }
    if (!orig) {
        errno = ENOSYS;
        return -1;
    }
    return has_mode ? orig(dirfd, path, flags, mode) : orig(dirfd, path, flags);
}

static FILE *fopen_common(FILE *(*orig)(const char *, const char *),
                          const char *path, const char *mode) {
    if (path && is_maps_path(path)) {
        int fd = build_filtered_memfd(path);
        if (fd >= 0) {
            FILE *f = fdopen(fd, "r");
            if (f) return f;
            close(fd);
        }
    }
    return orig ? orig(path, mode) : nullptr;
}

static int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    bool hm = (flags & O_CREAT) != 0;
    if (hm) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    return open_common(orig_open, path, flags, mode, hm);
}

static int my_open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    bool hm = (flags & O_CREAT) != 0;
    if (hm) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    return open_common(orig_open64, path, flags, mode, hm);
}

static int my_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    bool hm = (flags & O_CREAT) != 0;
    if (hm) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    return openat_common(orig_openat, dirfd, path, flags, mode, hm);
}

static int my_openat64(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    bool hm = (flags & O_CREAT) != 0;
    if (hm) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    return openat_common(orig_openat64, dirfd, path, flags, mode, hm);
}

static FILE *my_fopen(const char *path, const char *mode) {
    return fopen_common(orig_fopen, path, mode);
}

static FILE *my_fopen64(const char *path, const char *mode) {
    return fopen_common(orig_fopen64, path, mode);
}

static void hook_one(void *handle, const char *sym, void *repl, void **orig) {
    void *target = xdl_sym(handle, sym, nullptr);
    if (!target) target = xdl_dsym(handle, sym, nullptr);
    if (target) {
        DobbyHook(target, repl, orig);
    }
}

static bool procmaps_enabled() {
    char v[PROP_VALUE_MAX] = {0};
    __system_property_get("palka.procmaps", v);
    return strcmp(v, "1") == 0;
}

static void install_procmaps_hooks() {
    void *handle = xdl_open("libc.so", XDL_DEFAULT);
    if (!handle) {
        LOGD("xdl_open failed for libc.so");
        return;
    }
    hook_one(handle, "open", (void *) my_open, (void **) &orig_open);
    hook_one(handle, "open64", (void *) my_open64, (void **) &orig_open64);
    hook_one(handle, "openat", (void *) my_openat, (void **) &orig_openat);
    hook_one(handle, "openat64", (void *) my_openat64, (void **) &orig_openat64);
    hook_one(handle, "fopen", (void *) my_fopen, (void **) &orig_fopen);
    hook_one(handle, "fopen64", (void *) my_fopen64, (void **) &orig_fopen64);
    xdl_close(handle);
    LOGD("ProcMaps mediation installed (palka.procmaps=1)");
}

__attribute__((constructor)) void init_procmaps() {
    if (!procmaps_enabled()) return;  // off by default: zero runtime effect
    install_procmaps_hooks();
}

#else  // PROCMAPS_SELFTEST

// --------------------------------------------------------------------------
// Host self-check:  g++ -DPROCMAPS_SELFTEST ProcMaps.cpp -o procmaps_selftest
// Exercises the pure filter and path matcher only (no NDK/Dobby/xdl).
// --------------------------------------------------------------------------

#include <cassert>
#include <cstdio>

// Structural grammar check: "addr-addr perms offset dev inode [pathname]".
static bool valid_maps_line(const std::string &line) {
    unsigned long a, b, off, ino;
    char perms[8], dev[16];
    int m = sscanf(line.c_str(), "%lx-%lx %7s %lx %15s %lu", &a, &b, perms, &off, dev, &ino);
    return m == 6;
}

int main() {
    const char *sample =
            "7f0000000000-7f0000001000 r-xp 00000000 fe:00 100  /system/lib64/libc.so\n"
            "7f0000002000-7f0000003000 r--p 00001000 fe:00 101  /system/lib64/libart.so\n"
            "7f0000004000-7f0000005000 r-xp 00000000 fe:00 200  /data/app/~~x/base.apk!/lib/arm64-v8a/libblackbox.so\n"
            "7f0000006000-7f0000007000 rw-p 00000000 00:00 0    [anon:frida-agent]\n"
            "7f0000008000-7f0000009000 rw-p 00000000 00:00 0    [stack]\n"
            "7f000000a000-7f000000b000 rw-p 00000000 00:00 0\n";

    const std::string out = filter_maps_buffer(sample);

    // Hidden lines are gone.
    assert(out.find("libblackbox") == std::string::npos);
    assert(out.find("frida") == std::string::npos);

    // Non-hidden lines are untouched (present verbatim).
    assert(out.find("/system/lib64/libc.so") != std::string::npos);
    assert(out.find("/system/lib64/libart.so") != std::string::npos);
    assert(out.find("[stack]") != std::string::npos);

    // Every surviving non-empty line still matches the maps grammar.
    size_t start = 0;
    int kept = 0;
    while (start <= out.size()) {
        size_t nl = out.find('\n', start);
        bool last = (nl == std::string::npos);
        std::string line = out.substr(start, last ? std::string::npos : nl - start);
        if (!line.empty()) {
            assert(valid_maps_line(line));
            ++kept;
        }
        if (last) break;
        start = nl + 1;
    }
    assert(kept == 4);  // libc, libart, [stack], and the trailing anon line

    // Path matcher: the maps family matches, neighbours do not.
    assert(is_maps_path("/proc/self/maps"));
    assert(is_maps_path("/proc/1234/maps"));
    assert(is_maps_path("/proc/self/task/4567/maps"));
    assert(is_maps_path("/proc/1234/task/4567/maps"));
    assert(!is_maps_path("/proc/self/smaps"));
    assert(!is_maps_path("/proc/self/map_files/x"));
    assert(!is_maps_path("/proc/self/status"));
    assert(!is_maps_path("/proc/self/maps/extra"));
    assert(!is_maps_path("/proc/self/task/abc/maps"));
    assert(!is_maps_path("/etc/passwd"));
    assert(!is_maps_path(nullptr));

    printf("PROCMAPS_SELFTEST OK (kept=%d)\n", kept);
    return 0;
}

#endif  // PROCMAPS_SELFTEST
