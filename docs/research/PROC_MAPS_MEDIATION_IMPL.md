# /proc maps mediation (implementation notes)

Implements the first slice of the ROADMAP "P1 — `/proc` and process-map
consistency" item: a coherent mediation layer for the **maps family only**,
with every other access path left explicitly unmediated so residual leaks stay
visible.

Source: `Bcore/src/main/cpp/Utils/ProcMaps.cpp`.

## Mechanism

For a path in the maps family the hook reads the real file through the original
libc call, runs the bytes through the pure `filter_maps_buffer`, writes the
result to an anonymous `memfd_create` fd, seeks to 0, and returns that fd
(`fdopen`'d for the `fopen` family). `filter_maps_buffer` drops any line whose
**pathname field** contains one of the hidden markers:

    libblackbox, inject, frida, gum, gadget,
    guest-runtime, guest-agents, com.qm4rs.fridabox, linjector

All other lines, and the trailing newline, are preserved byte-for-byte, so the
filtered buffer remains structurally valid `addr-addr perms off dev inode
[path]` output.

**Bounded failure.** Any error at any step — unresolved original, read failure,
`memfd_create` failure, short write, failed seek — falls through to the
unmediated original fd/stream. The hook never crashes, never loops, and never
synthesizes a fake file.

## Gating (why this is safe to merge untested)

The maintainer cannot device-test this. The `DobbyHook` install is therefore
gated behind an off-by-default runtime check: `init_procmaps` installs hooks
only when `__system_property_get("palka.procmaps")` returns `"1"`. With the
property unset the constructor returns immediately and this translation unit has
**zero runtime effect**. Enable on an owned device with:

    adb shell setprop palka.procmaps 1   # before the guest process starts

A host-compilable self-check guards the pure logic:

    g++ -std=c++17 -DPROCMAPS_SELFTEST Bcore/src/main/cpp/Utils/ProcMaps.cpp -o /tmp/t && /tmp/t

It asserts a `libblackbox`/`frida` line is removed, surviving lines still parse
as maps grammar, non-hidden lines are untouched, and `is_maps_path` accepts the
four maps-family forms while rejecting their neighbours.

## Covered views

Intercepted libc entry points: `open`, `open64`, `openat`, `openat64`, `fopen`,
`fopen64`. Mediated paths (absolute only):

- `/proc/self/maps`
- `/proc/<pid>/maps`
- `/proc/self/task/<tid>/maps`
- `/proc/<pid>/task/<tid>/maps`

## NOT covered (residual leaks — the same fact still appears elsewhere)

This slice filters the maps file and nothing else. The following expose the
hidden mappings or process state through other interfaces and are untouched:

- **`/proc/<pid>/smaps`** and `smaps_rollup` — per-mapping detail, not filtered.
- **`/proc/<pid>/map_files/`** — directory of `addr-addr -> path` symlinks.
- **`dl_iterate_phdr` / linker module lists** — in-process enumeration that
  never touches the maps file.
- **`/proc/<pid>/status` `TracerPid`** and other status fields.
- **`/proc/net/*`** — Frida's loopback listener sockets.
- **Anonymous trampoline / hook pages** — Dobby's own code pages appear as
  legitimate-looking anonymous mappings and are not removed.
- **Inline / direct syscalls** — a guest that invokes `openat`/`read` via `svc`
  (or a raw `syscall(SYS_openat, ...)`) bypasses the libc hooks entirely.
- **`openat` with a path relative to a `/proc` dirfd** — only absolute `/proc`
  paths match `is_maps_path`.
- **`mmap`/`pread` of an already-open real fd**, or an fd inherited before the
  hook installed.

## Known tradeoffs

- **memfd identity leak.** The served fd is an anonymous memfd, so
  `readlink("/proc/self/fd/N")` shows `/memfd:palka-maps (deleted)` and `fstat`
  reports an anonymous inode instead of the proc file. This is itself a
  detectable signal; a stronger approach would overwrite in place or proxy at a
  lower layer.
- **Over-broad markers.** Short tokens (`gum`, `inject`) can match coincidental
  library names (e.g. `libgumbo.so`), dropping legitimate lines. Dropping a line
  that "should" be present is itself a fingerprint. Marker breadth vs. precision
  is left as a tuning knob rather than hard-coded as correct.

No app-specific anti-detection logic is included. This is general fidelity work
on an authorized research target.
