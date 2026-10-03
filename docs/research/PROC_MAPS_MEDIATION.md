# Research design: `/proc` and process-map mediation

Status: **design only — no hooks implemented yet.** This document specifies
behavior before code, per the ROADMAP P1 acceptance criteria ("behavior is
specified before hooks are added; direct and indirect reads are tested; filtered
output remains structurally valid; limitations and bypassable paths remain
explicit").

Scope: reduce the *avoidable* fingerprints that let a guest discover the Frida
Gadget (and, secondarily, the virtualization) by reading `/proc` and walking
loaded modules. This is **general fingerprint reduction**, not an app-specific
bypass, and it does **not** attempt to defeat Play Integrity, hardware
attestation, or a RASP that uses raw syscalls plus kernel-truth checks. See
[../DETECTION_SURFACES.md](../DETECTION_SURFACES.md) and
[../LIMITATIONS.md](../LIMITATIONS.md).

---

## 1. Why maps filtering alone is not a solution

The naive idea — "hook `open("/proc/self/maps")` and delete the Gadget lines" —
fails because the *same fact* (an executable region belonging to Frida) is
observable through many independent interfaces. Filtering one makes it
**inconsistent** with the others, which is itself a detection signal.

The repository already contains proof of the bypass it would have to defend
against: `Bcore/src/main/cpp/xdl/xdl_iterate.c` is a custom
`xdl_iterate_phdr` that enumerates the dynamic linker's internal `soinfo`
list. A RASP using the same technique sees the Gadget **without reading
`/proc/maps` at all**.

How the Gadget becomes visible today:

- `FridaGadgetLoader` loads it with `System.load(absolutePath)`
  (`Bcore/.../instrumentation/FridaGadgetLoader.java:54`), i.e. `dlopen`.
- `dlopen` creates a **file-backed executable mapping** whose path (e.g.
  `.../files/fridabox-gadget-runtimes/<pkg>/libpayload.so`) appears in
  `/proc/self/maps`, and **registers a `soinfo`** in the linker, visible to
  `dl_iterate_phdr`.

So two leaks exist from one load: a maps path **and** a linker entry.

---

## 2. Access-path inventory

Every row is a way to observe the Gadget's presence. A mediation layer must have
an answer for each, or declare it a residual leak.

### 2.1 File-backed `/proc` views

| Path | What it reveals | Reached by |
| --- | --- | --- |
| `/proc/self/maps`, `/proc/<pid>/maps` | mapping path + perms of the Gadget | `fopen`/`open`/`openat`, then `read`/`fgets` |
| `/proc/self/task/<tid>/maps` | same, per-thread (often forgotten by filters) | same |
| `/proc/self/smaps`, `smaps_rollup` | same regions + RSS/flags | same |
| `/proc/self/map_files/` | symlinks to backing files of mappings | `opendir`/`readlink` |
| `/proc/self/pagemap`, `statm` | region sizes / presence, no names | `open`+`read` |
| `/proc/self/status` (Uid, Threads, Seccomp) | host UID, thread count anomalies | `open`+`read` |
| `/proc/self/cmdline`, `/proc/self/comm` | `com.qm4rs.fridabox:pN` stub identity | `open`+`read` |
| `/proc/self/task/<tid>/comm` | Frida thread names (`gum-js-loop`, `gmain`, `pool-frida`) | `opendir`+`read` |
| `/proc/net/tcp`, `tcp6` | Gadget listener socket (listen mode only) | `open`+`read` |

### 2.2 Linker / loader views (do **not** touch `/proc`)

| Interface | What it reveals |
| --- | --- |
| `dl_iterate_phdr` | every loaded ELF incl. Gadget — the main bypass of maps filtering |
| linker `soinfo` walk (xdl-style) | same, even for linker-"hidden" libs |
| `dlopen(path, RTLD_NOLOAD)` / handle probing | whether a named lib is loaded |
| `android_dlopen_ext` namespace inspection | library namespaces |

### 2.3 Memory-scan views (content, not metadata)

| Technique | What it reveals |
| --- | --- |
| scan for strings `frida`, `gum`, `gum-js-loop`, `GLib`, `FridaScript` | Gadget/GumJS runtime in memory |
| find `rwx` or exec anon mappings not backed by a known file | a loaded-from-memory agent |
| exec region whose backing file name is "wrong" | relocated/renamed Gadget |

### 2.4 libc vs raw syscall (orthogonal to all of the above)

Each file read above is reachable either through a libc wrapper
(`open`/`openat`/`fopen`/`read`) **or** through a direct syscall
(`syscall(__NR_openat, ...)` or an inline `svc #0`). FridaBox hooks libc with
Dobby + xdl (see `Bcore/src/main/cpp/Hook/FileSystemHook.cpp`
`new_open`). **Dobby/PLT hooks on libc do not intercept a raw syscall.**

---

## 3. The consistency problem (the crux)

A filter that is not coherent across §2 is worse than none, because the
*discrepancy* is a reliable signal. Concrete cross-checks a RASP runs:

1. **maps vs `dl_iterate_phdr`** — Gadget removed from maps but present in the
   linker list → busted. (This is the big one; xdl in-repo proves it.)
2. **maps vs smaps vs task/maps** — filtering `maps` but not `smaps` or
   `task/<tid>/maps` → mismatch.
3. **"every exec region is file-backed"** — after hiding the Gadget's file path,
   an executable mapping with no backing file (or a hole where it was) →
   anomaly.
4. **maps vs `/proc/self/map_files/`** — the symlink set still points at the
   Gadget file.
5. **cmdline vs package identity** — Java process name spoofed to
   `com.bank.app` but `/proc/self/cmdline` says `com.qm4rs.fridabox:p3`.
6. **Java-PM UID vs `getuid()`** — faking `getPackageUid` at the Java layer
   contradicts the kernel UID in `/proc/self/status`.

Rule the design must follow: **either mediate a fact across *all* its paths
coherently, or do not mediate it and list it as residual.** Half-measures add
signal.

---

## 4. Design options

### Option A — Selective maps-family filtering (libc level)
Hook `open/openat/fopen` for the `maps|smaps|smaps_rollup|task/*/maps|map_files`
set; wrap the returned fd/stream so `read` strips lines matching the Gadget
region (by address range resolved once at load, not by name).
- **Defeats:** naive `fopen("/proc/self/maps")` + `strstr("frida"/"libpayload")`.
- **Does not defeat:** `dl_iterate_phdr`, raw-syscall reads, the "exec region
  without backing file" heuristic, memory signature scans.
- **Cost:** low. **Risk:** low, but *false confidence* if shipped alone.

### Option B — Relocate + rename the Gadget mapping
Load from an anonymous / `memfd` mapping (no file path) or at least move the
private copy out of an obviously named directory and rename the `.so`.
- **Defeats:** path/name string matches in maps and `map_files`.
- **Does not defeat:** `dl_iterate_phdr` (still a `soinfo`), and an anon exec
  region is *itself* suspicious (§3.3). `memfd` shows as `/memfd:...` in maps.
- **Cost:** medium (custom loader). **Risk:** medium (ART/linker expectations).

### Option C — Hide the Gadget `soinfo` from the linker list
After load, unlink the Gadget's `soinfo` so `dl_iterate_phdr` / xdl-walk miss it.
- **Defeats:** the main bypass (§3.1) **and** keeps maps/dl_iterate consistent
  *if* combined with A.
- **Does not defeat:** raw-syscall maps reads (unless A also covers syscalls),
  memory signature scans.
- **Cost:** medium. **Risk:** **high** — breaks stack unwinding through Gadget
  frames, future `dlsym`, and may destabilize GumJS itself. Must be validated
  hard and bounded.

### Option D — Coherent `/proc` mediation layer (A across all paths + syscall)
A + cover `task/*/maps`, `smaps`, `map_files`, `pagemap`, and intercept at the
`syscall()` wrapper / PLT level, not just named libc functions.
- **Defeats:** most file-based detection, consistently.
- **Does not defeat:** inline `svc` syscalls (no privilege to seccomp-filter our
  own process reliably), `dl_iterate_phdr` (needs C), memory scans.
- **Cost:** high. **Risk:** medium-high.

---

## 5. Syscall-level reality

- Dobby inline hook + xdl symbol resolution intercept **libc functions**.
- A guest calling `syscall(__NR_openat, …)` or emitting `svc #0` directly
  bypasses every libc hook.
- Catching raw syscalls from *inside* the same process requires `seccomp-bpf`
  with a user-notification/trap handler. We are unprivileged userspace; a
  self-installed seccomp filter is possible but fragile, interacts with
  Android's own seccomp policy, and can destabilize the guest. **Treat raw
  syscalls as an accepted residual leak for the first iterations.**

---

## 6. Recommended staging

Each stage ships with before/after probe output (depends on the P0 probe suite —
build that first) and updates [../DETECTION_SURFACES.md](../DETECTION_SURFACES.md).

1. **Measure first (P0).** A probe that dumps, for the guest: maps / smaps /
   task-maps / map_files / cmdline / comm / status / `dl_iterate_phdr` list /
   `/proc/net/tcp`, and diffs Clean vs listen vs script mode. Nothing below is
   meaningful without this baseline.
2. **Kill the easy socket surface.** Document and default to
   `MODE_LOCAL_SCRIPT` for stealth: its config is `type: script` with **no
   listener** (`LocalScriptGadgetRuntime.buildConfig`), so `/proc/net/tcp` and
   endpoint probing go away entirely. Zero new code.
3. **A + C together, never A alone.** Maps-family filtering *and* `soinfo`
   hiding, so maps and `dl_iterate_phdr` stay consistent (§3.1). Gate C behind a
   stability flag; bound failures (if unlink/unwind misbehaves, fall back to
   un-hidden rather than crash the guest).
4. **Address-range, not name.** Resolve the Gadget's mapping range once at load
   and filter by range, so renames/relocations don't create new string leaks.
5. **cmdline/comm identity** (separate workstream): spoof `/proc/self/cmdline`
   and `prctl(PR_SET_NAME)` to the guest package; mask Frida thread names.

Explicitly **out of first scope:** raw-syscall interception, memory
signature-scan defense, kernel UID / SELinux domain (permanent without root).

---

## 7. Acceptance criteria (per ROADMAP)

- Probes run against **owned** sample apps only.
- For each mediated path, a probe reads it **both** via libc and via direct
  syscall, and the report states which the mediation covers.
- Filtered output is **structurally valid** (a parser of `/proc/self/maps` must
  not choke; no dangling line, no broken address ordering).
- Cross-checks in §3 are added as regression probes; a mediation PR must not
  *introduce* a new discrepancy (e.g. maps clean but smaps dirty).
- Native failure (unwind break, linker inconsistency) has **bounded** handling:
  fall back to unmediated, never crash the guest.
- The doc and `DETECTION_SURFACES.md` keep listing what remains observable.

---

## 8. Residual leaks after all of the above (honest ceiling)

- Raw-syscall `/proc` reads (no unprivileged, stable fix).
- Memory signature scans for GumJS/GLib/Frida strings (needs a patched Gum
  build; out of scope while pinned to official Frida).
- Kernel UID (`getuid`, `/proc/self/status` Uid) = host UID — permanent.
- SELinux domain (`/proc/self/attr/current`) — permanent.
- Host + BlackBox classes coexisting in the ART process; ClassLoader topology —
  architectural.

A serious RASP combining any of these with Play Integrity still detects
FridaBox. The goal here is to remove the *careless* tells, not to claim stealth.
