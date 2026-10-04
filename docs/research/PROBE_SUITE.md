# Probe suite — detection-surface regression lab (ROADMAP P0)

"You can't harden what you can't measure." This is the P0 regression laboratory:
one probe that dumps the detection surfaces a guest sees, and a diff tool that
compares runs, so every hardening change ships with a before/after.

- `scripts/probe-suite.js` — raw Frida probe (no frida-java-bridge import).
- `tools/probe_diff.py` — loads probe outputs, flags leaks, prints a delta.

## What it records

| Surface | Source | Leak flagged when |
| --- | --- | --- |
| Process maps | `/proc/self/maps` | a mapping path matches `frida\|gum\|gadget\|palka\|guest-runtime\|linjector\|memfd:` |
| Exec anon regions | `/proc/self/maps` | reported as a count (JIT heuristic) |
| Loaded modules | `Process.enumerateModules()` | a module name/path matches the same pattern |
| Thread names | `/proc/self/task/<tid>/comm` | `gum-js-loop\|gmain\|gdbus\|pool-frida\|…` |
| Listening sockets | `/proc/net/tcp[6]` | any `st=0A` (LISTEN) entry (Gadget listener in Computer mode) |
| `/proc` identity | cmdline, comm, status | `TracerPid != 0` |
| System properties | `__system_property_get` | `ro.debuggable=1`, `ro.secure=0`, `ro.build.tags` has `test-keys` |
| Java identity (if a `Java` global is present) | ActivityThread/PM/Build/UserManager/WifiManager | `Build.TAGS` has `test-keys`, no installer |

The Java section runs only when a `Java` global already exists (inside an
on-device agent that injected the bridge). Run raw from a computer and the
native / `/proc` / property surfaces are covered; the Java section reports
`available: false`. A compiled variant (importing `frida-java-bridge`) that
always covers the Java surfaces is a follow-up — it needs the frida-compile
pipeline (`tools/build_frida_agents.py`), unlike this raw script.

## Running it

Computer mode (primary): import the target in Palka, launch in **Computer** mode,
then attach the probe from a computer — it prints one `PALKA_PROBE <json>` line
and sends the same object to the client:

```text
frida -U gadget -l scripts/probe-suite.js
```

On-device mode: select `scripts/probe-suite.js` as the on-device agent; it dumps
`PALKA_PROBE <json>` into the guest log overlay (`runtime.jsonl`), including the
Java section (the bridge is injected there).

Capture the output to a file per scenario, e.g. `normal.json`, `clean.json`,
`computer.json`, `ondevice.json` (raw JSON or the full log — the diff tool
extracts the `PALKA_PROBE` line either way).

## Diffing

```text
python tools/probe_diff.py normal.json clean.json computer.json ondevice.json
```

Per input it prints the leaks found; then a delta of each run against the first
(baseline). Use it to prove a hardening change removed a leak without adding a
new discrepancy. `--selftest` runs an offline logic check.

## Acceptance criteria (ROADMAP P0)

- Runs against an **owned** sample app only.
- Output is structured and diffable across Android versions and modes.
- Every hardening PR attaches a before/after `probe_diff` result.
- The suite never claims an untested surface is protected: a surface it does not
  read is simply absent from the report, not reported clean.

## Known gaps (do not oversell)

- Raw script → Java surfaces only when a bridge is present (see above).
- Reads via Frida/libc; a guest using **direct syscalls** can observe `/proc`
  facts this probe reads through the same libc. The probe measures what is
  exposed, not every path to it.
- Not a detector of every RASP technique — it covers the surfaces this project
  targets (maps, modules, threads, sockets, `/proc`, properties, virtual
  identity), matching the hardening work in
  [PROC_MAPS_MEDIATION.md](PROC_MAPS_MEDIATION.md) and
  [PATCHED_FRIDA_GADGET.md](PATCHED_FRIDA_GADGET.md).
