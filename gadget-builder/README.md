# gadget-builder — stealth Frida Gadget, built from source

Builds a **renamed** Frida Gadget for Android from the official Frida source, so
the common Frida signature fingerprints (telltale strings, symbols, thread
names) are gone while the client/protocol behavior stays identical. Written from
scratch for FridaBox, grounded in public reference projects (credited below).

This is **general fingerprint reduction** for authorized research on apps and
devices you own — not an app-specific bypass, and not a stealth guarantee. See
the honest ceiling in
[../docs/research/PATCHED_FRIDA_GADGET.md](../docs/research/PATCHED_FRIDA_GADGET.md)
and [../docs/research/PROC_MAPS_MEDIATION.md](../docs/research/PROC_MAPS_MEDIATION.md).

## Pieces

| File | Role |
| --- | --- |
| `build.py` | clone frida → apply patches → `configure --host`/`make` per ABI → collect, hash, verify |
| `patches.py` | source renames as string-contracts (`required` = build fails if absent; `optional` = best-effort) |
| `namegen.py` | polymorphic replacement token per build (no `frida`/`gum` substrings) |
| `verify.py` | hard gate: scans the final `.so` for forbidden markers |
| `../.github/workflows/build-gadget.yml` | manual CI build (heavy; ~hours) |

## How the rename stays safe

- **Renamed** (the fingerprints): `frida-server`/`-agent`/`-gadget`, the
  `re/frida/HelperBackend` JNI path, `frida-zymbiote-*`, thread names
  (`gum-js-loop`, `pool-frida`, …).
- **Preserved** (or the stock client / frida-java-bridge breaks): the public API
  string `Frida\0`, the `re.frida.*` D-Bus identifiers, `/re/frida/GadgetSession`,
  and the **runtime value** of `frida:rpc`.

`patches.py` attempts the renames; `verify.py` is the real guarantee — if any
forbidden marker survives in the artifact, `--verify` fails the build and names
the marker, which tells us which patch to fix.

## Staging (why the first build runs without `--verify`)

Building Frida from source on CI is the fragile part. So:

1. **Prove the build.** Run with `verify=false` and a single ABI first; confirm
   `android-arm64` produces `…-gadget-<ver>-android-arm64.so`.
2. **Widen ABIs.** Switch arch to all four.
3. **Tighten.** Turn `verify=true`; add/fix entries in `patches.py` until the
   artifact is marker-clean. Each CI failure names the surviving marker.
4. **Harden (frontier).** See the TODO list in `patches.py`
   (`frida:rpc` literal hiding, GType-name scrub, removing our `System.load`'d
   soinfo entry).

## Usage

CI (preferred): Actions → **Build Stealth Gadget** → set version / arch /
verify / publish. It must be on the default branch to appear there.

Local (Ubuntu 22.04, ANDROID_NDK_ROOT set):

```bash
cd gadget-builder
python3 build.py --version 17.16.0 --arch android-arm64        # prove build
python3 build.py --version 17.16.0 \
  --arch android-arm64,android-arm,android-x86_64,android-x86 --verify
```

Output in `output/`: `<name>-gadget-<ver>-android-<abi>.so(.gz)`,
`SHA256SUMS`, `build-info.json`.

## FridaBox integration (follow-up, after a published release)

Add a `GadgetSource` in `app/.../GadgetManager.kt` pointing at this repo's
releases. Because the name is **polymorphic**, match assets by regex
`.*-gadget-<ver>-android-<abi>\.so\.gz` instead of an exact prefix. FridaBox's
download → `decompressed()` (handles `.gz`) → `validateElf` → SHA pipeline is
already source-agnostic. Keep the official source the default; the stealth source
is opt-in.

## Licensing and credit

- **Frida** is under the **wxWindows Library Licence v3.1**. Modified builds must
  make their changes available — this directory's `patches.py` is exactly that
  change set. Keep the upstream notices; do not strip Frida's license.
- Techniques referenced (study only; no code copied verbatim — our own
  implementation):
  - [hzzheyang/strongR-frida-android](https://github.com/hzzheyang/strongR-frida-android) — the Android `configure --host`/`make` build recipe and the gadget output path.
  - [TheQmaks/phantom-frida](https://github.com/TheQmaks/phantom-frida) (MIT) — the string-contract patch model, the Frida 17.16.x source locations, and the forbidden-marker set.
  - [1013503897/Morphida](https://github.com/1013503897/Morphida) — polymorphic per-build naming.
  - [zer0def/undetected-frida](https://github.com/zer0def/undetected-frida) — combined patch-set reference.

## Ceiling (do not oversell)

A renamed gadget defeats string/symbol/thread-name scans. It does **not** defeat:
raw-syscall `/proc` reads, structural memory scans beyond strings, the kernel UID
/ SELinux domain, FridaBox's own virtualization tells, or Play Integrity. This
layer hides *Frida*; FridaBox's `/proc`/virtualization work hides the *container*.
They stack; neither makes the result undetectable.
