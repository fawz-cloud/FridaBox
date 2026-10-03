# Research deep-dive: patched / stealth Frida Gadget as a FridaBox source

Status: **research only — no code yet.** Evaluates swapping the official Frida
Gadget for a community-patched ("stealth") build to close the Frida-signature
fingerprints that [PROC_MAPS_MEDIATION.md](PROC_MAPS_MEDIATION.md) lists as
residual.

TL;DR: a patched gadget closes the **single biggest residual** (memory
string/symbol/thread-name scans for `frida`/`gum`/`gum-js-loop`) that FridaBox
*cannot* fix from the outside, and the wiring is **small** because FridaBox's
download → decompress → ELF-verify → SHA → load pipeline is already
source-agnostic. It does **not** touch the virtualization tells (host UID,
`:pN` cmdline, synthesized Binder) and does **not** affect Play Integrity.

---

## 1. What "patched Frida" changes

These forks rebuild Frida from source and rename/remove its telltale
identifiers. No runtime logic changes — only fingerprints. Vectors covered
(union across projects):

- **Strings**: global rename of `frida`, `gum`, `FridaScript`, `GLib`, the
  `frida:rpc` message marker, GType prefixes, the Frida directory name.
- **Symbols**: the agent entrypoint `frida_agent_main` renamed (needs a second
  incremental build), export tables scrubbed.
- **Thread names**: `gum-js-loop`, `gmain`, `gdbus`, `pool-frida`,
  `frida-gadget` renamed/removed from `/proc/<pid>/task/<tid>/comm` and
  `.../status`.
- **Linker**: the agent removed from the dynamic linker `soinfo` list
  (defeats `dl_iterate_phdr` / xdl-style walks) — this is exactly
  `PROC_MAPS_MEDIATION.md` Option C, done upstream.
- **Mappings**: renamed `.so` + (some builds) `memfd` name randomization, so
  `/proc/self/maps` no longer shows `frida-*`.
- **Polymorphic builds** (Morphida, phantom): every build randomizes the above,
  so static fingerprints differ per release.

Net effect reported by these projects: `/proc/<pid>/maps` has no `frida-*`
lines and string-based detections fail entirely.

---

## 2. Landscape — which ships an Android **Gadget** (not just server)

FridaBox loads a **Gadget** `.so` via `System.load` (`FridaGadgetLoader`), so a
frida-**server**-only project is useless here. Verified via GitHub API:

| Project | Gadget `.so`? | ABIs | Asset format | Frida ver | Notes |
| --- | --- | --- | --- | --- | --- |
| **zer0def/undetected-frida** | ✅ | arm, arm64, x86, x86_64 | **`.so.xz`** | 17.22.0 | melds strongR + Florida; magisk/riru too; **same compression + ABI naming as official** |
| **cergo666/Florida** | ✅ | arm, arm64, x86, x86_64 | `.so.gz` | 17.21.0 | ships `florida-identities-<ver>.json` (the random identity map) |
| **TheQmaks/phantom-frida** | ✅ | **arm64 only** | `.so` / `.so.gz` | 17.16.4 | ~90 patches / 16 vectors; **polymorphic names** per build |
| hzzheyang/strongR-frida-android | ✘ (server) | — | — | 17.21.0 | reference technique |
| Ylarod/Florida (upstream) | ✘ here | — | — | 17.21.0 | base of many forks |
| 1013503897/Morphida | ✘ (server arm64) | — | — | 17.17.x | polymorphic reference |

Best fits for FridaBox's 4-ABI model:
1. **zer0def/undetected-frida** — `.so.xz` (identical format to official), all
   four ABIs, tracks upstream. Lowest-friction drop-in.
2. **cergo666/Florida** — `.so.gz`, all four ABIs, publishes an identities map.
3. **phantom-frida** — most patches, but **arm64-only** and polymorphic names
   (breaks exact-name matching, see §4).

---

## 3. How this maps onto the residuals we could not fix

From `PROC_MAPS_MEDIATION.md` §8 "honest ceiling":

| Residual there | Patched gadget? |
| --- | --- |
| Memory signature scan (`gum`/`frida`/`GLib` strings) | ✅ **closed** (the whole point) |
| `dl_iterate_phdr` / soinfo shows the agent | ✅/⚠️ patched builds self-remove their agent's soinfo — but see §5 (our `System.load` entry) |
| Thread names `gum-js-loop` etc. | ✅ closed |
| maps path/name `frida-*` | ✅ closed (renamed) |
| Raw-syscall `/proc` reads | ➖ unaffected (orthogonal) |
| Kernel UID / SELinux domain | ➖ unaffected (not Frida) |
| Virtualization tells (`:pN`, Binder, UID, class coexistence) | ➖ **unaffected** — different problem |

So a patched gadget and the `/proc`/virtualization work are **complementary**,
not substitutes. Patched gadget hides *Frida*; the other work hides the
*container*.

---

## 4. Wiring into FridaBox (small)

The pipeline is already source-agnostic. Confirmed in `GadgetManager.kt`:

- Compression: `decompressed()` already handles **both** `.xz`
  (`XZInputStream`, `org.tukaani:xz`) **and** `.gz` (`GZIPInputStream`) — lines
  297-299. So zer0def (`.xz`) and Florida (`.gz`) both work unchanged.
- Host allow-list: `isTrustedUrl()` permits `github.com` /
  `*.githubusercontent.com` — patched repos pass.
- Verify + load: `validateElf()` checks ELF machine per ABI (same arch →
  passes); SHA-256 is computed at download (TOFU); `DownloadedGadgetRuntime` /
  `LocalScriptGadgetRuntime` consume the selected gadget path generically.

What must change:

1. **`GadgetSource` enum** (`GadgetManager.kt:21`): add entries, e.g.
   `UNDETECTED("undetected","Undetected Frida","zer0def/undetected-frida")`,
   `FLORIDA("florida","Florida","cergo666/Florida")`. `releaseCatalogUrl`
   already derives from `source.repository`.
2. **Per-source `expectedAsset`** (`GadgetManager.kt:28`): today it is hardcoded
   `"frida-gadget-$version-android-$arch.so.xz"`. Make it source-specific:
   - official → `frida-gadget-$v-android-$a.so.xz`
   - undetected → `undetected-frida-gadget-$v-android-$a.so.xz`
   - florida → `florida-gadget-$v-android-$a.so.gz`
3. **Polymorphic names (only if adding phantom)**: `parseCatalog` matches assets
   by exact `name != expected` (line 219). Phantom's random prefix needs a
   regex match `.*-gadget-<v>-android-<a>\.so(\.gz)?$` instead. Skip for v1.
4. **UI/default**: keep `OFFICIAL` the default; patched sources are opt-in in the
   Gadgets screen. This preserves the ROADMAP guardrail "official engine stays
   pinned" while allowing stealth as a choice.

Everything else (download, decompress, ELF check, SHA record, per-guest runtime
copy, `System.load`) is untouched.

---

## 5. What it does NOT solve (honest)

- **Our `System.load` soinfo entry.** The patched builds remove *their
  injector's* agent from the linker list. FridaBox loads the gadget itself via
  `dlopen`, so a renamed `soinfo` entry still exists — no `frida` string, but an
  extra library is visible to `dl_iterate_phdr`. Renaming lowers the signal; it
  does not remove the entry. (Full removal = `PROC_MAPS_MEDIATION.md` Option C,
  still risky.)
- **frida-java-bridge.** On-device script mode wraps the agent with
  `frida-java-bridge` built from official npm (`tools/build_frida_agents.py`).
  The patched **native** gadget does not patch the **Java** bridge; Java-layer
  artifacts (bridge class names, rpc in the JS runtime) may remain. Native
  gum-string scanning — the common case — is covered; Java-layer scanning is
  not. A renamed/clean java-bridge would be a separate workstream.
- **Virtualization tells.** Host UID, `:pN` cmdline, synthesized
  PackageManager/Binder, host+BlackBox class coexistence — untouched. Different
  problem.
- **Raw-syscall `/proc`, kernel UID, SELinux** — unaffected.
- **Play Integrity / hardware attestation** — unaffected; still out of scope
  forever (hardware + server rooted).

---

## 6. Tradeoffs / risks

- **Trust / supply chain.** These are third-party prebuilt binaries. FridaBox
  verifies ELF arch + SHA-256, but SHA here is trust-on-first-download, not a
  reproducible provenance check — it cannot prove the binary is not backdoored.
  Safer alternative: build from the project's own scripts (strongR / phantom
  publish build pipelines) and host the artifact yourself.
- **Breaks the "pinned official 17.16.0" guarantee.** Mitigate by keeping
  patched sources optional and clearly labeled; official stays default.
- **Polymorphic builds** change SHA every release — no stable pin; FridaBox's
  TOFU-at-download still works, but reproducibility is lost.
- **Upstream drift.** Patched forks lag official Frida by days; the bundled
  `frida-java-bridge` version must stay protocol-compatible with the chosen
  gadget's Frida version.
- **Legitimacy.** This is general fingerprint reduction for authorized research
  (matches ROADMAP P1 "reduce avoidable Frida visibility"), not an app-specific
  bypass. Keep it that way; do not add per-app logic.

---

## 7. Recommendation

Highest **leverage-to-effort** stealth change available: it closes the residual
FridaBox can't otherwise touch (native signature scans) for a small, additive
code change, and it stacks with the `/proc`/virtualization work rather than
replacing it.

Suggested first slice:
1. Add **one** patched `GadgetSource` — **zer0def/undetected-frida** (`.so.xz`,
   all ABIs, official-compatible format) — behind the existing Gadgets screen,
   official still default.
2. Make `expectedAsset` per-source.
3. Validate on an **owned** app with the P0 probe suite: diff native maps /
   thread names / string scan, official gadget vs patched gadget, same guest.
4. Document residuals (§5) in `DETECTION_SURFACES.md`.

Defer: phantom (arm64-only + polymorphic matching), a clean java-bridge, and
Option C soinfo removal of our own `System.load` entry.
