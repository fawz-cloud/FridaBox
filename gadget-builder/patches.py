"""Source patch contracts for the stealth gadget build.

Model (from the string-contract approach phantom-frida uses, which is more
drift-resistant than frozen .patch files): each patch is an exact source string
replacement with a minimum occurrence count. REQUIRED patches must apply the
expected number of times or the build stops — that is how we notice upstream
Frida moved a string between versions. OPTIONAL patches are best-effort; the
real completeness guarantee is verify.py scanning the final .so.

What we deliberately DO NOT rename (preserving these keeps the stock Frida
client and frida-java-bridge working):
  - the public API string "Frida\\0"
  - the "re.frida.*" D-Bus protocol identifiers and "/re/frida/GadgetSession"
  - the runtime value of "frida:rpc" (we may hide the static literal later via a
    char-code constructor, but the runtime bytes must stay identical)

Contracts below are grounded in the Frida 17.16.x source layout documented by
phantom-frida (credited in README.md). They are version-targeted; verify.py is
the hard gate that fails the build if any forbidden marker survives.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Patch:
    """One exact source string replacement, relative to the frida/ checkout."""

    path: str
    old: str
    new: str
    minimum: int = 1
    required: bool = True


def _cap(name: str) -> str:
    return name[0].upper() + name[1:]


def required_patches(name: str) -> list[Patch]:
    """Contracts we are confident about for Frida 17.16.x. Build fails if absent."""
    lhs = "subprojects/frida-core/src/linux/linux-host-session.vala"
    return [
        Patch(lhs, "re/frida/HelperBackend", f"re/{name}/HelperBackend"),
        Patch(lhs, '"/frida-zymbiote-', f'"/{name}-zymbiote-', minimum=2),
        Patch(
            "subprojects/frida-core/src/linux/helpers/zymbiote.c",
            '"/frida-zymbiote-',
            f'"/{name}-zymbiote-',
        ),
        Patch(
            "subprojects/frida-core/lib/base/session.vala",
            "frida-server",
            f"{name}-server",
            minimum=2,
        ),
        Patch(
            "subprojects/frida-core/src/socket/socket-host-session.vala",
            "frida-server",
            f"{name}-server",
            minimum=4,
        ),
    ]


def optional_patches(name: str) -> list[Patch]:
    """Best-effort renames; skipped with a warning if the string is absent.

    Thread names and worker identifiers. Exact source locations drift between
    Frida versions, so these are not hard contracts — verify.py still fails the
    build if any of these markers survive in the final artifact, which tells us
    to correct the path/string here.
    """
    cap = _cap(name)
    return [
        # Frida-owned thread names (shown in /proc/<pid>/task/<tid>/comm).
        Patch("subprojects/frida-gum/bindings/gumjs/gumscriptscheduler.c",
              "gum-js-loop", f"{name}-js-loop", required=False),
        Patch("subprojects/frida-gum/bindings/gumjs/gumscriptscheduler.c",
              "gum-js-cond", f"{name}-js-cond", required=False),
        Patch("subprojects/frida-core/lib/payload/exit-monitor.vala",
              "frida-main-loop", f"{name}-main-loop", required=False),
        # Gadget worker thread names.
        Patch("subprojects/frida-core/lib/gadget/gadget.vala",
              "frida-gadget", f"{name}-gadget", minimum=1, required=False),
        # Agent / helper identifiers.
        Patch("subprojects/frida-core/lib/payload/agent.vala",
              "frida-agent", f"{name}-agent", required=False),
        # Thread-pool names set via the GLib pool wrapper.
        Patch("subprojects/frida-gum/gum/gumprocess.c",
              "pool-frida", f"pool-{name}", required=False),
    ]


def all_patches(name: str) -> list[Patch]:
    return required_patches(name) + optional_patches(name)


# TODO (iterate in CI, verified by verify.py):
#   - hide the static "frida:rpc" literal behind a char-code constructor while
#     keeping the runtime value identical (phantom does this in message-bus code)
#   - scrub "FridaScriptEngine" / "GumScript" GType names where safe
#   - remove our System.load'd gadget soinfo entry (FridaBox-specific; see
#     docs/research/PATCHED_FRIDA_GADGET.md)
