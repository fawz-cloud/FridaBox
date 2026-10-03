"""Polymorphic replacement-name generator for the stealth gadget build.

Every build picks a fresh lowercase token that replaces Frida's observable
internal identifiers (see patches.py). Randomizing it per build means two
builds never share the same static string fingerprint, the way Morphida and
phantom-frida do.

The token must be a valid C identifier fragment: lowercase ASCII, starts with a
letter, 3-20 chars. It must NOT contain "frida" / "gum" and must not collide
with the protocol strings we deliberately preserve (re.frida.*, capital Frida).
"""

from __future__ import annotations

import secrets
import string

# Innocuous, plausible-looking stems so the token reads like an ordinary vendor
# library rather than a random blob. Mixed and suffixed per build.
_STEMS = (
    "oem", "media", "codec", "sensor", "telemetry", "sync", "render",
    "audio", "camera", "vendor", "runtime", "service", "bridge", "core",
    "graphics", "input", "power", "display", "netd", "cache",
)

_FORBIDDEN_SUBSTRINGS = ("frida", "gum", "zymbiote")


def generate() -> str:
    """Return a fresh lowercase identifier token, 3-20 chars, C-safe."""
    rng = secrets.SystemRandom()
    for _ in range(64):
        stem = rng.choice(_STEMS)
        tail = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(2, 5)))
        token = f"{stem}{tail}"
        token = token[:20]
        if len(token) < 3:
            continue
        if not token[0].isalpha():
            continue
        if any(bad in token for bad in _FORBIDDEN_SUBSTRINGS):
            continue
        return token
    # Deterministic fallback; still C-safe and clean.
    return "oemcodec"


def validate(token: str) -> None:
    """Raise ValueError if token is not a safe replacement identifier."""
    if not (3 <= len(token) <= 20):
        raise ValueError(f"name must be 3-20 chars: {token!r}")
    if not token[0].isalpha():
        raise ValueError(f"name must start with a letter: {token!r}")
    if not all(c in string.ascii_lowercase + string.digits for c in token):
        raise ValueError(f"name must be lowercase ascii/digits: {token!r}")
    low = token.lower()
    if any(bad in low for bad in _FORBIDDEN_SUBSTRINGS):
        raise ValueError(f"name must not contain a known marker: {token!r}")


if __name__ == "__main__":
    # ponytail: tiny self-check, fails loudly if the generator drifts
    for _ in range(500):
        t = generate()
        validate(t)
        assert "frida" not in t and "gum" not in t, t
    print(generate())
