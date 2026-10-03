"""Forbidden-marker verifier for a built stealth gadget.

Scans the final .so for byte markers that give Frida away. The list is the
union of the markers the public projects check (phantom-frida's verifier set is
the most complete reference) plus a couple we add.

Design notes:
- Markers ending in b"\\x00" are matched NUL-terminated, so "frida\\0" catches the
  standalone string but NOT the protocol prefix "re.frida." we deliberately keep.
- The exact public API string b"Frida\\x00" (capital) and the "re.frida.*"
  D-Bus identifiers are PRESERVED on purpose; renaming them breaks the stock
  client / frida-java-bridge contract. They are therefore not forbidden.
- Substring markers (e.g. b"gum-js-loop") are distinctive enough to match raw.
"""

from __future__ import annotations

from pathlib import Path

# NUL-terminated exact tokens (must not be a live symbol/string in the artifact).
_FORBIDDEN_NUL = [
    b"frida\x00",
    b"gmain\x00",
    b"gdbus\x00",
    b"jit-cache\x00",
]

# Distinctive substrings that must not appear anywhere.
_FORBIDDEN_SUBSTR = [
    b"frida-zymbiote",
    b"re/frida/HelperBackend",
    b"frida-server",
    b"frida-helper",
    b"frida-agent",
    b"frida-gadget",
    b"frida-eternal-agent",
    b"frida-generate-certificate",
    b"frida-main-loop",
    b"frida:rpc",
    b"FridaScriptEngine",
    b"GumScript",
    b"gum-js-loop",
    b"pool-frida",
    b"pool-spawner",
    b"Frida/",  # HTTP/Inspector prefix — distinct from the preserved API string "Frida\0"
]


def scan(path: Path) -> list[str]:
    """Return the list of forbidden markers present in the file (empty == clean)."""
    data = path.read_bytes()
    hits: list[str] = []
    for marker in _FORBIDDEN_NUL + _FORBIDDEN_SUBSTR:
        if marker in data:
            hits.append(_render(marker))
    return hits


def assert_clean(path: Path) -> None:
    """Raise if any forbidden marker is present."""
    hits = scan(path)
    if hits:
        raise SystemExit(
            f"verify FAILED for {path.name}: forbidden markers present: {', '.join(hits)}"
        )


def _render(marker: bytes) -> str:
    return marker.rstrip(b"\x00").decode("latin-1") + ("\\0" if marker.endswith(b"\x00") else "")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        raise SystemExit("usage: verify.py <artifact.so> [...]")
    bad = False
    for arg in sys.argv[1:]:
        p = Path(arg)
        hits = scan(p)
        if hits:
            bad = True
            print(f"[DIRTY] {p}: {', '.join(hits)}")
        else:
            print(f"[clean] {p}")
    raise SystemExit(1 if bad else 0)
