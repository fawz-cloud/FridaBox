#!/usr/bin/env python3
"""Diff Palka detection-surface probe outputs (see scripts/probe-suite.js).

Load two or more probe results (normal install, Palka Clean, each instrumented
mode), flag the detection-relevant leaks in each, and print a side-by-side
comparison so every hardening change can show a before/after.

Each input is either a raw JSON object (the probe `result`) or a log/text file
containing a `PALKA_PROBE <json>` line (the probe prints that to the console).

Usage:
    python tools/probe_diff.py normal.json clean.json computer.json
    python tools/probe_diff.py --selftest
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_probe(path: str) -> dict:
    raw = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    if "PALKA_PROBE " in raw:
        # Last PALKA_PROBE line wins (a log may contain several).
        line = [ln for ln in raw.splitlines() if "PALKA_PROBE " in ln][-1]
        raw = line.split("PALKA_PROBE ", 1)[1].strip()
    return json.loads(raw)


def collect_leaks(p: dict) -> list[str]:
    """Return the detection-relevant leaks present in one probe result."""
    leaks: list[str] = []

    maps = p.get("maps") or {}
    for line in maps.get("suspicious", []) or []:
        leaks.append(f"maps: {line}")

    for mod in (p.get("modules") or {}).get("suspicious", []) or []:
        leaks.append(f"module: {mod.get('path') or mod.get('name')}")

    for name in (p.get("threads") or {}).get("suspicious", []) or []:
        leaks.append(f"thread: {name}")

    for addr in (p.get("sockets") or {}).get("listening", []) or []:
        leaks.append(f"listening socket: {addr}")

    status = (p.get("proc") or {}).get("status") or {}
    if isinstance(status, dict):
        tracer = status.get("TracerPid")
        if tracer not in (None, "0"):
            leaks.append(f"TracerPid: {tracer}")

    props = p.get("props") or {}
    if isinstance(props, dict):
        if props.get("ro.debuggable") == "1":
            leaks.append("prop ro.debuggable=1")
        if props.get("ro.secure") == "0":
            leaks.append("prop ro.secure=0")
        tags = props.get("ro.build.tags") or ""
        if "test-keys" in tags:
            leaks.append(f"prop ro.build.tags={tags}")

    java = p.get("java") or {}
    if java.get("available"):
        build = java.get("build") or {}
        if "test-keys" in (build.get("TAGS") or ""):
            leaks.append(f"Build.TAGS={build.get('TAGS')}")
        inst = java.get("installer")
        if inst in (None, "null"):
            leaks.append("installer: none (not store-installed)")

    return leaks


def label_for(path: str) -> str:
    return Path(path).stem


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Diff Palka probe outputs")
    ap.add_argument("probes", nargs="*", help="probe JSON or log files")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if len(args.probes) < 1:
        ap.error("provide at least one probe file (two+ to compare)")

    results = []
    for path in args.probes:
        try:
            results.append((label_for(path), load_probe(path)))
        except Exception as e:  # noqa: BLE001
            print(f"[error] {path}: {e}", file=sys.stderr)
            return 2

    any_leak = False
    for label, probe in results:
        leaks = collect_leaks(probe)
        any_leak = any_leak or bool(leaks)
        print(f"=== {label} === ({len(leaks)} leak(s))")
        for leak in leaks:
            print(f"  ! {leak}")
        if not leaks:
            print("  clean")
        print()

    if len(results) >= 2:
        base_label, base = results[0]
        base_leaks = set(collect_leaks(base))
        print(f"=== delta vs baseline '{base_label}' ===")
        for label, probe in results[1:]:
            leaks = set(collect_leaks(probe))
            added = sorted(leaks - base_leaks)
            removed = sorted(base_leaks - leaks)
            print(f"  {label}: +{len(added)} new, -{len(removed)} gone")
            for a in added:
                print(f"    + {a}")

    return 1 if any_leak else 0


def selftest() -> int:
    dirty = {
        "maps": {"suspicious": ["b700 r-xp 0 /data/.../libgadget.so"], "exec_anon_regions": 2},
        "modules": {"suspicious": [{"name": "libgadget.so", "path": "/x/libgadget.so"}]},
        "threads": {"suspicious": ["gum-js-loop"]},
        "sockets": {"listening": ["0100007F:69A2"]},
        "proc": {"status": {"TracerPid": "1234"}},
        "props": {"ro.debuggable": "1", "ro.secure": "0", "ro.build.tags": "test-keys"},
        "java": {"available": True, "build": {"TAGS": "test-keys"}, "installer": None},
    }
    clean = {
        "maps": {"suspicious": [], "exec_anon_regions": 1},
        "modules": {"suspicious": []},
        "threads": {"suspicious": []},
        "sockets": {"listening": []},
        "proc": {"status": {"TracerPid": "0"}},
        "props": {"ro.debuggable": "0", "ro.secure": "1", "ro.build.tags": "release-keys"},
        "java": {"available": True, "build": {"TAGS": "release-keys"}, "installer": "com.android.vending"},
    }
    d = collect_leaks(dirty)
    c = collect_leaks(clean)
    assert c == [], f"clean must have no leaks, got {c}"
    assert any("gum-js-loop" in x for x in d), d
    assert any("ro.debuggable=1" in x for x in d), d
    assert any("libgadget" in x for x in d), d
    assert any("TracerPid" in x for x in d), d
    assert len(d) >= 7, d
    print("probe_diff selftest OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
