#!/usr/bin/env python3
"""Build a renamed ("stealth") Frida Gadget for Android from source.

Pipeline (grounded in the proven strongR-frida-android recipe, credited in
README.md):

  1. clone frida --recurse-submodules at a pinned version
  2. apply the source renames in patches.py (contract-checked)
  3. per ABI:  mkdir build-<abi>; (cd) ../frida/configure --host=<abi>; make
  4. collect   build-<abi>/subprojects/frida-core/lib/gadget/frida-gadget.so
  5. rename -> <name>-gadget-<version>-android-<abi>.so(.gz), hash, verify

Staging: run WITHOUT --verify first to prove the 4-ABI build works on CI; then
add/fix patches and turn --verify on until the artifact is marker-clean.

Requires ANDROID_NDK_ROOT in the environment for the build steps (CI sets it).
Pure standard library.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import namegen
import patches as patchmod
import verify

ALL_ARCHS = ["android-arm64", "android-arm", "android-x86_64", "android-x86"]
FRIDA_REPO = "https://github.com/frida/frida"
GADGET_REL = "subprojects/frida-core/lib/gadget/frida-gadget.so"


def log(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def run(cmd: list[str], cwd: Path | None = None) -> None:
    log("$ " + " ".join(cmd) + (f"   (cwd={cwd})" if cwd else ""))
    subprocess.run(cmd, cwd=cwd, check=True)


def clone_frida(work: Path, version: str) -> Path:
    src = work / "frida"
    if src.exists():
        log(f"reusing existing source tree {src}")
        return src
    run([
        "git", "clone", "--depth", "1", "--branch", version,
        "--recurse-submodules", "--shallow-submodules", FRIDA_REPO, str(src),
    ])
    return src


def apply_patches(src: Path, name: str) -> None:
    applied = 0
    for p in patchmod.required_patches(name):
        applied += _apply_one(src, p, hard=True)
    for p in patchmod.optional_patches(name):
        applied += _apply_one(src, p, hard=False)
    log(f"applied {applied} patch occurrence(s) for name={name!r}")


def _apply_one(src: Path, p: patchmod.Patch, hard: bool) -> int:
    f = src / p.path
    if not f.is_file():
        msg = f"patch target missing: {p.path}"
        if hard:
            raise SystemExit(f"REQUIRED {msg}")
        log(f"skip optional (no file): {p.path}")
        return 0
    text = f.read_text(encoding="utf-8", errors="surrogateescape")
    count = text.count(p.old)
    if count < p.minimum:
        msg = f"{p.path}: found {count}x {p.old!r}, need >= {p.minimum}"
        if hard:
            raise SystemExit(f"REQUIRED contract broken (upstream drift?): {msg}")
        log(f"skip optional ({msg})")
        return 0
    f.write_text(text.replace(p.old, p.new), encoding="utf-8", errors="surrogateescape")
    log(f"patched {p.path}: {count}x {p.old!r} -> {p.new!r}")
    return count


def build_arch(src: Path, work: Path, arch: str) -> Path:
    bdir = work / f"build-{arch}"
    bdir.mkdir(parents=True, exist_ok=True)
    # Frida's out-of-tree build: configure from the build dir, then make.
    run([str(src / "configure"), f"--host={arch}"], cwd=bdir)
    run(["make"], cwd=bdir)
    gadget = bdir / GADGET_REL
    if not gadget.is_file():
        raise SystemExit(f"gadget not produced for {arch}: {gadget}")
    return gadget


def abi_from_arch(arch: str) -> str:
    return arch[len("android-"):]  # android-arm64 -> arm64


def collect(gadget: Path, out: Path, name: str, version: str, arch: str,
            do_verify: bool) -> dict:
    abi = abi_from_arch(arch)
    staged = out / f"{name}-gadget-{version}-android-{abi}.so"
    shutil.copy2(gadget, staged)
    # Strip to drop symbol tables that would otherwise leak names (best-effort).
    strip = os.environ.get("STRIP")
    if strip:
        try:
            run([strip, "--strip-unneeded", str(staged)])
        except (subprocess.CalledProcessError, OSError) as e:
            log(f"WARNING strip failed ({e}); continuing unstripped")
    if do_verify:
        verify.assert_clean(staged)
    else:
        hits = verify.scan(staged)
        if hits:
            log(f"WARNING {staged.name} still contains markers: {', '.join(hits)}")
    digest = _sha256(staged)
    gz = Path(str(staged) + ".gz")
    with staged.open("rb") as fin, gzip.open(gz, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    return {
        "abi": abi,
        "asset": gz.name,
        "raw": staged.name,
        "sha256": digest,
        "sha256_gz": _sha256(gz),
        "size": staged.stat().st_size,
    }


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def frida_commit(src: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=src, text=True).strip()
    except Exception:
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a renamed Frida Gadget for Android.")
    ap.add_argument("--version", "-v", required=True, help="Frida version tag, e.g. 17.16.0")
    ap.add_argument("--name", "-n", default=None, help="replacement token (default: polymorphic)")
    ap.add_argument("--arch", "-a", default=",".join(ALL_ARCHS),
                    help="comma-separated archs (default: all four)")
    ap.add_argument("--work-dir", default="build", help="working directory")
    ap.add_argument("--output", "-o", default="output", help="artifact output directory")
    ap.add_argument("--verify", action="store_true", help="fail if forbidden markers survive")
    ap.add_argument("--skip-clone", action="store_true")
    ap.add_argument("--skip-patches", action="store_true")
    ap.add_argument("--skip-build", action="store_true", help="patch only, do not compile")
    args = ap.parse_args()

    name = args.name or namegen.generate()
    namegen.validate(name)
    archs = [a.strip() for a in args.arch.split(",") if a.strip()]
    for a in archs:
        if a not in ALL_ARCHS:
            raise SystemExit(f"unsupported arch: {a}")

    work = Path(args.work_dir).resolve()
    out = Path(args.output).resolve()
    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)

    if not args.skip_build and not os.environ.get("ANDROID_NDK_ROOT"):
        raise SystemExit("ANDROID_NDK_ROOT must be set for the build steps")

    log(f"version={args.version} name={name} archs={archs} verify={args.verify}")

    src = (work / "frida") if args.skip_clone else clone_frida(work, args.version)
    if not args.skip_patches:
        apply_patches(src, name)
    else:
        log("skipping patches")

    if args.skip_build:
        log("skip-build set; patched source ready at " + str(src))
        return 0

    artifacts = []
    for arch in archs:
        log(f"=== building {arch} ===")
        gadget = build_arch(src, work, arch)
        artifacts.append(collect(gadget, out, name, args.version, arch, args.verify))

    info = {
        "name": name,
        "frida_version": args.version,
        "frida_commit": frida_commit(src),
        "archs": archs,
        "built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verified": args.verify,
        "artifacts": artifacts,
    }
    (out / "build-info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    sums = "".join(f"{a['sha256_gz']}  {a['asset']}\n" for a in artifacts)
    (out / "SHA256SUMS").write_text(sums, encoding="utf-8")
    log("done. artifacts:")
    for a in artifacts:
        log(f"  {a['asset']}  sha256(raw)={a['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
