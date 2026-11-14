#!/usr/bin/env python3
"""Compare two builds of one image, file by file, and fail on any difference build-noise.toml doesn't name.

Two builds from the same pinned inputs must hold the same files. A difference outside the noise list means an
input floats. Usage: compare_builds.py [--engine podman] [--noise build-noise.toml] IMAGE_A IMAGE_B
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

CONFIG_KEYS = ("Env", "User", "Entrypoint", "Cmd", "WorkingDir", "ExposedPorts", "Volumes", "Labels", "StopSignal")
KINDS = {tarfile.REGTYPE: "file", tarfile.AREGTYPE: "file", tarfile.DIRTYPE: "dir", tarfile.SYMTYPE: "symlink",
         tarfile.LNKTYPE: "hardlink", tarfile.CHRTYPE: "char", tarfile.BLKTYPE: "block", tarfile.FIFOTYPE: "fifo"}


@dataclass
class Rules:
    ignore: list[dict] = field(default_factory=list)
    normalize: list[dict] = field(default_factory=list)
    used: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Path) -> Rules:
        data = tomllib.loads(path.read_text())
        rules = cls(data.get("ignore", []), data.get("normalize", []))
        for rule in rules.ignore + rules.normalize:
            if not rule.get("path") or not rule.get("why"):
                raise SystemExit(f"{path}: every rule needs a path and a why: {rule}")
        for rule in rules.normalize:
            rule["_re"] = re.compile(rule["pattern"].encode(), re.MULTILINE)
            rule["_with"] = rule["replace"].encode()
        return rules

    def ignored(self, path: str) -> bool:
        for rule in self.ignore:
            if fnmatch.fnmatchcase(path, rule["path"]):
                self.used.add(rule["path"])
                return True
        return False

    def apply(self, path: str, data: bytes) -> bytes:
        for rule in self.normalize:
            if fnmatch.fnmatchcase(path, rule["path"]):
                self.used.add(rule["path"])
                data = rule["_re"].sub(rule["_with"], data)
        return data

    def unused(self) -> list[str]:
        return [r["path"] for r in self.ignore + self.normalize if r["path"] not in self.used]


def manifest(stream: IO[bytes], rules: Rules) -> dict[str, tuple]:
    """Each path's kind, mode, owner, link target and content hash, from a flattened filesystem tar."""
    entries: dict[str, tuple] = {}
    with tarfile.open(fileobj=stream, mode="r|") as tar:
        for member in tar:
            path = "/" + member.name.lstrip("./").rstrip("/")
            digest = ""
            if member.isreg():
                if rules.ignored(path):
                    digest = "(ignored)"
                else:
                    data = tar.extractfile(member).read()
                    digest = hashlib.sha256(rules.apply(path, data)).hexdigest()
            entries[path] = (KINDS.get(member.type, "other"), oct(member.mode), member.uid, member.gid,
                             member.linkname, digest)
    return entries


def compare(a: dict[str, tuple], b: dict[str, tuple]) -> list[str]:
    diffs = [f"only in A: {p}" for p in sorted(a.keys() - b.keys())]
    diffs += [f"only in B: {p}" for p in sorted(b.keys() - a.keys())]
    names = ("kind", "mode", "uid", "gid", "link", "content")
    for path in sorted(a.keys() & b.keys()):
        if a[path] != b[path]:
            what = [n for n, x, y in zip(names, a[path], b[path]) if x != y]
            diffs.append(f"differs ({', '.join(what)}): {path}")
    return diffs


def config(engine: str, image: str) -> dict:
    out = json.loads(subprocess.run([engine, "image", "inspect", image], check=True, capture_output=True).stdout)
    cfg = (out[0] if isinstance(out, list) else out).get("Config") or {}
    return {k: cfg.get(k) for k in CONFIG_KEYS}


def export(engine: str, image: str, rules: Rules) -> dict[str, tuple]:
    cid = subprocess.run([engine, "create", image, "true"], check=True, capture_output=True,
                         text=True).stdout.strip()
    try:
        proc = subprocess.Popen([engine, "export", cid], stdout=subprocess.PIPE)
        entries = manifest(proc.stdout, rules)
        if proc.wait():
            raise SystemExit(f"{engine} export {image} failed")
        return entries
    finally:
        subprocess.run([engine, "rm", "-f", cid], check=False, capture_output=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", default="podman")
    parser.add_argument("--noise", type=Path, default=Path(__file__).resolve().parent.parent / "build-noise.toml")
    parser.add_argument("image_a")
    parser.add_argument("image_b")
    args = parser.parse_args(argv)
    rules = Rules.load(args.noise)

    cfg_a, cfg_b = config(args.engine, args.image_a), config(args.engine, args.image_b)
    diffs = [f"config {k}: A {cfg_a[k]!r}, B {cfg_b[k]!r}" for k in CONFIG_KEYS if cfg_a[k] != cfg_b[k]]
    a = export(args.engine, args.image_a, rules)
    b = export(args.engine, args.image_b, rules)
    diffs += compare(a, b)

    for line in diffs:
        print(line)
    for path in rules.unused():
        print(f"note: noise rule matched nothing, check whether it can go: {path}")
    print(f"{len(a)} paths in A, {len(b)} in B, {len(diffs)} differences outside build-noise.toml")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
