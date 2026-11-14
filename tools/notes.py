#!/usr/bin/env python3
"""Release notes from the published images and this repository's data: what each image is and what it pins.

Usage: notes.py images.txt, one name:tag@digest per line, the tag starting with the branch.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build  # noqa: E402


def notes(lines: list[str]) -> str:
    out = []
    for line in filter(None, (l.strip() for l in lines)):
        ref, digest = line.split("@", 1)
        name, tag = ref.rsplit(":", 1)
        image = name.rsplit("/", 1)[-1]
        branch = next(b for b in build.load(build.ROOT / "images" / f"{image}.toml")["branches"]
                      if tag.startswith(f"{b}-"))
        spec = build.Spec(image, branch)
        out += [f"## {image} {branch}", "", f"`{name}:{tag}`", "", f"`{digest}`", "",
                f"- {image} at `{spec.project['commit']}` ({spec.project['branch']})",
                f"- openstack-helm-images at `{spec.upstream['commit']}`",
                f"- Ubuntu packages as of {spec.br['snapshot']}, Ceph {spec.br['ceph']['version']}",
                f"- Drivers: {', '.join(spec.drivers) or 'none'}"]
        for pin_name, pin in spec.br.get("constraints", {}).items():
            out.append(f"- {pin_name} {pin['version']}: {pin['why']}")
        out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    print(notes(Path(sys.argv[1]).read_text().splitlines()))
