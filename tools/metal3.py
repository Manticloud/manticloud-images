#!/usr/bin/env python3
"""Build, check and scan Ironic's image from metal3-io/ironic-image, unchanged, one platform at a time.

  metal3.py build PLATFORM TAG [--no-cache]   PLATFORM is amd64 or arm64
  metal3.py check TAG                         its Ironic commit, and metal3/ironic.toml's check
  metal3.py scan TAG [--out DIR]              Trivy's report and SBOM: reported, never failed on
  metal3.py version                           the tag to publish: <branch>-<commit>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build  # noqa: E402

SPEC = build.ROOT / "metal3" / "ironic.toml"
PLATFORMS = ("amd64", "arm64")
# pbr records the commit Ironic was installed from
PBR = "/usr/lib/python3.12/site-packages/ironic-*.dist-info/pbr.json"


def load() -> dict:
    """metal3/ironic.toml, refused unless the commit is full and the base image is pinned by digest."""
    spec = build.load(SPEC)
    if not build.COMMIT.match(spec.get("commit", "")):
        raise SystemExit(f"{SPEC.name}: commit must be a full 40-character commit")
    if not build.DIGEST_REF.match(spec.get("base", "")):
        raise SystemExit(f"{SPEC.name}: base must be name:tag@sha256:<digest>")
    if not re.fullmatch(r"[0-9a-f]{7,40}", spec.get("ironic", "")) or not spec.get("check"):
        raise SystemExit(f"{SPEC.name}: ironic names Ironic's commit, and check what the image must hold")
    return spec


def checkout(spec: dict) -> Path:
    path = build.WORK / "ironic-image"
    if not (path / ".git").exists():
        build.run("git", "clone", "-q", spec["repo"], str(path))
    if build.run("git", "rev-parse", "HEAD", capture=True, cwd=path).strip() != spec["commit"]:
        build.run("git", "fetch", "-q", "origin", spec["branch"], cwd=path)
        build.run("git", "checkout", "-q", "--detach", spec["commit"], cwd=path)
    return path


def labels(spec: dict) -> dict[str, str]:
    return {"org.opencontainers.image.source": build.SOURCE,
            "org.opencontainers.image.licenses": "Apache-2.0",
            "org.manticloud.upstream": spec["repo"],
            "org.manticloud.upstream-commit": spec["commit"]}


def build_image(platform: str, tag: str, no_cache: bool) -> None:
    if platform not in PLATFORMS:
        raise SystemExit(f"platform is one of {', '.join(PLATFORMS)}")
    spec = load()
    src = checkout(spec)
    cmd = [build.ENGINE, "build", "--platform", f"linux/{platform}", "--build-arg", f"BASE_IMAGE={spec['base']}",
           *[a for k, v in labels(spec).items() for a in ("--label", f"{k}={v}")], "-t", tag]
    build.run(*cmd, *(["--no-cache"] if no_cache else []), str(src))


def check(tag: str) -> None:
    spec, failures = load(), []
    found = build.in_image(tag, f"cat {PBR}").stdout
    commit = json.loads(found).get("git_version", "") if found.strip().startswith("{") else ""
    if not commit or not spec["ironic"].startswith(commit):
        failures.append(f"Ironic is at {commit or 'unknown'}, not commit {spec['ironic']}")
    result = build.in_image(tag, spec["check"])
    print(f"image: {'ok' if result.returncode == 0 else 'FAILED'}")
    if result.returncode:
        failures.append(f"image: {spec['check']}\n{result.stdout}{result.stderr}".rstrip())
    if failures:
        raise SystemExit("\n".join(failures))


def scan(tag: str, out: Path) -> None:
    try:
        build.scan(tag, out)
    except SystemExit as found:      # upstream's pins, unchanged: the report is for reading, not a gate
        print(f"Reported, not failed on: {str(found).split(':', 1)[0]}")


def version() -> str:
    spec = load()
    return f"{spec['branch']}-{spec['commit'][:9]}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("build")
    p.add_argument("platform")
    p.add_argument("tag")
    p.add_argument("--no-cache", action="store_true")
    sub.add_parser("check").add_argument("tag")
    p = sub.add_parser("scan")
    p.add_argument("tag")
    p.add_argument("--out", type=Path, default=build.WORK / "scan-metal3-ironic")
    sub.add_parser("version")
    args = parser.parse_args(argv)
    if args.cmd == "build":
        build_image(args.platform, args.tag, args.no_cache)
    elif args.cmd == "check":
        check(args.tag)
    elif args.cmd == "scan":
        scan(args.tag, args.out)
    else:
        print(version())
    return 0


if __name__ == "__main__":
    sys.exit(main())
