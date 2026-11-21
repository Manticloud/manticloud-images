#!/usr/bin/env python3
"""Build, check and scan an image for an OpenStack branch from this repository's data, the same way here and in CI.

  build.py matrix                          every image and branch, as JSON for a workflow matrix
  build.py build IMAGE BRANCH TAG [--no-cache]
  build.py check IMAGE BRANCH TAG          the project commit, Ceph's version, the constraints and each driver
  build.py scan TAG [--out DIR]            Trivy, failing on a fixable critical or high CVE outside vex.json
  build.py version IMAGE BRANCH TAG        the tag to publish: <branch>-<ubuntu>-<project version>-<commit>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "build"
ENGINE = os.environ.get("ENGINE", "podman")
TRIVY = "ghcr.io/aquasecurity/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
# openssh-server's install makes host keys; every pod would share them, and anyone could pull them. Nova's chart
# makes a pod's own when none is there, so the hook in our base layer removes them in the RUN that installs.
HOST_KEYS = "/etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub"
CEPH_PACKAGES = ("ceph", "ceph-common", "python3-rados", "python3-rbd", "python3-cephfs", "python3-ceph-argparse",
                 "python3-ceph-common", "librados2", "librbd1", "libcephfs2", "libradosstriper1", "librgw2")
SOURCE = "https://github.com/Manticloud/manticloud-images"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST_REF = re.compile(r"^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$")


def load(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def run(*cmd: str, capture: bool = False, cwd: Path | None = None) -> str:
    print("+", " ".join(cmd), flush=True)
    out = subprocess.run(cmd, check=True, cwd=cwd, text=True, stdout=subprocess.PIPE if capture else None)
    return out.stdout if capture else ""


class Spec:
    """What one image on one branch is built from, read and checked from the data files."""

    def __init__(self, image: str, branch: str):
        self.image, self.branch = image, branch
        self.upstream = load(ROOT / "upstream.toml")
        self.img = load(ROOT / "images" / f"{image}.toml")
        self.br = load(ROOT / "branches" / f"{branch}.toml")
        if branch not in self.img["branches"]:
            raise SystemExit(f"images/{image}.toml doesn't build {branch}")
        self.project = self.img["branches"][branch]
        self.drivers = {p.stem: load(p) for p in sorted((ROOT / "drivers" / image).glob("*.toml"))
                        if branch in load(p).get("branches", [branch])}
        self.validate()

    def validate(self) -> None:
        problems = []
        pins = [("upstream.toml commit", self.upstream["commit"]),
                (f"images/{self.image}.toml {self.branch} commit", self.project["commit"])]
        for name, extra in self.img.get("extra", {}).items():
            if self.branch not in extra.get("branches", {}):
                problems.append(f"images/{self.image}.toml extra {name} has no {self.branch} commit")
            else:
                pins.append((f"images/{self.image}.toml extra {name} {self.branch} commit", extra["branches"][self.branch]["commit"]))
        for where, value in pins:
            if not COMMIT.match(value):
                problems.append(f"{where} isn't a full commit: {value}")
        if "build_base" in self.br:
            bb = self.br["build_base"]
            if not all(DIGEST_REF.match(bb.get(k, "")) for k in ("from", "ca")) or "@sha256:" not in bb["uv"] \
                    or not COMMIT.match(bb["requirements"]):
                problems.append(f"branches/{self.branch}.toml build_base: from, ca and uv by digest, requirements a commit")
        else:
            for key in ("venv_builder", "base"):
                if not DIGEST_REF.match(self.br.get(key, "")):
                    problems.append(f"branches/{self.branch}.toml {key} isn't a tag@digest")
        if not re.match(r"^\d{8}T\d{6}Z$", self.br.get("snapshot", "")):
            problems.append(f"branches/{self.branch}.toml snapshot isn't a snapshot.ubuntu.com time")
        for name, drv in self.drivers.items():
            for key in ("check", "license", "source"):
                if not drv.get(key):
                    problems.append(f"drivers/{self.image}/{name}.toml has no {key}")
            for pkg in drv.get("python", []):
                if pkg.startswith("git+") and not COMMIT.match(pkg.rsplit("@", 1)[-1]):
                    problems.append(f"drivers/{self.image}/{name}.toml: {pkg} isn't pinned to a full commit")
        if problems:
            raise SystemExit("\n".join(problems))

    def dockerfile(self, ohi: Path) -> Path:
        """Upstream's Dockerfile at the pinned commit, or the one carried here until upstream has one."""
        return ROOT / "carried" / self.img["dockerfile"] if self.img.get("carried") else ohi / self.img["dockerfile"]

    @property
    def project_name(self) -> str:
        return self.img["dockerfile"].split("/")[0]

    def packages(self) -> list[str]:
        return sorted({p for d in self.drivers.values() for p in d.get("packages", [])})

    def python(self) -> list[str]:
        return sorted({p for d in self.drivers.values() for p in d.get("python", [])})

    def extras(self) -> dict[str, dict]:
        return self.img.get("extra", {})

    def labels(self) -> dict[str, str]:
        return {"org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.licenses": "Apache-2.0",
                "org.manticloud.branch": self.branch,
                "org.manticloud.drivers": ",".join(self.drivers),
                "org.manticloud.project-commit": self.project["commit"],
                "org.manticloud.upstream-commit": self.upstream["commit"],
                "org.manticloud.snapshot": self.br["snapshot"]}


def upstream_checkout(spec: Spec) -> Path:
    path = WORK / "openstack-helm-images"
    if not (path / ".git").exists():
        run("git", "clone", "-q", spec.upstream["repo"], str(path))
    if run("git", "rev-parse", "HEAD", capture=True, cwd=path).strip() != spec.upstream["commit"]:
        run("git", "fetch", "-q", "origin", spec.upstream["branch"], cwd=path)
        run("git", "checkout", "-q", "--detach", spec.upstream["commit"], cwd=path)
    return path


def mirror(name: str, source: str, branch: str, commit: str, context: Path) -> None:
    """A bare mirror of a branch with `pinned` at the commit; the Dockerfile clones it over file://."""
    cache = WORK / "mirrors" / f"{name}.git"
    if not cache.exists():
        run("git", "clone", "-q", "--bare", source, str(cache))
    if subprocess.run(["git", "-C", str(cache), "cat-file", "-e", commit + "^{commit}"]).returncode:
        run("git", "-C", str(cache), "fetch", "-q", "origin", f"+refs/heads/{branch}:refs/heads/{branch}", "--tags")
    dest = context / "src" / f"{name}.git"
    run("git", "clone", "-q", "--bare", "--single-branch", "-b", branch, str(cache), str(dest))
    # No background maintenance after the fetch: it writes into the mirror while the build copies it.
    run("git", "-C", str(dest), "-c", "maintenance.auto=false", "-c", "gc.auto=0", "fetch", "-q", "--tags", str(cache))
    run("git", "-C", str(dest), "branch", "-f", "pinned", commit)


def project_mirror(spec: Spec, context: Path) -> None:
    """The project's mirror, and one for each extra source upstream's Dockerfile clones (Octavia's OVN provider)."""
    mirror(spec.project_name, spec.img["source"], spec.project["branch"], spec.project["commit"], context)
    for name, extra in spec.extras().items():
        pin = extra["branches"][spec.branch]
        mirror(name, pin["repo"], pin["branch"], pin["commit"], context)


def constrain(original: str, pins: dict[str, dict]) -> str:
    """upper-constraints with each pin's version in place of the original's, or added when it isn't there."""
    wanted = {norm(n): (n, p["version"]) for n, p in pins.items()}
    lines, seen = [], set()
    for line in original.splitlines():
        name = line.split("===", 1)[0].strip()
        key = norm(name) if "===" in line and not line.startswith("#") else None
        if key in wanted:
            seen.add(key)
            line = f"{name}==={wanted[key][1]}"
        lines.append(line)
    lines += [f"{n}==={v}" for k, (n, v) in sorted(wanted.items()) if k not in seen]
    return "\n".join(lines) + "\n"


def base_images(spec: Spec, ohi: Path) -> tuple[str, str]:
    """The branch's venv_builder and base: published by upstream, or built here from its Dockerfiles (master)."""
    if "build_base" not in spec.br:
        return spec.br["venv_builder"], spec.br["base"]
    bb, tag = spec.br["build_base"], f"localhost/manti-base/{{}}:{spec.branch}"
    context = WORK / f"base-{spec.branch}"
    context.mkdir(parents=True, exist_ok=True)
    (context / "50-manti-snapshot").write_text(f'APT::Snapshot "{spec.br["snapshot"]}";\n'
                                              'Acquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\n')
    (context / "Containerfile").write_text(
        "ARG FROM\nARG CA\nFROM ${CA} AS ca\nFROM ${FROM}\n"
        "COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n"
        "COPY 50-manti-snapshot /etc/apt/apt.conf.d/\n")
    run(ENGINE, "build", "-q", "--build-arg", f"FROM={bb['from']}", "--build-arg", f"CA={bb['ca']}",
        "-t", tag.format("ubuntu"), str(context))
    run(ENGINE, "build", "-q", "-f", str(ohi / "venv_builder" / "Dockerfile"), "--build-arg", f"FROM={tag.format('ubuntu')}",
        "--build-arg", f"UV_IMAGE_VERSION={bb['uv']}", "--build-arg", "REQUIREMENTS_REF=master",
        "--build-arg", "SETUPTOOLS_CONSTRAINT=", "-t", tag.format("venv_builder"), str(ohi))
    run(ENGINE, "build", "-q", "-f", str(ohi / "base" / "Dockerfile"), "--build-arg", f"FROM={tag.format('ubuntu')}",
        "--build-arg", f"CEPH_REPO={bb['ceph_repo']}", "--build-arg", f"CEPH_KEY={bb['ceph_key']}",
        "-t", tag.format("base"), str(ohi))
    return tag.format("venv_builder"), tag.format("base")


def pin_layers(spec: Spec, venv_builder: str, base: str) -> tuple[str, str]:
    """Our two layers: the snapshot, the constraints and the project's mirror on venv_builder; the snapshot and
    Ceph's version on base. Nothing but files, so they're the same every time."""
    context = WORK / f"{spec.image}-{spec.branch}"
    shutil.rmtree(context, ignore_errors=True)
    context.mkdir(parents=True)
    (context / "50-manti-snapshot").write_text(f'APT::Snapshot "{spec.br["snapshot"]}";\n')
    version = spec.br["ceph"]["version"]
    (context / "50-manti-ceph").write_text("".join(
        f"Package: {p}\nPin: version {version}\nPin-Priority: 1001\n\n" for p in CEPH_PACKAGES))
    if "build_base" in spec.br:
        url = f"https://opendev.org/openstack/requirements/raw/commit/{spec.br['build_base']['requirements']}/upper-constraints.txt"
        original = urllib.request.urlopen(url).read().decode()
    else:
        original = run(ENGINE, "run", "--rm", venv_builder, "cat", "/upper-constraints.txt", capture=True)
    (context / "upper-constraints.txt").write_text(constrain(original, spec.br.get("constraints", {})))
    project_mirror(spec, context)
    (context / "Containerfile.venv_builder").write_text(
        "ARG FROM\nFROM ${FROM}\nCOPY 50-manti-snapshot /etc/apt/apt.conf.d/\n"
        "COPY upper-constraints.txt /upper-constraints.txt\nCOPY src/ /src/\n"
        # uWSGI's parallel compile sometimes links before an object exists ("cannot find core/legion.o").
        "ENV CPUCOUNT=1\n"
        # Debug info records uv's random build folder, so C extensions built from source differ between builds.
        "ENV CFLAGS=-g0\n")
    (context / "50-manti-no-host-keys").write_text(f'DPkg::Post-Invoke {{ "rm -f {HOST_KEYS}"; }};\n')
    (context / "Containerfile.base").write_text(
        "ARG FROM\nFROM ${FROM}\nCOPY 50-manti-snapshot 50-manti-no-host-keys /etc/apt/apt.conf.d/\n"
        "COPY 50-manti-ceph /etc/apt/preferences.d/\n")
    tags = (f"localhost/manti-pin/{spec.image}-venv_builder:{spec.branch}", f"localhost/manti-pin/{spec.image}-base:{spec.branch}")
    run(ENGINE, "build", "-q", "-f", str(context / "Containerfile.venv_builder"), "--build-arg", f"FROM={venv_builder}",
        "-t", tags[0], str(context))
    run(ENGINE, "build", "-q", "-f", str(context / "Containerfile.base"), "--build-arg", f"FROM={base}",
        "-t", tags[1], str(context))
    return tags


def unconstrained(spec: Spec, constraints: str) -> list[str]:
    """Python packages a driver adds that are neither in upper-constraints nor pinned with == or a commit."""
    known = {norm(line.split("===", 1)[0]) for line in constraints.splitlines() if "===" in line}
    return [p for p in spec.python() if not p.startswith("git+") and "==" not in p and norm(p) not in known]


def build(spec: Spec, tag: str, no_cache: bool) -> None:
    ohi = upstream_checkout(spec)
    venv_builder, base = pin_layers(spec, *base_images(spec, ohi))
    loose = unconstrained(spec, (WORK / f"{spec.image}-{spec.branch}" / "upper-constraints.txt").read_text())
    if loose:
        raise SystemExit(f"not in upper-constraints and not pinned: {', '.join(loose)}")
    cmd = [ENGINE, "build", "-f", str(spec.dockerfile(ohi)),
           "--build-arg", f"BASE_VENV_BUILDER={venv_builder}", "--build-arg", f"BASE_RUNTIME={base}",
           "--build-arg", f"{spec.img['repo_arg']}=file:///src/{spec.project_name}.git",
           "--build-arg", f"{spec.img['ref_arg']}=pinned",
           *[a for name, extra in spec.extras().items() for a in
             ("--build-arg", f"{extra['repo_arg']}=file:///src/{name}.git", "--build-arg", f"{extra['ref_arg']}=pinned")],
           "--build-arg", f"EXTRA_PACKAGES={' '.join(spec.packages())}",
           "--build-arg", f"EXTRA_PYTHON_PACKAGES={' '.join(spec.python())}"]
    for key, value in spec.labels().items():
        cmd += ["--label", f"{key}={value}"]
    if no_cache:
        cmd.append("--no-cache")
    run(*cmd, "-t", tag, str(ohi))


def in_image(tag: str, script: str) -> subprocess.CompletedProcess:
    return subprocess.run([ENGINE, "run", "--rm", "--entrypoint", "sh", tag, "-c", script], text=True,
                          capture_output=True)


def check(spec: Spec, tag: str) -> None:
    failures = []
    commit = in_image(tag, "cat /etc/image_info/project.txt").stdout.split(" ", 1)[0]
    if not commit or not spec.project["commit"].startswith(commit):
        failures.append(f"project commit is {commit or 'unknown'}, not {spec.project['commit']}")
    dpkg = in_image(tag, "dpkg-query -W -f '${Package} ${Version}\\n'").stdout.split("\n")
    for line in filter(None, dpkg):
        name, version = line.split(" ", 1)
        if name in CEPH_PACKAGES and version != spec.br["ceph"]["version"]:
            failures.append(f"{name} is {version}, not {spec.br['ceph']['version']}")
    frozen = {norm(l.split("==", 1)[0]): l.split("==", 1)[1] for l in
              in_image(tag, "cat /etc/image_info/pip.txt").stdout.splitlines() if "==" in l and " @ " not in l}
    for name, pin in spec.br.get("constraints", {}).items():
        if frozen.get(norm(name), pin["version"]) != pin["version"]:
            failures.append(f"{name} is {frozen[norm(name)]}, not the pinned {pin['version']}")
    if keys := in_image(tag, f"ls {HOST_KEYS} 2>/dev/null").stdout.split():
        failures.append(f"SSH host keys baked into the image: {', '.join(keys)}")
    checks = [("image", spec.img["check"])] + [(f"driver {n}", d["check"]) for n, d in spec.drivers.items()]
    for what, script in checks:
        result = in_image(tag, script)
        print(f"{what}: {'ok' if result.returncode == 0 else 'FAILED'}")
        if result.returncode:
            failures.append(f"{what}: {script}\n{result.stdout}{result.stderr}".rstrip())
    if failures:
        raise SystemExit("\n".join(failures))


def scan(tag: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    archive = out / "image.tar"
    run(ENGINE, "save", "-q", "-o", str(archive), tag)
    base = [ENGINE, "run", "--rm", "-v", f"{out.resolve()}:/w:Z", "-v", f"{ROOT}/vex.json:/vex.json:ro,Z", TRIVY]
    run(*base, "image", "-q", "--input", "/w/image.tar", "--format", "cyclonedx", "--output", "/w/sbom.cdx.json")
    run(*base, "image", "-q", "--input", "/w/image.tar", "--format", "json", "--output", "/w/trivy.json",
        "--vex", "/vex.json", "--ignore-unfixed", "--severity", "CRITICAL,HIGH")
    archive.unlink()
    found = [(r["Target"], v["PkgName"], v["InstalledVersion"], v["VulnerabilityID"], v["Severity"], v.get("FixedVersion"))
             for r in json.loads((out / "trivy.json").read_text()).get("Results", [])
             for v in r.get("Vulnerabilities") or []]
    for f in found:
        print("{1} {2}: {3} {4}, fixed in {5} ({0})".format(*f))
    if found:
        raise SystemExit(f"{len(found)} fixable critical or high CVEs: pin a fixed version in branches/, or say why "
                         "it doesn't apply in vex.json")


def version(spec: Spec, tag: str) -> str:
    package = spec.img.get("package", spec.project_name)
    found = in_image(tag, f"python -c 'import importlib.metadata as m; print(m.version(\"{package}\"))'")
    if found.returncode or not found.stdout.strip():
        raise SystemExit(f"no {package} version in {tag}: {found.stderr}")
    return f"{spec.branch}-{spec.br['ubuntu']}-{found.stdout.strip()}-{spec.project['commit'][:9]}"


def matrix() -> list[dict]:
    return [{"image": p.stem, "branch": b} for p in sorted((ROOT / "images").glob("*.toml"))
            for b in load(p)["branches"]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("matrix")
    for name in ("build", "check", "version"):
        p = sub.add_parser(name)
        p.add_argument("image")
        p.add_argument("branch")
        p.add_argument("tag")
        if name == "build":
            p.add_argument("--no-cache", action="store_true")
    p = sub.add_parser("scan")
    p.add_argument("tag")
    p.add_argument("--out", type=Path, default=WORK / "scan")
    args = parser.parse_args(argv)

    if args.cmd == "matrix":
        print(json.dumps(matrix()))
    elif args.cmd == "scan":
        scan(args.tag, args.out)
    else:
        spec = Spec(args.image, args.branch)
        if args.cmd == "build":
            build(spec, args.tag, args.no_cache)
        elif args.cmd == "check":
            check(spec, args.tag)
        else:
            print(version(spec, args.tag))
    return 0


if __name__ == "__main__":
    sys.exit(main())
