# MANTI images

OpenStack service images: openstack-helm-images' own, built from its Dockerfiles, with some extra security on top.
Published to `ghcr.io/manticloud/<image>`.

- **Every input pinned**: the project and upstream at a commit, base images by digest, Ubuntu's packages at a snapshot
  date. Two builds from scratch must hold the same files (`tools/compare_builds.py`).
- **CVE fixes**: libraries with a fixable critical or high CVE are pinned to the fixed version before anything installs,
  each with the CVEs it fixes; the build fails on any left.
- **Attested**: each published image carries build provenance and an SBOM; a daily scan reopens an issue when a new CVE
  lands in a published image.
- **Storage drivers added as data**, each with a check that it loads (`drivers/`).

| Path | What |
|---|---|
| `upstream.toml` | openstack-helm-images, at a commit |
| `branches/<branch>.toml` | one OpenStack branch: Ubuntu, base images by digest, the package snapshot, Ceph's version, the constraints we pin and why |
| `images/<image>.toml` | upstream's Dockerfile for the image, and the project's commit on each branch it's built for |
| `carried/<image>/Dockerfile` | a Dockerfile openstack-helm-images doesn't have yet, built until it does (`carried = true`) |
| `drivers/<image>/<driver>.toml` | one driver: its packages, its check, license and source |
| `vex.json` | CVEs that don't apply, each with its reason (OpenVEX) |
| `build-noise.toml` | the files two builds from the same inputs may differ in, and the upstream change that would end each |
| `tools/build.py` | build, check, scan and name an image, the same way on a workstation and in CI |
| `tools/compare_builds.py` | compares two builds file by file; fails on anything `build-noise.toml` doesn't name |
| `metal3/ironic.toml` | Ironic's image: metal3-io/ironic-image at a commit, its base image by digest, and what it must hold |
| `tools/metal3.py` | build, check and scan Ironic's image for one platform |

## Build one

Needs podman 5 and Python 3.11 or later; the tools use the standard library only.

```console
python3 tools/build.py build cinder 2026.1 localhost/manti/cinder:one
python3 tools/build.py check cinder 2026.1 localhost/manti/cinder:one
python3 tools/build.py scan localhost/manti/cinder:one
python3 tools/build.py build cinder 2026.1 localhost/manti/cinder:two --no-cache
python3 tools/compare_builds.py localhost/manti/cinder:one localhost/manti/cinder:two
python3 -m unittest discover -s tests
```

CI runs the same steps for every image on every branch (`.github/workflows/build.yaml`); a `v*` tag publishes,
attests (provenance and SBOM) and writes the release. `scan.yaml` scans what's published daily and keeps an issue open
per image while a fixable critical or high CVE is found. Renovate moves the pins by pull request.

**How the pins move, and what to do with each pull request and issue: [docs/updates.md](docs/updates.md).**

## Ironic

Ironic's image is metal3-io/ironic-image's own, built from its Dockerfile unchanged, for amd64 and arm64: upstream
publishes it for amd64 only. It installs CentOS Stream's packages as it builds, so it isn't held to `compare_builds.py`,
and its scan is reported, not failed on. `.github/workflows/ironic.yaml` builds each platform on its own runner, and an
`ironic-*` tag publishes both as one multi-arch image, `ghcr.io/manticloud/ironic:<branch>-<commit>`.

```console
python3 tools/metal3.py build arm64 localhost/manti/ironic:arm64
python3 tools/metal3.py check localhost/manti/ironic:arm64
python3 tools/metal3.py scan localhost/manti/ironic:arm64
```

## Add

- **A driver**: `drivers/<image>/<name>.toml`. Its Python packages are in upper-constraints, pinned with `==`, or a
  git source at a full commit; its `check` proves it loads; `branches` limits it to some branches.
- **A branch** (2027.1): `branches/2027.1.toml` once openstack-helm-images publishes its base images, and a line in
  each `images/*.toml`.
- **An image**: `images/<image>.toml` naming upstream's Dockerfile, and its project in `renovate.json`.
  Upstream has no Dockerfile for it: `carried/<image>/Dockerfile` and `carried = true`, removed when upstream's lands.
- **A constraint**: a line in the branch's `[constraints]`, with the CVEs or the reason.
