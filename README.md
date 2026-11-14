# MANTI images

The OpenStack images MANTI Deployer must change, and only those: openstack-helm-images' own Dockerfiles at a pinned
commit, each storage driver added as data, every input pinned. Published to `ghcr.io/manticloud/<image>`; why and how
in adr/0064 of manticloud-deployer.

| Path | What |
|---|---|
| `upstream.toml` | openstack-helm-images, at a commit |
| `branches/<branch>.toml` | one OpenStack branch: Ubuntu, base images by digest, the package snapshot, Ceph's version, the constraints we pin and why |
| `images/<image>.toml` | upstream's Dockerfile for the image, and the project's commit on each branch it's built for |
| `drivers/<image>/<driver>.toml` | one driver: its packages, its check, license and source |
| `vex.json` | CVEs that don't apply, each with its reason (OpenVEX) |
| `build-noise.toml` | the files two builds from the same inputs may differ in, and the upstream change that would end each |
| `tools/build.py` | build, check, scan and name an image, the same way on a workstation and in CI |
| `tools/compare_builds.py` | compares two builds file by file; fails on anything `build-noise.toml` doesn't name |

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

## Add

- **A driver**: `drivers/<image>/<name>.toml`. Its Python packages are in upper-constraints, pinned with `==`, or a
  git source at a full commit; its `check` proves it loads; `branches` limits it to some branches.
- **A branch** (2027.1): `branches/2027.1.toml` once openstack-helm-images publishes its base images, and a line in
  each `images/*.toml`.
- **An image**: `images/<image>.toml` naming upstream's Dockerfile, and its project in `renovate.json`.
- **A constraint**: a line in the branch's `[constraints]`, with the CVEs or the reason.
