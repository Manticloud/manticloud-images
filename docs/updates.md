# How the images stay current

Every input to an image here is pinned: a commit, a digest, a version or a snapshot date. That's what makes a build
repeatable, and it also means nothing moves on its own. Three things move it, each as a pull request whose build proves
the change before anything is published:

| What moves a pin | Which pins | When |
|---|---|---|
| Renovate, a bot | commits, image digests, the pinned driver packages, the tools, the actions | Monday mornings, a pull request per pin |
| The daily scan | none itself: it opens an issue, and a person pins the fix | when a published image has a fixable critical or high CVE |
| A person | the CVE constraints, the snapshot date, a new branch, image or driver | as needed |

## Why

- **Consistency.** A floating input (a branch tip, a `latest` tag, today's package archive) changes an image without
  anyone deciding to. Pinning
  everything means an image changes only when a pull request says so, and two builds from the same commit of this
  repository hold the same files (`tools/compare_builds.py`).
- **Pins rot.** Upstream keeps fixing bugs and CVEs. Without something that notices, the pins fall behind and the images
  carry what's already fixed. Renovate does the noticing; the build does the checking; a person decides.
- **Nobody has to go looking.** Updates arrive as pull requests and CVEs as issues, so the work comes to us.

Renovate over Dependabot because Dependabot only reads the files of the ecosystems it knows (pip, Docker, Actions),
and most pins here are in our own TOML files: Renovate reads them through `customManagers` in `renovate.json`, one
regular expression per kind of pin. Both are free on a public repository.

## What Renovate watches

`renovate.json`, schedule `before 6am on monday`:

| Pin | File | Source it checks |
|---|---|---|
| openstack-helm-images' commit | `upstream.toml` | its `master` branch |
| The project's commit on each branch | `images/<image>.toml` | the branch named beside it (`stable/2026.1`, `master`) |
| Upstream's base images | `branches/<branch>.toml`: `venv_builder`, `base` | the tag's current digest |
| master's own base inputs | `branches/master.toml`: `from`, `ca`, `uv`, `requirements` | Ubuntu's and uv's images, openstack/requirements' `master` |
| A driver's source commit | `drivers/<image>/<driver>.toml` | the driver repository's `main` |
| A driver's `==` packages | `drivers/<image>/<driver>.toml` | PyPI |
| Trivy, and podman's image CI builds in | `tools/build.py`, `.github/workflows/` | the tag's current digest, and newer tags |
| GitHub actions | `.github/workflows/` | each action's releases, kept pinned by commit |

Renovate's **Dependency Dashboard** issue lists every pin it found and every pending update. A pin missing from it means
its `customManagers` expression didn't match the file: fix the expression, or the file.

## Handling a Renovate pull request

Its build runs everything a release does, for every image on every branch: build, check each driver, scan, build again
from scratch, and compare.

- **Green**: merge it. Nothing is published until the next `v*` tag.
- **The build fails to resolve** (uv's "No solution found"): the new input conflicts with a constraint. Read which
  package, and either move that constraint in the same pull request or close it and wait.
- **A check fails** (`driver pure: FAILED`): the update breaks something an image must do. Don't merge; find the fix
  upstream or hold the pin.
- **The scan fails**: the update brings in a CVE. Pin the fixed version in the branch's `[constraints]` on the same
  pull request.
- **The compare fails**: something now differs between two builds of the same inputs, so an input floats. Find it in the
  compare's list; add it to `build-noise.toml` only if it's noise, with why and the upstream change that would end it.

Renovate never edits `[constraints]` or the snapshot date.

## The daily scan

`.github/workflows/scan.yaml` scans every image the latest release published, every day, against Trivy's current
database. A CVE published after the release shows up here: the workflow keeps one issue per image and branch open while
a fixable critical or high CVE is found, adds the day's report to it, and closes it when none is.

To fix one: add the package to the branch's `[constraints]` at the fixed version, with the CVE IDs as its `why`, and open
a pull request. Its build shows whether the fix fits: cryptography 49, for example, needed pyOpenSSL 26.3.0 to resolve,
and then broke Cinder's imports until cursive went to 0.3.1. If a CVE doesn't apply to how the image is used, say so in
`vex.json` (OpenVEX: the status, the justification, the impact) instead of pinning; never in a `.trivyignore`.

## By hand

- **The snapshot date** (`snapshot` in each branch file): the date Ubuntu's packages are taken from. Move it to pick up
  Ubuntu's security updates, at least monthly and whenever the scan names an OS package. One pull request per branch.
- **Ceph's version** (`[ceph]` in each branch file): its repository keeps only its newest version, so when it publishes
  one, builds fail with the old version missing. Move it to the new one.
- **A new branch, image or driver**: see the README's Add section.

## Publishing

A `v*` tag (`v2026.11.14`) builds, checks, scans and compares again, then pushes each image as
`<branch>-<ubuntu>-<project version>-<commit>`, attests it (provenance and an SBOM), and writes a release listing every
image with its digest and pins. Pin an image by that digest; `master` images are for development, never production.
