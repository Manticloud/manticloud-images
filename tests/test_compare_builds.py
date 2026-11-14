"""tools/compare_builds.py: what it lets through and what it fails on, from synthetic filesystem tars."""

import io
import sys
import tarfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import compare_builds  # noqa: E402

RECORD = "/var/lib/openstack/lib/python3.12/site-packages/cinder-28.1.1.dist-info/RECORD"
UV_CACHE = "/var/lib/openstack/lib/python3.12/site-packages/cinder-28.1.1.dist-info/uv_cache.json"


def tar(files: dict[str, bytes], mode: int = 0o644) -> io.BytesIO:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for path, data in files.items():
            info = tarfile.TarInfo(path.lstrip("/"))
            info.size, info.mode = len(data), mode
            t.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def diff(a: dict[str, bytes], b: dict[str, bytes], mode_b: int = 0o644) -> tuple[list[str], compare_builds.Rules]:
    rules = compare_builds.Rules.load(ROOT / "build-noise.toml")
    return compare_builds.compare(compare_builds.manifest(tar(a), rules),
                                  compare_builds.manifest(tar(b, mode_b), rules)), rules


BASE = {
    "/etc/shadow": b"root:*:20767:0:99999:7:::\ncinder:!:20770:0:99999:7:::\n",
    "/etc/iscsi/initiatorname.iscsi": b"## comment\nInitiatorName=iqn.2004-10.com.ubuntu:01:7b9a3b62cabf\n",
    "/var/log/dpkg.log": b"2026-11-13 23:52:58 install nfs-common\n",
    "/var/lib/openstack/bin/uwsgi": b"binary built 13 November 2026",
    UV_CACHE: b'{"timestamp":{"secs_since_epoch":1794613968}}',
    RECORD: b"cinder/__init__.py,sha256=abc,10\n"
            b"cinder-28.1.1.dist-info/uv_cache.json,sha256=ROkgjJqJ,137\n",
    "/var/lib/openstack/lib/python3.12/site-packages/urllib3/__init__.py": b"__version__ = '2.6.3'\n",
}


class CompareBuilds(unittest.TestCase):
    def test_the_two_spike_builds_differ_only_in_noise(self):
        """The differences two from-scratch builds of Cinder showed all pass."""
        b = dict(BASE)
        b["/etc/shadow"] = b"root:*:20767:0:99999:7:::\ncinder:!:20771:0:99999:7:::\n"
        b["/etc/iscsi/initiatorname.iscsi"] = b"## comment\nInitiatorName=iqn.2004-10.com.ubuntu:01:ab691eee42\n"
        b["/var/log/dpkg.log"] = b"2026-11-14 00:00:08 install nfs-common\n"
        b["/var/lib/openstack/bin/uwsgi"] = b"binary built 14 November 2026"
        b[UV_CACHE] = b'{"timestamp":{"secs_since_epoch":1794614398}}'
        b[RECORD] = (b"cinder/__init__.py,sha256=abc,10\n"
                     b"cinder-28.1.1.dist-info/uv_cache.json,sha256=_jSWk8yL,136\n")
        found, _ = diff(BASE, b)
        self.assertEqual(found, [])

    def test_a_package_version_that_moved_fails(self):
        b = dict(BASE)
        b["/var/lib/openstack/lib/python3.12/site-packages/urllib3/__init__.py"] = b"__version__ = '2.8.0'\n"
        found, _ = diff(BASE, b)
        self.assertEqual(found, ["differs (content): /var/lib/openstack/lib/python3.12/site-packages/urllib3/__init__.py"])

    def test_a_normalized_file_still_fails_outside_its_pattern(self):
        b = dict(BASE)
        b["/etc/shadow"] = b"root:*:20767:0:99999:7:::\ncinder:!:20770:0:99999:7:::\nnova:!:20770:0:99999:7:::\n"
        found, _ = diff(BASE, b)
        self.assertEqual(found, ["differs (content): /etc/shadow"])

    def test_a_record_line_other_than_the_noise_fails(self):
        b = dict(BASE)
        b[RECORD] = BASE[RECORD].replace(b"sha256=abc,10", b"sha256=xyz,10")
        found, _ = diff(BASE, b)
        self.assertEqual(found, [f"differs (content): {RECORD}"])

    def test_an_ignored_file_must_still_exist_with_the_same_mode(self):
        b = {k: v for k, v in BASE.items() if k != "/var/log/dpkg.log"}
        found, _ = diff(BASE, b)
        self.assertEqual(found, ["only in A: /var/log/dpkg.log"])
        found, _ = diff(BASE, dict(BASE), mode_b=0o600)
        self.assertEqual(len(found), len(BASE))
        self.assertTrue(all(line.startswith("differs (mode)") for line in found))

    def test_a_file_only_one_build_has_fails(self):
        b = dict(BASE, **{"/var/lib/openstack/lib/python3.12/site-packages/pydantic/__init__.py": b""})
        found, _ = diff(BASE, b)
        self.assertEqual(found, ["only in B: /var/lib/openstack/lib/python3.12/site-packages/pydantic/__init__.py"])

    def test_every_rule_says_why_and_what_upstream_would_change(self):
        rules = compare_builds.Rules.load(ROOT / "build-noise.toml")
        for rule in rules.ignore + rules.normalize:
            self.assertTrue(rule.get("why") and rule.get("upstream"), rule["path"])

    def test_a_rule_that_matched_nothing_is_reported(self):
        _, rules = diff(BASE, dict(BASE))
        self.assertIn("/var/log/alternatives.log", rules.unused())
        self.assertNotIn("/etc/shadow", rules.unused())


if __name__ == "__main__":
    unittest.main()
