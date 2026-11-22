"""Ironic's image: its inputs pinned, both platforms built, and Renovate moving its pins."""

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import metal3  # noqa: E402


class Ironic(unittest.TestCase):
    def test_its_commit_and_base_image_are_pinned(self):
        metal3.load()

    def test_the_workflow_builds_every_platform_and_publishes_them_as_one(self):
        text = (ROOT / ".github" / "workflows" / "ironic.yaml").read_text()
        for platform in metal3.PLATFORMS:
            self.assertRegex(text, rf"platform: {platform}, runner: ")
            self.assertIn(platform, re.search(r"for p in ([^;]+);", text).group(1))

    def test_renovate_moves_its_commit_and_base_image(self):
        managers = json.loads((ROOT / "renovate.json").read_text())["customManagers"]
        text = metal3.SPEC.read_text()
        for name in ("commit", "base"):
            with self.subTest(pin=name):
                self.assertTrue(any(any(re.search(f.strip("/"), "metal3/ironic.toml") for f in m["managerFilePatterns"])
                                    and any(name in s and re.search(s.replace("(?<", "(?P<"), text) for s in m["matchStrings"])
                                    for m in managers), f"renovate.json doesn't move metal3/ironic.toml's {name}")

    def test_a_short_commit_or_a_floating_base_is_refused(self):
        good = metal3.build.load(metal3.SPEC)
        for bad in ({"commit": good["commit"][:9]}, {"base": "quay.io/centos/centos:stream9-minimal"}):
            with self.subTest(**bad):
                orig = metal3.build.load
                metal3.build.load = lambda _p, b=bad: {**good, **b}
                try:
                    with self.assertRaises(SystemExit):
                        metal3.load()
                finally:
                    metal3.build.load = orig


if __name__ == "__main__":
    unittest.main()
