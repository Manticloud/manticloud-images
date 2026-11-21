"""The data files and workflows: every input pinned, every rule kept, nothing a build would trip on."""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import build  # noqa: E402

class Repo(unittest.TestCase):
    def test_every_image_on_every_branch_is_pinned(self):
        """Spec refuses a commit that isn't full, a base image without a digest, or an unpinned driver source."""
        for entry in build.matrix():
            with self.subTest(**entry):
                build.Spec(entry["image"], entry["branch"])

    def test_every_branch_has_a_file_and_every_driver_an_image(self):
        branches = {p.stem for p in (ROOT / "branches").glob("*.toml")}
        self.assertTrue({e["branch"] for e in build.matrix()} <= branches)
        images = {p.stem for p in (ROOT / "images").glob("*.toml")}
        self.assertTrue({p.name for p in (ROOT / "drivers").iterdir()} <= images)

    def test_a_carried_dockerfile_exists_and_only_where_an_image_says_so(self):
        carried = {p.relative_to(ROOT / "carried").as_posix() for p in (ROOT / "carried").rglob("Dockerfile")}
        named = {build.load(p)["dockerfile"] for p in (ROOT / "images").glob("*.toml") if build.load(p).get("carried")}
        self.assertEqual(carried, named)

    def test_every_constraint_says_why(self):
        for path in (ROOT / "branches").glob("*.toml"):
            for name, pin in build.load(path).get("constraints", {}).items():
                with self.subTest(branch=path.stem, package=name):
                    self.assertTrue(pin.get("version") and pin.get("why"))

    def test_every_action_a_workflow_uses_is_pinned_to_a_commit(self):
        uses = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.M)
        for path in (ROOT / ".github" / "workflows").glob("*.y*ml"):
            for ref in uses.findall(path.read_text()):
                with self.subTest(workflow=path.name, uses=ref):
                    self.assertTrue(ref.startswith("./") or re.search(r"@[0-9a-f]{40}$", ref), ref)

    def test_renovate_moves_every_images_project_pins(self):
        import json
        managers = json.loads((ROOT / "renovate.json").read_text())["customManagers"]
        for path in (ROOT / "images").glob("*.toml"):
            with self.subTest(image=path.stem):
                source = build.load(path)["source"]
                self.assertTrue(any(m.get("depNameTemplate") == source and any(re.search(f.strip("/"), f"images/{path.name}") for f in m["managerFilePatterns"])
                                    for m in managers), f"renovate.json has no manager for {path.name}'s {source}")

    def test_the_vex_file_is_openvex(self):
        import json
        vex = json.loads((ROOT / "vex.json").read_text())
        self.assertEqual(vex["@context"], "https://openvex.dev/ns/v0.2.0")
        for statement in vex["statements"]:
            self.assertIn(statement["status"], {"not_affected", "fixed", "under_investigation", "affected"})
            if statement["status"] == "not_affected":
                self.assertTrue(statement.get("justification") and statement.get("impact_statement"))


class Constraints(unittest.TestCase):
    ORIGINAL = "# comment\nPyJWT===2.11.0\nurllib3===2.6.3\nzstd===1.5.7.3\nlxml===6.0.2\n"

    def test_a_pin_replaces_the_version_whatever_the_names_spelling(self):
        out = build.constrain(self.ORIGINAL, {"pyjwt": {"version": "2.14.0"}, "ZSTD": {"version": "1.5.7.2"}})
        self.assertEqual(out, "# comment\nPyJWT===2.14.0\nurllib3===2.6.3\nzstd===1.5.7.2\nlxml===6.0.2\n")

    def test_a_pin_not_in_upper_constraints_is_added(self):
        out = build.constrain(self.ORIGINAL, {"new_pkg": {"version": "1.0"}})
        self.assertTrue(out.endswith("lxml===6.0.2\nnew_pkg===1.0\n"))

    def test_no_pins_changes_nothing(self):
        self.assertEqual(build.constrain(self.ORIGINAL, {}), self.ORIGINAL)

    def test_a_driver_package_must_be_constrained_or_pinned(self):
        spec = build.Spec("cinder", "2026.1")
        constraints = "py-pure-client===1.83.1\nwebsocket-client===1.9.0\n"
        self.assertEqual(build.unconstrained(spec, constraints), [])
        self.assertEqual(build.unconstrained(spec, "websocket-client===1.9.0\n"), ["py-pure-client"])


if __name__ == "__main__":
    unittest.main()
