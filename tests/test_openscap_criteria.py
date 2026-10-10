"""Live OpenSCAP regression tests on Rocky 9 with gzip installed.

The affected-package cases use a synthetic version threshold. No packages
are downgraded or changed. Results can be retained with OVAL_TEST_ARTIFACTS.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from oval import transform, xml


def fixture(packages, rl_version):
    scope = xml.version["Scope"]
    tag = xml.version["Tag"]
    contents = transform.criterias([], "", rl_version)
    contents.extend(transform.criterias(
        packages, "Rocky Linux " + str(rl_version), rl_version
    ))
    definitions = [{"id": "20224582", "criteria": contents}]
    tests, objects, states = transform.generate(definitions, rl_version)
    metadata = xml.metadata(
        "Platform guard regression fixture", "unix",
        ["Rocky Linux " + str(rl_version)], "RLSA-2022:4582", "RLSA", [],
        "Local test fixture; synthetic thresholds are not security advisories.",
        "Important", "2022-05-17", "2022-05-17", [], rl_version,
    )
    parts = [xml.header(xml.version), xml.section("definitions"),
             xml.definition(scope, "20224582", transform.transform_version["Definition"],
                            "patch", metadata, xml.criteria(scope, contents)),
             xml.section("definitions", True), xml.section("tests")]
    for test in tests:
        parts.append(xml.test(tag, scope, test["type"], test["id"],
                              test["version"], test["comment"], test["check"],
                              test["oid"], test["sids"]))
    parts.extend([xml.section("tests", True), xml.section("objects")])
    for obj in objects:
        parts.append(xml.object(tag, scope, obj["type"], obj["id"],
                                obj["version"], obj["contents"]))
    parts.extend([xml.section("objects", True), xml.section("states")])
    for state in states:
        parts.append(xml.state(tag, scope, state["type"], state["id"],
                               state["version"], state["contents"]))
    parts.extend([xml.section("states", True), xml.footer()])
    return "\n".join(parts)


@unittest.skipUnless(shutil.which("oscap") and shutil.which("rpm"),
                     "requires OpenSCAP and RPM")
class OpenSCAPCriteriaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        release = subprocess.run(
            ["rpm", "-q", "--qf", "%{VERSION}", "rocky-release"],
            text=True, capture_output=True,
        )
        if release.returncode or not release.stdout.startswith("9."):
            raise unittest.SkipTest("requires a Rocky Linux 9 host")
        gzip = subprocess.run(["rpm", "-q", "gzip"], capture_output=True)
        if gzip.returncode:
            raise unittest.SkipTest("requires installed gzip")
        cls.temporary = tempfile.TemporaryDirectory(prefix="oval-criteria-")
        cls.artifacts = Path(os.environ.get("OVAL_TEST_ARTIFACTS", cls.temporary.name))
        cls.artifacts.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def check_fixture(self, name, packages, rl_version, expected):
        source = self.artifacts / (name + ".xml")
        result = self.artifacts / (name + "-results.xml")
        source.write_text(fixture(packages, rl_version), encoding="utf-8")
        for stage, command in (
            ("validate", ["oscap", "oval", "validate", str(source)]),
            ("eval", ["oscap", "oval", "eval", "--results", str(result), str(source)]),
        ):
            run = subprocess.run(command, text=True, capture_output=True)
            (self.artifacts / (name + "-" + stage + ".log")).write_text(
                run.stdout + run.stderr, encoding="utf-8"
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        root = ET.parse(result).getroot()
        results = [x.get("result") for x in root.iter()
                   if x.tag.endswith("}definition") and x.get("definition_id")]
        self.assertEqual(results, [expected])

    def test_fixed_gzip(self):
        self.check_fixture("fixed-gzip", ["gzip-0:1.10-9.el9_0.x86_64.rpm"], 9, "false")

    def test_package_absent(self):
        self.check_fixture("absent-package", [
            "oval24-absent-package-0:99.0-1.el9.x86_64.rpm"
        ], 9, "false")

    def test_affected_comparison(self):
        self.check_fixture("synthetic-affected", ["gzip-0:99.0-1.el9.x86_64.rpm"], 9, "true")

    def test_wrong_major_version(self):
        self.check_fixture("wrong-major-version", ["gzip-0:99.0-1.el8.x86_64.rpm"], 8, "false")

    def test_one_package_alternative_is_enough(self):
        self.check_fixture("one-affected-alternative", [
            "oval24-absent-package-0:99.0-1.el9.x86_64.rpm",
            "gzip-0:99.0-1.el9.x86_64.rpm",
        ], 9, "true")

    def test_no_package_alternative_is_affected(self):
        self.check_fixture("no-affected-alternative", [
            "oval24-absent-package-0:99.0-1.el9.x86_64.rpm",
            "gzip-0:1.10-9.el9_0.x86_64.rpm",
        ], 9, "false")


if __name__ == "__main__":
    unittest.main()
