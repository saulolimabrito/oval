"""Regression tests for platform guards in security advisory definitions.

Run: python3 -m unittest discover -s tests -p 'test_*.py' -v
No network access or third-party Python dependencies are required.
"""
import unittest
import xml.etree.ElementTree as ET

from oval import transform, xml


def expression(products, rl_version=9):
    contents = transform.criterias([], "", rl_version)
    for product, packages in products:
        contents.extend(transform.criterias(packages, product, rl_version))
    for index, content in enumerate(contents, 1):
        content["id"] = str(index)
    return ET.fromstring(xml.criteria(xml.version["Scope"], contents))


def evaluate(element, values):
    if element.tag == "criterion":
        return values.get(element.get("comment"), False)
    children = [evaluate(child, values) for child in element]
    if element.get("operator", "AND") == "AND":
        return all(children)
    return any(children)


class CriteriaTests(unittest.TestCase):
    def setUp(self):
        self.tree = expression([
            ("Rocky Linux 9", ["gzip", "gzip-debuginfo"])
        ])
        self.platform = {
            "Rocky Linux must be installed": True,
            "Rocky Linux 9 must be installed": True,
        }

    def test_correct_platform_does_not_report_patched_or_absent_packages(self):
        self.assertFalse(evaluate(self.tree, self.platform))

    def test_one_affected_package_is_sufficient(self):
        for package in ("gzip", "gzip-debuginfo"):
            with self.subTest(package=package):
                values = dict(self.platform, **{package: True})
                self.assertTrue(evaluate(self.tree, values))

    def test_platform_guards_are_required_even_with_affected_packages(self):
        for guard in self.platform:
            with self.subTest(guard=guard):
                values = dict(self.platform, gzip=True)
                values[guard] = False
                self.assertFalse(evaluate(self.tree, values))

    def test_other_product_packages_cannot_satisfy_current_product(self):
        tree = expression([
            ("Rocky Linux 8", ["el8-package"]),
            ("Rocky Linux 9", ["el9-package"]),
        ])
        values = dict(self.platform, **{"el8-package": True})
        self.assertFalse(evaluate(tree, values))
        values["el9-package"] = True
        self.assertTrue(evaluate(tree, values))

    def test_both_package_conditions_are_required(self):
        # Distinct condition labels allow the version and signature checks to
        # be exercised independently, rather than treating the pair as one.
        contents = transform.criterias([], "", 9)
        contents.extend(transform.criterias(["gzip"], "Rocky Linux 9", 9))
        contents[1]["comment"] = "affected version"
        contents[2]["comment"] = "accepted signature"
        for index, content in enumerate(contents, 1):
            content["id"] = str(index)
        tree = ET.fromstring(xml.criteria(xml.version["Scope"], contents))
        for version in (False, True):
            for signature in (False, True):
                with self.subTest(version=version, signature=signature):
                    values = dict(self.platform, **{
                        "affected version": version,
                        "accepted signature": signature,
                    })
                    self.assertEqual(evaluate(tree, values), version and signature)

    def test_generic_rocky_check_accepts_matching_items(self):
        tests, objects, states = [], [], []
        transform.generate_default(tests, objects, states, "20224582", 9)
        self.assertEqual(tests[0]["check"], "at least one")


if __name__ == "__main__":
    unittest.main()
