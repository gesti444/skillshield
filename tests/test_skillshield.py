import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from skillshield.output import render_sarif
from skillshield.scanner import scan


FIXTURE = Path(__file__).parent / "fixtures" / "risky"


class SkillShieldTests(unittest.TestCase):
    def test_detects_risky_skill_patterns(self):
        report = scan(FIXTURE)
        ids = {item["rule_id"] for item in report["findings"]}
        self.assertTrue({"SS001", "SS003", "SS004", "SS005"}.issubset(ids))

    def test_sarif_is_valid_json_with_results(self):
        sarif = json.loads(render_sarif(scan(FIXTURE)))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertGreater(len(sarif["runs"][0]["results"]), 0)

    def test_clean_file_has_no_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "AGENTS.md").write_text("Run unit tests and explain changes.", encoding="utf-8")
            self.assertEqual(scan(directory)["findings"], [])


if __name__ == "__main__":
    unittest.main()
