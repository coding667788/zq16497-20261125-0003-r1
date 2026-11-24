import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "meshcutover", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )

    def test_audit_good_plan_exit_zero_and_utf8_json(self):
        proc = self.run_cli(
            "audit",
            "fixtures/transition_case.json",
            "fixtures/transition_good_plan.json",
            "--trace-level", "compact",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["schema"], "meshcutover.audit.v1")
        self.assertTrue(all("state" in c for c in report["checkpoints"]))

    def test_audit_bad_plan_exit_one(self):
        proc = self.run_cli(
            "audit",
            "fixtures/transition_case.json",
            "fixtures/transition_one_side_bad_plan.json",
            "--trace-level", "compact",
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["first_failure"]["batch_index"], 1)

    def test_plan_exit_zero(self):
        proc = self.run_cli(
            "plan", "fixtures/transition_case.json", "--no-audit", "--no-relax", "--compact"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "optimal")
        self.assertEqual(report["objective"]["batch_count"], 1)

    def test_invalid_json_returns_json_input_error_exit_two(self):
        bad = ROOT / ".runtime-tmp" / "bad.json"
        bad.parent.mkdir(exist_ok=True)
        bad.write_text("{not json", encoding="utf-8")
        proc = self.run_cli("plan", str(bad))
        self.assertEqual(proc.returncode, 2)
        report = json.loads(proc.stdout)
        self.assertEqual(report["status"], "input_error")


if __name__ == "__main__":
    unittest.main()
