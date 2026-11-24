import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from meshcutover.audit import audit_case_plan
from meshcutover.model import parse_case, load_json_document
from meshcutover.planner import plan_case


def fixture_case(name: str) -> dict:
    return parse_case(load_json_document(ROOT / "fixtures" / name))


def fixture_doc(name: str) -> dict:
    return load_json_document(ROOT / "fixtures" / name)


class FixtureAuditTests(unittest.TestCase):
    def test_transition_good_plan_is_safe_before_and_after(self):
        case = fixture_case("transition_case.json")
        plan = fixture_doc("transition_good_plan.json")
        report = audit_case_plan(case, plan, trace_level="compact")
        self.assertEqual(report["status"], "pass", report.get("first_failure"))
        self.assertIsNone(report["first_failure"])
        self.assertEqual([c["checkpoint_index"] for c in report["checkpoints"]], [0, 1])
        # Before cutover: old-r1, old-r2 and stable-r1 are usable.
        before = report["checkpoints"][0]["requests"][0]["normal"]
        self.assertEqual(before["usable_path_count"], 3)
        # After homogeneous new policy: new-r1, new-r2 and stable-r1 are usable.
        after = report["checkpoints"][1]["requests"][0]["normal"]
        self.assertEqual(after["usable_path_count"], 3)

    def test_only_one_side_loses_redundancy(self):
        case = fixture_case("transition_case.json")
        plan = fixture_doc("transition_one_side_bad_plan.json")
        report = audit_case_plan(case, plan, trace_level="compact")
        self.assertEqual(report["status"], "fail")
        failure = report["first_failure"]
        self.assertEqual(failure["batch_index"], 1)
        self.assertEqual(failure["batch_id"], "b1-only-source-side")
        self.assertEqual(failure["reason_code"], "insufficient_compliant_paths")
        normal = report["checkpoints"][1]["requests"][0]["normal"]
        self.assertEqual(normal["usable_path_count"], 1)
        self.assertEqual(normal["usable_path_ids"], ["checkout:path-0005"])
        # Cross-version conjunction rejects all old-only and new-only edges.
        edge_states = report["checkpoints"][1]["state"]["edge_states"]
        by_id = {e["edge_id"]: e for e in edge_states}
        self.assertFalse(by_id["old-r1"]["policy_conjunction_active"])
        self.assertFalse(by_id["new-r1"]["policy_conjunction_active"])
        self.assertTrue(by_id["stable-r1"]["policy_conjunction_active"])

    def test_two_compliant_paths_share_physical_failure_domain(self):
        case = fixture_case("shared_failure_domain_case.json")
        plan = fixture_doc("shared_failure_domain_plan.json")
        report = audit_case_plan(case, plan, trace_level="compact")
        self.assertEqual(report["status"], "fail")
        self.assertEqual(
            report["first_failure"]["reason_code"],
            "no_failure_domain_disjoint_selection",
        )
        request = report["checkpoints"][0]["requests"][0]
        self.assertEqual(request["normal"]["usable_path_count"], 2)
        domains = request["normal"]["selected_internal_failure_domains"]
        self.assertEqual(domains, [])
        outage = request["domain_outage_checks"][0]
        self.assertEqual(outage["domain"], "fd-shared-rack")
        self.assertEqual(outage["usable_path_count"], 0)
        self.assertFalse(outage["ok"])

    def test_audit_json_is_utf8_serializable(self):
        case = fixture_case("shared_failure_domain_case.json")
        plan = fixture_doc("shared_failure_domain_plan.json")
        report = audit_case_plan(case, plan, trace_level="none")
        encoded = json.dumps(report, ensure_ascii=False).encode("utf-8")
        self.assertIn("fd-shared-rack", encoded.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
