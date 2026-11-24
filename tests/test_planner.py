import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from meshcutover.model import parse_case, load_json_document
from meshcutover.planner import plan_case


def parsed_fixture(name: str) -> dict:
    return parse_case(load_json_document(ROOT / "fixtures" / name))


class PlannerFixtureTests(unittest.TestCase):
    def test_transition_exact_one_batch_plan(self):
        case = parsed_fixture("transition_case.json")
        result = plan_case(case, include_relaxations=False, include_audit=False)
        self.assertEqual(result["status"], "optimal")
        self.assertEqual(result["objective"]["weighted_downtime"], 30)
        self.assertEqual(result["objective"]["batch_count"], 1)
        self.assertEqual(result["objective"]["canonical_ordinal_sequence"], [1, 1])
        self.assertEqual([b["groups"] for b in result["plan"]["batches"]],
                         [["g-replicas", "g-source"]])

    def test_capacity_conflict_is_infeasible_then_relaxed(self):
        case = parsed_fixture("strict_infeasible_relaxed_case.json")
        result = plan_case(case, include_relaxations=True, include_audit=False)
        self.assertEqual(result["status"], "infeasible")
        self.assertIn(result["reason_code"], {
            "no_safe_batched_transition",
            "batch_window_count_below_capacity_lower_bound",
        })
        self.assertEqual(len(result["relaxed_resolves"]), 1)
        relaxed = result["relaxed_resolves"][0]
        self.assertEqual(relaxed["business_id"], "checkout")
        self.assertEqual(relaxed["status"], "optimal")
        self.assertEqual(relaxed["objective"]["batch_count"], 2)
        # Sorted groups are g-replicas then g-source. Lex-smallest two-batch
        # canonical sequence migrates g-replicas first.
        self.assertEqual(relaxed["objective"]["canonical_ordinal_sequence"], [1, 2])
        self.assertEqual(
            [b["groups"] for b in relaxed["plan"]["batches"]],
            [["g-replicas"], ["g-source"]],
        )

    def test_forbidden_pair_selects_cheapest_hard_isolation(self):
        case = parsed_fixture("forbidden_isolation_case.json")
        result = plan_case(case, include_relaxations=False, include_audit=False)
        self.assertEqual(result["status"], "optimal")
        self.assertEqual(result["objective"]["weighted_downtime"], 12)
        self.assertEqual(result["plan"]["initial_isolation_operations"], ["iso-edge-cheap"])
        self.assertNotIn("iso-domain-pricey", result["plan"]["initial_isolation_operations"])

    def test_embedded_audit_passes_for_returned_plan(self):
        case = parsed_fixture("forbidden_isolation_case.json")
        result = plan_case(case, include_relaxations=False, include_audit=True)
        self.assertEqual(result["audit"]["status"], "pass")
        self.assertIsNone(result["audit_first_failure"])


if __name__ == "__main__":
    unittest.main()
