import itertools
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from meshcutover.evaluator import StateEvaluator
from meshcutover.model import parse_case
from meshcutover.paths import build_path_index
from meshcutover.planner import plan_case


def graph_parity_document() -> dict:
    nodes = []
    domain_by_node = {
        "a": "dA",
        "b": "dB",
        "sec1": "dC",
        "net1": "dD",
        "sec2": "dE",
        "net2": "dF",
    }
    for node_id in ["s", "a", "b", "t", "sec1", "net1", "sec2", "net2"]:
        node = {"id": node_id, "switch_group": f"g-{node_id}"}
        if node_id in domain_by_node:
            node["failure_domain"] = domain_by_node[node_id]
        if node_id.startswith("sec"):
            node["kind"] = "inspection"
            node["ops_group"] = "secops"
        elif node_id.startswith("net"):
            node["kind"] = "inspection"
            node["ops_group"] = "netops"
        nodes.append(node)

    def edge(eid, source, target, inspections, scope="test", old=True, new=True):
        return {
            "id": eid,
            "from": source,
            "to": target,
            "region": "r1",
            "peer_cert": "cert1",
            "cert_zone": "tz1",
            "scope": scope,
            "inspection_nodes": inspections,
            "allowed": {"old": old, "new": new},
        }

    return {
        "schema": "meshcutover.case.v1",
        "case_id": "parity-small-graph",
        "regions": ["r1"],
        "certificates": {"cert1": {"trust_zone": "tz1"}},
        "failure_domains": ["dA", "dB", "dC", "dD", "dE", "dF"],
        "inspection_groups": ["secops", "netops"],
        "nodes": nodes,
        "edges": [
            edge("e_st", "s", "t", ["sec1", "net1"]),
            edge("e_sa", "s", "a", ["sec1"]),
            edge("e_at", "a", "t", ["net1"], old=True, new=False),
            edge("e_sb", "s", "b", ["sec2"], old=False, new=True),
            edge("e_bt", "b", "t", ["net2"]),
            edge("e_ab", "a", "b", []),
            edge("e_ba", "b", "a", [], scope="wrong-scope"),
        ],
        "services": [{
            "id": "svc",
            "source": "s",
            "targets": ["t"],
            "scope": "test",
            "required_paths": 2,
            "failure_required_paths": 0,
            "distinct_replicas": False,
            "require_each_replica": False,
            "disjoint_failure_domains": True,
        }],
    }


def reference_structural_paths() -> set[tuple[str, ...]]:
    # Independent enumeration: all permutations of the two internal vertices.
    edge_endpoints = {
        ("s", "t"), ("s", "a"), ("a", "t"), ("s", "b"), ("b", "t"),
        ("a", "b"), ("b", "a"),
    }
    result = set()
    internals = ["a", "b"]
    for count in range(len(internals) + 1):
        for middle in itertools.permutations(internals, count):
            node_tuple = ("s",) + middle + ("t",)
            pairs = list(zip(node_tuple, node_tuple[1:]))
            if all(pair in edge_endpoints for pair in pairs):
                result.add(node_tuple)
    return result


class FullPathStateParityTests(unittest.TestCase):
    def setUp(self):
        self.document = graph_parity_document()
        self.case = parse_case(self.document)
        self.index = build_path_index(self.case)
        self.evaluator = StateEvaluator(self.case, self.index)
        self.req = self.case["requests"][0]
        self.edge_by_endpoints = {(e["from"], e["to"]): e for e in self.case["edges"]}

    def _edge_ids_for_nodes(self, node_tuple):
        edge_ids = []
        for u, v in zip(node_tuple, node_tuple[1:]):
            edge = self.edge_by_endpoints.get((u, v))
            if edge is None:
                return None
            edge_ids.append(edge["id"])
        return edge_ids

    def test_engine_enumerates_every_reference_simple_path(self):
        engine_paths = {tuple(p["nodes"]) for p in self.index["svc"]}
        self.assertEqual(engine_paths, reference_structural_paths())
        self.assertEqual(len(engine_paths), 5)

    def _reference_static_ok(self, node_tuple, edge_ids):
        for eid in edge_ids:
            edge = self.case["edge_by_id"][eid]
            if not edge["enabled"]:
                return False
            cert = self.case["certificates"][edge["peer_cert"]]
            if cert["trust_zone"] != edge["cert_zone"]:
                return False
            if not any(scope in edge["scopes"] for scope in self.req["scopes"]):
                return False

        visit_groups = []
        for eid in edge_ids:
            for nid in self.case["edge_by_id"][eid]["inspection_nodes"]:
                visit_groups.append(self.case["nodes"][nid]["ops_group"])
        step = 0
        for group in visit_groups:
            wanted = self.req["inspection"][step]["ops_group"]
            if group == wanted:
                step += 1
                if step == 2:
                    break
        return step == 2 and visit_groups.count("secops") >= 1 and visit_groups.count("netops") >= 1

    def _reference_version(self, node_id, mask):
        gid = self.case["nodes"][node_id]["switch_group"]
        unit = self.case["group_to_unit"][gid]
        return "new" if mask & (1 << unit) else "old"

    def _reference_domains(self, node_tuple, edge_ids):
        resource_nodes = set(node_tuple)
        internal_nodes = list(node_tuple[1:-1])
        for eid in edge_ids:
            insp = self.case["edge_by_id"][eid]["inspection_nodes"]
            resource_nodes.update(insp)
            for nid in insp:
                if nid not in (node_tuple[0], node_tuple[-1]):
                    internal_nodes.append(nid)
        all_domains = {
            self.case["nodes"][nid]["failure_domain"]
            for nid in resource_nodes
            if self.case["nodes"][nid].get("failure_domain")
        }
        internal_domains = {
            self.case["nodes"][nid]["failure_domain"]
            for nid in dict.fromkeys(internal_nodes)
            if self.case["nodes"][nid].get("failure_domain")
        }
        return all_domains, internal_domains

    def _reference_usable(self, mask, outage):
        usable = []
        for node_tuple in reference_structural_paths():
            edge_ids = self._edge_ids_for_nodes(node_tuple)
            if edge_ids is None or not self._reference_static_ok(node_tuple, edge_ids):
                continue
            active = True
            for eid in edge_ids:
                edge = self.case["edge_by_id"][eid]
                for endpoint in (edge["from"], edge["to"]):
                    version = self._reference_version(endpoint, mask)
                    allows = edge["allow_old"] if version == "old" else edge["allow_new"]
                    trusts = edge["trust_old"] if version == "old" else edge["trust_new"]
                    if not (allows and trusts):
                        active = False
            if not active:
                continue
            all_domains, internal_domains = self._reference_domains(node_tuple, edge_ids)
            if outage is not None and outage in all_domains:
                continue
            usable.append((node_tuple, internal_domains))
        return usable

    def test_all_policy_states_and_domain_outages_match_bruteforce(self):
        state_count = 1 << len(self.case["units"])
        outages = [None] + self.case["domains"]
        comparisons = 0
        for mask in range(state_count):
            for outage in outages:
                reference = self._reference_usable(mask, outage)
                engine = self.evaluator.usable_paths(self.req, mask, 0, outage)
                self.assertEqual(
                    len(engine), len(reference),
                    msg=f"mask={mask:08b} outage={outage}",
                )
                reference_disjoint_pair = any(
                    first_domains.isdisjoint(second_domains)
                    for i, (_, first_domains) in enumerate(reference)
                    for _, second_domains in reference[i + 1:]
                )
                engine_selection = self.evaluator.select_paths(self.req, engine)
                self.assertEqual(
                    engine_selection is not None,
                    reference_disjoint_pair,
                    msg=f"mask={mask:08b} outage={outage}",
                )
                comparisons += 1
        # 2^8 policy states times (normal + six domains).
        self.assertEqual(comparisons, 256 * 7)


def batch_oracle_document(capacity: int) -> dict:
    nodes = [
        {"id": "src"}, {"id": "r1"}, {"id": "r2"},
        {"id": "sec1", "kind": "inspection", "ops_group": "secops", "failure_domain": "d1"},
        {"id": "net1", "kind": "inspection", "ops_group": "netops", "failure_domain": "d1"},
        {"id": "sec2", "kind": "inspection", "ops_group": "secops", "failure_domain": "d2"},
        {"id": "net2", "kind": "inspection", "ops_group": "netops", "failure_domain": "d2"},
        {"id": "d0"}, {"id": "d1dummy"}, {"id": "d2dummy"},
    ]
    return {
        "schema": "meshcutover.case.v1",
        "case_id": "batch-oracle",
        "certificates": {"c": {"trust_zone": "z"}},
        "inspection_groups": ["secops", "netops"],
        "failure_domains": ["d1", "d2"],
        "nodes": nodes,
        "edges": [
            {"id": "p1", "from": "src", "to": "r1", "region": "r1",
             "peer_cert": "c", "cert_zone": "z",
             "scope": "x", "inspection_nodes": ["sec1", "net1"], "allowed": True},
            {"id": "p2", "from": "src", "to": "r2", "region": "r1",
             "peer_cert": "c", "cert_zone": "z",
             "scope": "x", "inspection_nodes": ["sec2", "net2"], "allowed": True},
        ],
        "services": [{
            "id": "biz", "source": "src", "replicas": ["r1", "r2"], "scope": "x",
            "required_paths": 2, "failure_required_paths": 1,
        }],
        "switch_groups": [
            {"id": "g0", "nodes": ["d0"], "migration_units": 1, "weighted_downtime": 2},
            {"id": "g1", "nodes": ["d1dummy"], "migration_units": 1, "weighted_downtime": 3},
            {"id": "g2", "nodes": ["d2dummy"], "migration_units": 1, "weighted_downtime": 4},
        ],
        "batch": {"capacity": capacity},
    }


class ExhaustiveBatchOracleTests(unittest.TestCase):
    def test_planner_matches_all_group_label_assignments(self):
        for capacity in (1, 2, 3):
            with self.subTest(capacity=capacity):
                case = parse_case(batch_oracle_document(capacity))
                index = build_path_index(case)
                evaluator = StateEvaluator(case, index)
                result = plan_case(case, include_relaxations=False, include_audit=False)
                self.assertEqual(result["status"], "optimal")

                best = None
                group_count = len(case["group_ids"])
                for batch_count in range(1, group_count + 1):
                    for labels in itertools.product(range(1, batch_count + 1), repeat=group_count):
                        if set(labels) != set(range(1, batch_count + 1)):
                            continue
                        batches = [[] for _ in range(batch_count)]
                        for group_index, label in enumerate(labels):
                            batches[label - 1].append(case["group_ids"][group_index])
                        if any(len(batch) > capacity for batch in batches):
                            continue
                        safe = True
                        mask = 0
                        for label in range(1, batch_count + 1):
                            for group_index, batch_label in enumerate(labels):
                                if batch_label == label:
                                    gid = case["group_ids"][group_index]
                                    mask |= 1 << case["group_to_unit"][gid]
                            if not evaluator.is_safe(mask, 0):
                                safe = False
                                break
                        if safe:
                            key = (batch_count, labels)
                            if best is None or key < best:
                                best = key
                self.assertIsNotNone(best)
                self.assertEqual(result["objective"]["batch_count"], best[0])
                self.assertEqual(result["objective"]["canonical_ordinal_sequence"], list(best[1]))
                self.assertEqual(result["objective"]["weighted_downtime"], 9)


if __name__ == "__main__":
    unittest.main()
