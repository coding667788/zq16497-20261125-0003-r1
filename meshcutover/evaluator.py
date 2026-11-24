from __future__ import annotations

from .model import as_int


class StateEvaluator:
    """Fast state/path predicates used by audit traces and the planner."""

    def __init__(self, case: dict, path_index: dict[str, list[dict]]):
        self.case = case
        self.path_index = path_index
        self.node_unit: dict[str, int] = {}
        for unit in case["units"]:
            for gid in unit["groups"]:
                for node_id in case["switch_groups"][gid]["nodes"]:
                    self.node_unit[node_id] = unit["index"]

        self.edge_count = len(case["edges"])
        self.node_count = len(case["nodes"])
        self.full_edge_mask = (1 << self.edge_count) - 1
        self.full_node_mask = (1 << self.node_count) - 1
        self.edge_index = case["_edge_index"]
        self.node_index = case["_node_index"]

        self.op_effects = []
        for oid in case["operation_ids"]:
            op = case["operations"][oid]
            emask = 0
            nmask = 0
            dmask = 0
            for eid in op["disable_edges"]:
                emask |= 1 << self.edge_index[eid]
            for nid in op["disable_nodes"]:
                nmask |= 1 << self.node_index[nid]
            for did in op["disable_failure_domains"]:
                dmask |= 1 << case["domain_index"][did]
            self.op_effects.append((emask, nmask, dmask))

        self._op_effect_cache: dict[int, tuple[int, int, int]] = {0: (0, 0, 0)}
        self._edge_active_cache: dict[int, int] = {}
        self._safe_cache: dict[tuple[int, int], bool] = {}

    def version_index(self, node_id: str, group_mask: int) -> int:
        unit = self.node_unit.get(node_id)
        if unit is not None:
            return 1 if (group_mask >> unit) & 1 else 0
        fixed = self.case["nodes"][node_id].get("fixed_version")
        if fixed == "new":
            return 1
        return 0

    def version_name(self, node_id: str, group_mask: int) -> str:
        return "new" if self.version_index(node_id, group_mask) else "old"

    def endpoint_decisions(self, edge: dict, group_mask: int) -> list[dict]:
        result = []
        for endpoint in (edge["from"], edge["to"]):
            version = self.version_name(endpoint, group_mask)
            allow = edge["allow_old"] if version == "old" else edge["allow_new"]
            trust = edge["trust_old"] if version == "old" else edge["trust_new"]
            result.append({
                "node": endpoint,
                "policy_version": version,
                "policy_allows": allow,
                "certificate_trusted": trust,
                "effective": bool(allow and trust),
            })
        return result

    def edge_active_mask(self, group_mask: int) -> int:
        cached = self._edge_active_cache.get(group_mask)
        if cached is not None:
            return cached
        mask = 0
        for i, edge in enumerate(self.case["edges"]):
            if not edge["enabled"]:
                continue
            decisions = self.endpoint_decisions(edge, group_mask)
            if all(item["effective"] for item in decisions):
                mask |= 1 << i
        self._edge_active_cache[group_mask] = mask
        return mask

    def operation_effect_masks(self, operation_mask: int) -> tuple[int, int, int]:
        cached = self._op_effect_cache.get(operation_mask)
        if cached is not None:
            return cached
        lowest = operation_mask & -operation_mask
        bit_index = lowest.bit_length() - 1
        prev_mask = operation_mask ^ lowest
        pe, pn, pd = self.operation_effect_masks(prev_mask)
        oe, on, od = self.op_effects[bit_index]
        result = (pe | oe, pn | on, pd | od)
        self._op_effect_cache[operation_mask] = result
        return result

    def path_fast_ok(self, path: dict, group_mask: int, operation_mask: int,
                     outage_domain_bit: int = 0) -> bool:
        if not path["static_ok"]:
            return False
        active_edges = self.edge_active_mask(group_mask)
        if path["edge_mask"] & (self.full_edge_mask ^ active_edges):
            return False
        op_edges, op_nodes, op_domains = self.operation_effect_masks(operation_mask)
        if path["edge_mask"] & op_edges:
            return False
        if path["node_mask"] & op_nodes:
            return False
        if path["all_domain_mask"] & (outage_domain_bit | op_domains):
            return False
        return True

    def usable_paths(self, req: dict, group_mask: int, operation_mask: int,
                     outage_domain: str | int | None = None) -> list[dict]:
        outage_bit = 0
        if isinstance(outage_domain, str):
            outage_bit = 1 << self.case["domain_index"][outage_domain]
        elif isinstance(outage_domain, int):
            outage_bit = outage_domain
        return [
            path for path in self.path_index[req["id"]]
            if self.path_fast_ok(path, group_mask, operation_mask, outage_bit)
        ]

    def select_paths(self, req: dict, paths: list[dict], k: int | None = None) -> list[dict] | None:
        if k is None:
            k = req["required_paths"]
        if k <= 0:
            return []
        if len(paths) < k:
            return None

        required_targets = set(req.get("replicas", [])) if req.get("require_each_replica") else set()
        distinct_targets = bool(req.get("distinct_replicas"))
        disjoint = bool(req.get("disjoint"))

        # Fast common case: two paths.
        if k == 2:
            for i, first in enumerate(paths):
                for second in paths[i + 1:]:
                    if disjoint and first["internal_domain_mask"] & second["internal_domain_mask"]:
                        continue
                    if distinct_targets and first["target"] == second["target"]:
                        continue
                    chosen_targets = {first["target"], second["target"]}
                    if required_targets and not required_targets.issubset(chosen_targets):
                        continue
                    return [first, second]
            return None

        def recurse(start: int, chosen: list[dict], domain_mask: int,
                    targets: set[str]) -> list[dict] | None:
            if len(chosen) == k:
                if required_targets and not required_targets.issubset(targets):
                    return None
                return chosen[:]
            remaining_slots = k - len(chosen)
            if len(paths) - start < remaining_slots:
                return None
            for j in range(start, len(paths)):
                path = paths[j]
                if disjoint and domain_mask & path["internal_domain_mask"]:
                    continue
                if distinct_targets and path["target"] in targets:
                    continue
                chosen.append(path)
                targets.add(path["target"])
                result = recurse(
                    j + 1, chosen,
                    domain_mask | path["internal_domain_mask"],
                    targets,
                )
                if result is not None:
                    return result
                targets.discard(path["target"])
                chosen.pop()
            return None

        return recurse(0, [], 0, set())

    def request_safe(self, req: dict, group_mask: int, operation_mask: int) -> tuple[bool, str | None]:
        if self.case.get("_path_truncation", {}).get(req["id"]):
            return False, "path_enumeration_truncated"

        usable = self.usable_paths(req, group_mask, operation_mask)
        if req["kind"] == "forbidden":
            if usable:
                return False, "forbidden_pair_authorized"
            return True, None

        if not req.get("enforced", True):
            return True, None

        if len(usable) < req["required_paths"]:
            return False, "insufficient_compliant_paths"

        selected = self.select_paths(req, usable)
        if selected is None:
            if req.get("disjoint"):
                return False, "no_failure_domain_disjoint_selection"
            return False, "replica_affinity_not_satisfied"

        for domain in self.case["domains"]:
            surviving = self.usable_paths(req, group_mask, operation_mask, domain)
            if len(surviving) < req["failure_required_paths"]:
                return False, "domain_outage_path_count_below_requirement"
            if req.get("failure_require_each_replica"):
                targets = {p["target"] for p in surviving}
                if set(req.get("replicas", [])) - targets:
                    return False, "domain_outage_replica_unreachable"
        return True, None

    def is_safe(self, group_mask: int, operation_mask: int = 0) -> bool:
        key = (group_mask, operation_mask)
        cached = self._safe_cache.get(key)
        if cached is not None:
            return cached
        safe = True
        for req in self.case["requests"]:
            ok, _reason = self.request_safe(req, group_mask, operation_mask)
            if not ok:
                safe = False
                break
        self._safe_cache[key] = safe
        return safe
