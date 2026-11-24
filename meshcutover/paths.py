from __future__ import annotations

from typing import Any

from .model import as_int


def _add_unique(items: list[str], value: str | None) -> None:
    if value and value not in items:
        items.append(value)


def build_visits(case: dict, node_ids: list[str], edge_refs: list[tuple[str, bool]]) -> list[dict]:
    """Return inspection visits in traversal order.

    Edge-declared inspection nodes are emitted first in edge order. A graph
    vertex whose kind is inspection is emitted after the edge leading to it.
    Consecutive duplicate references are collapsed.
    """
    visits: list[dict] = []

    def append(node_id: str, via_edge: str | None, source_kind: str) -> None:
        if visits and visits[-1]["node"] == node_id:
            return
        node = case["nodes"][node_id]
        visits.append({
            "node": node_id,
            "ops_group": node.get("ops_group"),
            "via_edge": via_edge,
            "source": source_kind,
        })

    source = case["nodes"][node_ids[0]]
    if source.get("kind") == "inspection" or source.get("ops_group"):
        append(node_ids[0], None, "graph_vertex")

    for i, (edge_id, reversed_direction) in enumerate(edge_refs):
        edge = case["edge_by_id"][edge_id]
        annotated = list(edge["inspection_nodes"])
        if reversed_direction:
            annotated.reverse()
        for node_id in annotated:
            append(node_id, edge_id, "edge_annotation")
        destination = node_ids[i + 1]
        node = case["nodes"][destination]
        if node.get("kind") == "inspection" or node.get("ops_group"):
            append(destination, edge_id, "graph_vertex")
    return visits


def _inspection_check(req: dict, visits: list[dict]) -> dict:
    steps = req["inspection"]
    step_index = 0
    witnesses: list[dict] = []
    for visit in visits:
        if step_index >= len(steps):
            break
        step = steps[step_index]
        matched = False
        if step["kind"] == "node":
            matched = visit["node"] == step["node"]
        else:
            matched = visit.get("ops_group") == step["ops_group"]
        if matched:
            witness = dict(visit)
            witness["step"] = step_index + 1
            witness["required"] = step
            witnesses.append(witness)
            step_index += 1

    ok = step_index == len(steps)
    groups = [w.get("ops_group") for w in witnesses]
    distinct_groups = len(groups) == 2 and groups[0] != groups[1]
    ok = ok and distinct_groups
    return {
        "check": "inspection_order_and_ops_groups",
        "ok": ok,
        "reason_code": None if ok else "inspection_order_not_satisfied",
        "required_steps": steps,
        "visits": visits,
        "witnesses": witnesses,
        "distinct_ops_groups": distinct_groups,
    }


def evaluate_path_static(case: dict, req: dict, node_ids: list[str],
                         edge_refs: list[tuple[str, bool]]) -> dict:
    checks: list[dict] = []
    reason_codes: list[str] = []

    def fail(code: str) -> None:
        if code not in reason_codes:
            reason_codes.append(code)

    for edge_id, _reversed in edge_refs:
        edge = case["edge_by_id"][edge_id]

        enabled_ok = edge["enabled"]
        checks.append({
            "check": "edge_candidate_enabled",
            "edge_id": edge_id,
            "ok": enabled_ok,
            "reason_code": None if enabled_ok else "edge_disabled",
        })
        if not enabled_ok:
            fail("edge_disabled")

        region_ok = not req["allowed_regions"] or edge["region"] in req["allowed_regions"]
        checks.append({
            "check": "region_allowed",
            "edge_id": edge_id,
            "ok": region_ok,
            "actual_region": edge["region"],
            "allowed_regions": req["allowed_regions"],
            "reason_code": None if region_ok else "region_not_allowed",
        })
        if not region_ok:
            fail("region_not_allowed")

        cert = case["certificates"][edge["peer_cert"]]
        zone_ok = cert["trust_zone"] == edge["cert_zone"]
        checks.append({
            "check": "certificate_trust_zone_match",
            "edge_id": edge_id,
            "ok": zone_ok,
            "peer_cert": edge["peer_cert"],
            "certificate_trust_zone": cert["trust_zone"],
            "edge_cert_zone": edge["cert_zone"],
            "reason_code": None if zone_ok else "cert_zone_mismatch",
        })
        if not zone_ok:
            fail("cert_zone_mismatch")

        scope_ok = (
            not req["scopes"]
            or "*" in edge["scopes"]
            or "*" in req["scopes"]
            or any(scope in edge["scopes"] for scope in req["scopes"])
        )
        checks.append({
            "check": "service_scope_match",
            "edge_id": edge_id,
            "ok": scope_ok,
            "request_scopes": req["scopes"],
            "edge_scopes": edge["scopes"],
            "reason_code": None if scope_ok else "scope_mismatch",
        })
        if not scope_ok:
            fail("scope_mismatch")

    visits = build_visits(case, node_ids, edge_refs)
    inspection_check = _inspection_check(req, visits)
    checks.append(inspection_check)
    if not inspection_check["ok"]:
        fail("inspection_order_not_satisfied")

    internal_nodes: list[str] = []
    for node_id in node_ids[1:-1]:
        _add_unique(internal_nodes, node_id)
    source = node_ids[0]
    target = node_ids[-1]
    for visit in visits:
        node_id = visit["node"]
        if node_id != source and node_id != target:
            _add_unique(internal_nodes, node_id)

    resource_nodes: list[str] = []
    for node_id in node_ids:
        _add_unique(resource_nodes, node_id)
    for visit in visits:
        _add_unique(resource_nodes, visit["node"])

    domain_index = case["domain_index"]
    internal_domains = sorted({
        case["nodes"][nid]["failure_domain"]
        for nid in internal_nodes
        if case["nodes"][nid].get("failure_domain") is not None
    })
    internal_mask = 0
    for domain in internal_domains:
        internal_mask |= 1 << domain_index[domain]

    all_domains = sorted({
        case["nodes"][nid]["failure_domain"]
        for nid in resource_nodes
        if case["nodes"][nid].get("failure_domain") is not None
    })
    all_mask = 0
    for domain in all_domains:
        all_mask |= 1 << domain_index[domain]

    edge_mask = 0
    edge_index = case.get("_edge_index", {})
    for edge_id, _ in edge_refs:
        edge_mask |= 1 << edge_index[edge_id]

    node_mask = 0
    node_index = case.get("_node_index", {})
    for node_id in resource_nodes:
        node_mask |= 1 << node_index[node_id]

    static_ok = not reason_codes
    return {
        "request_id": req["id"],
        "kind": req["kind"],
        "source": source,
        "target": target,
        "nodes": list(node_ids),
        "edges": [edge_id for edge_id, _ in edge_refs],
        "edge_refs": list(edge_refs),
        "visits": visits,
        "internal_nodes": internal_nodes,
        "internal_domains": internal_domains,
        "internal_domain_mask": internal_mask,
        "all_domain_mask": all_mask,
        "edge_mask": edge_mask,
        "node_mask": node_mask,
        "static_ok": static_ok,
        "reason_codes": reason_codes,
        "checks": checks,
    }


def enumerate_request_paths(case: dict, req: dict, max_paths: int) -> tuple[list[dict], bool]:
    target_set = set(req["targets"])
    found: list[tuple[tuple[str, ...], tuple[tuple[str, bool], ...]]] = []
    truncated = False

    def dfs(current: str, nodes: list[str], edge_refs: list[tuple[str, bool]], visited: set[str]) -> None:
        nonlocal truncated
        if truncated:
            return
        if current in target_set and len(nodes) >= 2:
            found.append((tuple(nodes), tuple(edge_refs)))
            if len(found) >= max_paths:
                truncated = True
            return
        for nxt, edge_id, reversed_direction in case["adjacency"].get(current, []):
            if nxt in visited:
                continue
            visited.add(nxt)
            nodes.append(nxt)
            edge_refs.append((edge_id, reversed_direction))
            dfs(nxt, nodes, edge_refs, visited)
            edge_refs.pop()
            nodes.pop()
            visited.remove(nxt)
            if truncated:
                return

    dfs(req["source"], [req["source"]], [], {req["source"]})

    # Deterministic ordering independent of DFS tie quirks.
    found.sort(key=lambda item: (item[1], item[0]))
    paths = []
    for i, (node_tuple, edge_tuple) in enumerate(found):
        path = evaluate_path_static(case, req, list(node_tuple), list(edge_tuple))
        path["path_id"] = f"{req['id']}:path-{i + 1:04d}"
        paths.append(path)
    return paths, truncated


def build_path_index(case: dict) -> dict[str, list[dict]]:
    limits = case.get("limits", {}) if isinstance(case.get("limits"), dict) else {}
    max_paths = as_int(limits.get("max_paths_per_request"), "$.limits.max_paths_per_request", 100000, 1)
    case["_edge_index"] = {edge["id"]: i for i, edge in enumerate(case["edges"])}
    case["_node_index"] = {node_id: i for i, node_id in enumerate(case["nodes"])}

    index: dict[str, list[dict]] = {}
    truncation: dict[str, bool] = {}
    for req in case["requests"]:
        paths, truncated = enumerate_request_paths(case, req, max_paths)
        index[req["id"]] = paths
        truncation[req["id"]] = truncated
    case["_path_truncation"] = truncation
    return index
