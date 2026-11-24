from __future__ import annotations

from typing import Any

from .evaluator import StateEvaluator
from .paths import build_path_index
from .plan_doc import parse_plan_document


def _operation_ids_for_mask(case: dict, mask: int) -> list[str]:
    result = []
    for i, oid in enumerate(case["operation_ids"]):
        if mask & (1 << i):
            result.append(oid)
    return result


def _trace_path(case: dict, evaluator: StateEvaluator, path: dict,
                group_mask: int, operation_mask: int, trace_level: str,
                outage_domain_bit: int = 0) -> dict:
    usable = evaluator.path_fast_ok(path, group_mask, operation_mask, outage_domain_bit)
    op_edges, op_nodes, op_domains = evaluator.operation_effect_masks(operation_mask)
    active_edges = evaluator.edge_active_mask(group_mask)

    reason_codes = list(path["reason_codes"])
    dynamic_checks: list[dict] = []

    if path["static_ok"]:
        for edge_id in path["edges"]:
            edge_index = case["_edge_index"][edge_id]
            edge = case["edge_by_id"][edge_id]
            policy_active = bool(active_edges & (1 << edge_index))
            isolated = bool(op_edges & (1 << edge_index))
            decisions = evaluator.endpoint_decisions(edge, group_mask)
            check = {
                "check": "endpoint_version_conjunction",
                "edge_id": edge_id,
                "ok": policy_active,
                "endpoint_decisions": decisions,
                "conjunction": policy_active,
                "hard_isolated": isolated,
                "reason_code": None if policy_active else "policy_version_conjunction_denied",
            }
            dynamic_checks.append(check)
            if not policy_active and "policy_version_conjunction_denied" not in reason_codes:
                reason_codes.append("policy_version_conjunction_denied")
            if isolated and "hard_isolated_edge" not in reason_codes:
                reason_codes.append("hard_isolated_edge")

        if path["edge_mask"] & op_edges:
            dynamic_checks.append({"check": "isolation_edge_mask", "ok": False,
                                   "reason_code": "hard_isolated_edge"})
        if path["node_mask"] & op_nodes:
            dynamic_checks.append({"check": "isolation_node_mask", "ok": False,
                                   "reason_code": "hard_isolated_node"})
            reason_codes.append("hard_isolated_node")
        if path["all_domain_mask"] & op_domains:
            dynamic_checks.append({"check": "hard_isolated_failure_domain", "ok": False,
                                   "reason_code": "hard_isolated_failure_domain"})
            reason_codes.append("hard_isolated_failure_domain")
        if outage_domain_bit and path["all_domain_mask"] & outage_domain_bit:
            dynamic_checks.append({"check": "declared_failure_domain_offline", "ok": False,
                                   "reason_code": "failure_domain_offline"})
            reason_codes.append("failure_domain_offline")

    # De-duplicate while preserving order.
    seen = set()
    reason_codes = [x for x in reason_codes if not (x in seen or seen.add(x))]

    trace = {
        "path_id": path["path_id"],
        "usable": usable,
        "nodes": path["nodes"],
        "edges": path["edges"],
        "target": path["target"],
        "internal_nodes": path["internal_nodes"],
        "internal_failure_domains": path["internal_domains"],
        "reason_codes": reason_codes,
    }
    if trace_level == "full":
        trace["inspection_visits"] = path["visits"]
        trace["static_checks"] = path["checks"]
        trace["dynamic_checks"] = dynamic_checks
    elif trace_level == "compact":
        trace["failed_static_checks"] = [c for c in path["checks"] if not c.get("ok", True)]
        trace["failed_dynamic_checks"] = [c for c in dynamic_checks if not c.get("ok", True)]
    return trace


def _target_counts(paths: list[dict], targets: list[str]) -> dict[str, int]:
    counts = {target: 0 for target in targets}
    for path in paths:
        counts[path["target"]] = counts.get(path["target"], 0) + 1
    return counts


def _assess_request(case: dict, evaluator: StateEvaluator, req: dict,
                    group_mask: int, operation_mask: int, trace_level: str,
                    request_index: int) -> dict:
    all_paths = evaluator.path_index[req["id"]]
    usable = evaluator.usable_paths(req, group_mask, operation_mask)
    selected = evaluator.select_paths(req, usable) if req["kind"] == "business" else None
    selected_ids = [p["path_id"] for p in selected] if selected else []
    selected_domain_sets = [p["internal_domains"] for p in selected] if selected else []

    path_traces = []
    if trace_level != "none":
        for path in all_paths:
            path_traces.append(_trace_path(case, evaluator, path, group_mask,
                                           operation_mask, trace_level))

    violations: list[dict] = []
    normal: dict[str, Any] = {
        "candidate_path_count": len(all_paths),
        "usable_path_count": len(usable),
        "usable_path_ids": [p["path_id"] for p in usable],
        "selected_path_ids": selected_ids,
        "selected_internal_failure_domains": selected_domain_sets,
        "target_counts": _target_counts(usable, req["targets"]),
        "required_paths": req["required_paths"],
    }

    if case.get("_path_truncation", {}).get(req["id"]):
        violations.append({
            "code": "path_enumeration_truncated",
            "message": "路径数量达到枚举上限，不能给出安全证明",
            "phase": "normal",
            "domain": None,
        })

    if req["kind"] == "forbidden":
        normal["authorized"] = bool(usable)
        if usable:
            violations.append({
                "code": "forbidden_pair_authorized",
                "message": "禁止服务对在当前状态存在合规授权路径",
                "phase": "normal",
                "domain": None,
                "violating_path_ids": [p["path_id"] for p in usable],
            })
    else:
        if len(usable) < req["required_paths"]:
            violations.append({
                "code": "insufficient_compliant_paths",
                "message": f"合规路径数 {len(usable)} 小于要求 {req['required_paths']}",
                "phase": "normal",
                "domain": None,
            })
        if req.get("require_each_replica"):
            missing = [t for t in req.get("replicas", []) if normal["target_counts"].get(t, 0) == 0]
            if missing:
                violations.append({
                    "code": "replica_unreachable",
                    "message": "有业务副本缺少合规路径: " + ", ".join(missing),
                    "phase": "normal",
                    "domain": None,
                    "missing_replicas": missing,
                })
        if req["required_paths"] > 0 and selected is None:
            code = ("no_failure_domain_disjoint_selection" if req.get("disjoint")
                    else "replica_affinity_not_satisfied")
            message = ("找不到内部物理故障域互不重叠的所需路径组合"
                        if req.get("disjoint") else "找不到满足副本亲和/去重要求的路径组合")
            violations.append({
                "code": code,
                "message": message,
                "phase": "normal",
                "domain": None,
                "usable_path_failure_domains": [
                    {"path_id": p["path_id"], "domains": p["internal_domains"]}
                    for p in usable
                ],
            })

    domain_reports = []
    for domain in case["domains"]:
        surviving = evaluator.usable_paths(req, group_mask, operation_mask, domain)
        surviving_ids = {p["path_id"] for p in surviving}
        removed_ids = [p["path_id"] for p in usable if p["path_id"] not in surviving_ids]
        target_counts = _target_counts(surviving, req["targets"])
        required = req["failure_required_paths"]
        ok = len(surviving) >= required
        missing_replicas = []
        if req.get("failure_require_each_replica"):
            missing_replicas = [t for t in req.get("replicas", []) if target_counts.get(t, 0) == 0]
            ok = ok and not missing_replicas
        report = {
            "domain": domain,
            "usable_path_count": len(surviving),
            "required_paths": required,
            "ok": ok,
            "surviving_path_ids": [p["path_id"] for p in surviving],
            "removed_path_ids": removed_ids,
            "target_counts": target_counts,
        }
        domain_reports.append(report)
        if not ok and req["kind"] != "forbidden":
            violations.append({
                "code": "domain_outage_path_count_below_requirement",
                "message": f"故障域 {domain} 离线后路径数 {len(surviving)} 小于要求 {required}",
                "phase": "domain_outage",
                "domain": domain,
                "surviving_path_count": len(surviving),
                "required_paths": required,
            })
        if missing_replicas:
            violations.append({
                "code": "domain_outage_replica_unreachable",
                "message": f"故障域 {domain} 离线后副本不可达: " + ", ".join(missing_replicas),
                "phase": "domain_outage",
                "domain": domain,
                "missing_replicas": missing_replicas,
            })

    for j, violation in enumerate(violations):
        violation["trace_ref"] = f"checkpoints.current.requests[{request_index}].violations[{j}]"

    return {
        "request_id": req["id"],
        "kind": req["kind"],
        "critical": req["critical"],
        "enforced": req.get("enforced", True),
        "expect_authorized": req["expect_authorized"],
        "scope": req["scopes"],
        "ok": not violations,
        "violations": violations,
        "normal": normal,
        "domain_outage_checks": domain_reports,
        "path_traces": path_traces,
    }


def _edge_states(case: dict, evaluator: StateEvaluator, group_mask: int,
                 operation_mask: int) -> list[dict]:
    active_mask = evaluator.edge_active_mask(group_mask)
    op_edges, _op_nodes, _op_domains = evaluator.operation_effect_masks(operation_mask)
    states = []
    for i, edge in enumerate(case["edges"]):
        policy_active = bool(active_mask & (1 << i))
        isolated = bool(op_edges & (1 << i))
        states.append({
            "edge_id": edge["id"],
            "from": edge["from"],
            "to": edge["to"],
            "policy_conjunction_active": policy_active,
            "hard_isolated": isolated,
            "authorized_state": policy_active and not isolated,
            "endpoint_decisions": evaluator.endpoint_decisions(edge, group_mask),
        })
    return states


def audit_checkpoint(case: dict, evaluator: StateEvaluator, index: int,
                     phase: str, batch_id: str | None, group_mask: int,
                     operation_mask: int, trace_level: str = "full") -> dict:
    group_versions = {}
    for gid in case["group_ids"]:
        unit_index = case["group_to_unit"][gid]
        group_versions[gid] = "new" if group_mask & (1 << unit_index) else "old"

    node_versions = {
        node_id: evaluator.version_name(node_id, group_mask)
        for node_id in sorted(case["nodes"])
    }
    reports = []
    for i, req in enumerate(case["requests"]):
        reports.append(_assess_request(case, evaluator, req, group_mask,
                                       operation_mask, trace_level, i))

    violations = []
    for request_report in reports:
        for violation in request_report["violations"]:
            violation = dict(violation)
            violation["request_id"] = request_report["request_id"]
            violation["request_kind"] = request_report["kind"]
            violations.append(violation)

    return {
        "checkpoint_index": index,
        "phase": phase,
        "batch_id": batch_id,
        "ok": not violations,
        "state": {
            "switch_group_policy_versions": group_versions,
            "node_policy_versions": node_versions,
            "active_isolation_operations": _operation_ids_for_mask(case, operation_mask),
            "group_mask": group_mask,
            "operation_mask": operation_mask,
            "edge_states": _edge_states(case, evaluator, group_mask, operation_mask),
        },
        "requests": reports,
        "violations": violations,
    }


def audit_case_plan(case: dict, plan_document: dict, trace_level: str = "full") -> dict:
    path_index = build_path_index(case)
    evaluator = StateEvaluator(case, path_index)
    plan = parse_plan_document(plan_document, case)

    checkpoints = []
    baseline = audit_checkpoint(
        case, evaluator, 0, "before_cutover", None,
        0, plan["initial_operation_mask"], trace_level,
    )
    checkpoints.append(baseline)

    first_failure = None
    if not baseline["ok"]:
        violation = baseline["violations"][0]
        first_failure = {
            "checkpoint_index": 0,
            "batch_index": 0,
            "batch_id": None,
            "phase": "before_cutover",
            "reason_code": violation["code"],
            "request_id": violation.get("request_id"),
            "domain": violation.get("domain"),
            "message": violation.get("message"),
            "trace_ref": "checkpoints[0]",
        }
    else:
        for batch in plan["batches"]:
            checkpoint = audit_checkpoint(
                case, evaluator, batch["index"], "after_batch", batch["id"],
                batch["cumulative_group_mask"],
                batch["cumulative_operation_mask"], trace_level,
            )
            checkpoints.append(checkpoint)
            if not checkpoint["ok"]:
                violation = checkpoint["violations"][0]
                first_failure = {
                    "checkpoint_index": len(checkpoints) - 1,
                    "batch_index": batch["index"],
                    "batch_id": batch["id"],
                    "phase": "after_batch",
                    "reason_code": violation["code"],
                    "request_id": violation.get("request_id"),
                    "domain": violation.get("domain"),
                    "message": violation.get("message"),
                    "trace_ref": f"checkpoints[{len(checkpoints) - 1}]",
                }
                break

    status = "pass" if first_failure is None else "fail"
    return {
        "schema": "meshcutover.audit.v1",
        "case_id": case["case_id"],
        "status": status,
        "first_failure": first_failure,
        "checked_batches": len(checkpoints) - 1,
        "total_batches_in_plan": len(plan["batches"]),
        "stopped_at_first_failure": first_failure is not None,
        "checkpoints": checkpoints,
        "normalized_plan": _public_plan(case, plan),
    }


def _public_plan(case: dict, plan: dict) -> dict:
    return {
        "initial_isolation_operations": plan["initial_operation_ids"],
        "batches": [
            {
                "id": b["id"],
                "window_id": b["window_id"],
                "groups": b["group_ids"],
                "isolation_operations": b["activated_operation_ids"],
                "migration_units": b["migration_units"],
                "capacity": b["capacity"],
            }
            for b in plan["batches"]
        ],
    }
