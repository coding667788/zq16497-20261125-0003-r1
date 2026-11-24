from __future__ import annotations

import copy
from dataclasses import dataclass, field
from decimal import Decimal
from functools import lru_cache
from itertools import combinations
from typing import Any

from .audit import audit_case_plan
from .evaluator import StateEvaluator
from .model import parse_case
from .paths import build_path_index


@dataclass
class Label:
    cost: Decimal
    batches: int
    sequence: tuple[int, ...]
    operation_mask: int
    parent: "Label | None" = None
    action: dict[str, Any] | None = None

    def objective_key(self) -> tuple[Decimal, int, tuple[int, ...]]:
        return (self.cost, self.batches, self.sequence)


def _mask_sum(bit_count: int, values: list[Decimal | int]) -> list[Any]:
    zero = Decimal(0) if values and isinstance(values[0], Decimal) else 0
    result = [zero] * (1 << bit_count)
    for mask in range(1, 1 << bit_count):
        low = mask & -mask
        i = low.bit_length() - 1
        result[mask] = result[mask ^ low] + values[i]
    return result


def _groups_in_unit_mask(case: dict, unit_mask: int) -> list[str]:
    group_ids = set()
    for i, unit in enumerate(case["units"]):
        if unit_mask & (1 << i):
            group_ids.update(unit["groups"])
    return sorted(group_ids, key=lambda gid: case["group_index"][gid])


def _operations_in_mask(case: dict, op_mask: int) -> list[str]:
    return [oid for i, oid in enumerate(case["operation_ids"]) if op_mask & (1 << i)]


def _canonical_sequences(case: dict, sequence: tuple[int, ...], batches: list[dict]) -> dict:
    canonical_tokens = [f"batch-{ordinal}" if ordinal else "unassigned" for ordinal in sequence]
    actual = []
    for gid_index, ordinal in enumerate(sequence):
        if ordinal == 0:
            actual.append("unassigned")
        else:
            actual.append(batches[ordinal - 1]["id"])
    return {
        "switch_group_order": case["group_ids"],
        "canonical_ordinal_sequence": list(sequence),
        "canonical_batch_id_sequence": [f"batch-{x}" if x else None for x in sequence],
        "normalized_actual_batch_id_sequence": actual,
        "canonical_token_sequence": canonical_tokens,
    }


def _build_plan_from_label(case: dict, best: Label) -> dict:
    actions = []
    current = best
    while current.parent is not None:
        actions.append(current.action)
        current = current.parent
    actions.reverse()
    initial_operation_mask = current.operation_mask

    batches = []
    for i, action in enumerate(actions, start=1):
        window_id = case["windows"][i - 1]["id"] if i - 1 < len(case["windows"]) else None
        batch_id = window_id or f"batch-{i}"
        batches.append({
            "schema": "meshcutover.plan-batch.v1",
            "id": batch_id,
            "window_id": window_id,
            "groups": _groups_in_unit_mask(case, action["add_unit_mask"]),
            "isolation_operations": _operations_in_mask(case, action["add_operation_mask"]),
        })

    return {
        "schema": "meshcutover.plan.v1",
        "initial_isolation_operations": _operations_in_mask(case, initial_operation_mask),
        "batches": batches,
    }


def _diagnose_infeasible(case: dict, evaluator: StateEvaluator) -> dict:
    unit_count = len(case["units"])
    full_unit_mask = (1 << unit_count) - 1
    op_count = len(case["operation_ids"])
    full_op_mask = (1 << op_count) - 1
    capacity = case["batch_capacity"]

    for unit in case["units"]:
        if capacity is not None and unit["migration_units"] > capacity:
            return {
                "reason_code": "migration_unit_exceeds_batch_quota",
                "message": "必须一起切换的合并单元本身超过每批迁移额度",
                "unit_groups": unit["groups"],
                "migration_units": unit["migration_units"],
                "capacity": capacity,
            }

    max_batches = case["max_batches"]
    if max_batches is None and case["windows"]:
        max_batches = len(case["windows"])
    if capacity is not None:
        total_units = sum(u["migration_units"] for u in case["units"])
        lower_bound_batches = (total_units + capacity - 1) // capacity
        if max_batches is not None and lower_bound_batches > max_batches:
            return {
                "reason_code": "batch_window_count_below_capacity_lower_bound",
                "message": "即使按额度最优装箱，所需最少批次也超过给定批次窗口数",
                "minimum_batches_by_capacity": lower_bound_batches,
                "max_batches": max_batches,
                "total_migration_units": total_units,
                "capacity": capacity,
            }

    baseline_reasons = []
    for omask in range(full_op_mask + 1):
        if evaluator.is_safe(0, omask):
            break
    else:
        for req in case["requests"]:
            ok, reason = evaluator.request_safe(req, 0, 0)
            if not ok:
                baseline_reasons.append({"request_id": req["id"], "reason_code": reason})
        return {
            "reason_code": "no_safe_baseline_even_with_all_candidate_operations",
            "message": "切换前状态无法满足约束；即使尝试所有候选硬隔离组合也没有安全基线",
            "baseline_reasons_without_isolation": baseline_reasons,
        }

    final_safe_ops = []
    for omask in range(full_op_mask + 1):
        if evaluator.is_safe(full_unit_mask, omask):
            final_safe_ops.append(omask)
    if not final_safe_ops:
        final_reasons = []
        for req in case["requests"]:
            ok, reason = evaluator.request_safe(req, full_unit_mask, 0)
            if not ok:
                final_reasons.append({"request_id": req["id"], "reason_code": reason})
        return {
            "reason_code": "final_policy_state_unsafe",
            "message": "全部切到新策略后的最终状态不满足验收约束，候选硬隔离组合也无法修复",
            "final_state_reasons_without_isolation": final_reasons,
        }

    return {
        "reason_code": "no_safe_batched_transition",
        "message": "存在安全基线和安全最终态，但额度、成组约束或中间批次检查点使任何分批序列都无法通过",
    }


def _bit_indices(mask: int) -> list[int]:
    indices = []
    while mask:
        low = mask & -mask
        indices.append(low.bit_length() - 1)
        mask ^= low
    return indices


def _iter_batch_masks(remaining_mask: int, capacity: int | None,
                      unit_size_mask: list[int]):
    """Yield nonempty subsets of remaining_mask, large/capacity-filling first."""
    indices = _bit_indices(remaining_mask)
    max_size = len(indices)
    if capacity is not None:
        # Every unit has integer migration_units >= 1, so a batch cannot
        # contain more than capacity units. Weight feasibility is filtered
        # below because weights may be > 1.
        max_size = min(max_size, capacity)
    for size in range(max_size, 0, -1):
        for combo in combinations(indices, size):
            mask = 0
            for i in combo:
                mask |= 1 << i
            if capacity is None or unit_size_mask[mask] <= capacity:
                yield mask


def _exists_at_most_batches(case: dict, evaluator: StateEvaluator,
                            unit_size_mask: list[int], max_slots: int) -> bool:
    unit_count = len(case["units"])
    full = (1 << unit_count) - 1
    capacity = case["batch_capacity"]

    @lru_cache(maxsize=None)
    def can(mask: int, slots_left: int) -> bool:
        if mask == full:
            return True
        if slots_left == 0:
            return False
        remaining = full ^ mask
        remaining_size = unit_size_mask[remaining]
        if capacity is not None:
            lower_batches = (remaining_size + capacity - 1) // capacity
            if lower_batches > slots_left:
                return False
        if remaining.bit_count() < 1:
            return True

        for add_mask in _iter_batch_masks(remaining, capacity, unit_size_mask):
            new_mask = mask | add_mask
            if not evaluator.is_safe(new_mask, 0):
                continue
            if can(new_mask, slots_left - 1):
                return True
        return False

    return can(0, max_slots)


def _completion_exists(case: dict, evaluator: StateEvaluator,
                       unit_size_mask: list[int], batch_count: int,
                       fixed_labels: tuple[int, ...]) -> bool:
    unit_count = len(case["units"])
    group_count = len(case["group_ids"])
    full = (1 << unit_count) - 1
    capacity = case["batch_capacity"]

    # Convert labels on sorted original groups to unit requirement masks.
    required_masks = [0] * (batch_count + 1)
    for group_index, label in enumerate(fixed_labels):
        if label:
            gid = case["group_ids"][group_index]
            unit_index = case["group_to_unit"][gid]
            required_masks[label] |= 1 << unit_index
    fixed_mask = 0
    seen_required = 0
    for mask in required_masks[1:]:
        if mask & seen_required:
            # A joint switch unit was constrained to two different labels.
            return False
        seen_required |= mask
        fixed_mask |= mask

    @lru_cache(maxsize=None)
    def dfs(label: int, remaining: int) -> bool:
        if label > batch_count:
            return remaining == 0

        required = required_masks[label]
        if required & ~remaining:
            return False
        if capacity is not None and unit_size_mask[required] > capacity:
            return False

        if label == batch_count:
            add_mask = remaining
            if add_mask == 0:
                return False
            if capacity is not None and unit_size_mask[add_mask] > capacity:
                return False
            return evaluator.is_safe(full, 0)

        future_fixed = 0
        for later in range(label + 1, batch_count + 1):
            future_fixed |= required_masks[later]
        optional = remaining & ~fixed_mask
        # Sanity: future fixed units must still be present.
        if future_fixed & ~remaining:
            return False

        optional_subset = optional
        while True:
            add_mask = required | optional_subset
            if add_mask and (capacity is None or unit_size_mask[add_mask] <= capacity):
                after = (full ^ remaining) | add_mask
                remaining_after = remaining ^ add_mask
                size_after = unit_size_mask[remaining_after]
                prune_ok = capacity is None or (
                    (size_after + capacity - 1) // capacity <= batch_count - label
                )
                if prune_ok and evaluator.is_safe(after, 0):
                    if dfs(label + 1, remaining_after):
                        return True
            if optional_subset == 0:
                break
            optional_subset = (optional_subset - 1) & optional
        return False

    return dfs(1, full)


def _fast_no_operation_plan(case: dict, evaluator: StateEvaluator,
                           unit_cost_mask: list[Any]) -> dict | None:
    unit_count = len(case["units"])
    full = (1 << unit_count) - 1
    unit_sizes = [u["migration_units"] for u in case["units"]]
    unit_size_mask = _mask_sum(unit_count, unit_sizes)
    capacity = case["batch_capacity"]

    if unit_count == 0:
        if evaluator.is_safe(0, 0):
            return {
                "schema": "meshcutover.plan.v1",
                "case_id": case["case_id"],
                "status": "optimal",
                "satisfiable": True,
                "solver": "empty_plan",
                "objective": {
                    "weighted_downtime": Decimal(0),
                    "batch_count": 0,
                    "switch_group_order": case["group_ids"],
                    "canonical_ordinal_sequence": [],
                    "canonical_batch_id_sequence": [],
                    "normalized_actual_batch_id_sequence": [],
                    "canonical_token_sequence": [],
                },
                "plan": {"schema": "meshcutover.plan.v1",
                         "initial_isolation_operations": [], "batches": []},
            }
        diagnostic = _diagnose_infeasible(case, evaluator)
        return {
            "schema": "meshcutover.plan.v1",
            "case_id": case["case_id"],
            "status": "infeasible",
            "satisfiable": False,
            "objective": None,
            "plan": None,
            **diagnostic,
        }

    max_batches = case["max_batches"]
    if max_batches is None and case["windows"]:
        max_batches = len(case["windows"])
    if max_batches is None:
        max_batches = max(1, unit_count)

    if any(size > capacity for size in unit_sizes if capacity is not None):
        diagnostic = _diagnose_infeasible(case, evaluator)
        return {
            "schema": "meshcutover.plan.v1",
            "case_id": case["case_id"],
            "status": "infeasible",
            "satisfiable": False,
            "objective": None,
            "plan": None,
            **diagnostic,
        }

    if not evaluator.is_safe(0, 0):
        diagnostic = _diagnose_infeasible(case, evaluator)
        return {
            "schema": "meshcutover.plan.v1",
            "case_id": case["case_id"],
            "status": "infeasible",
            "satisfiable": False,
            "objective": None,
            "plan": None,
            **diagnostic,
        }

    total_size = sum(unit_sizes)
    lower_bound = 1
    if capacity is not None:
        lower_bound = max(1, (total_size + capacity - 1) // capacity)
    lower_bound = min(lower_bound, max(1, unit_count))

    minimum_batches = None
    for batch_count in range(lower_bound, max_batches + 1):
        if _exists_at_most_batches(case, evaluator, unit_size_mask, batch_count):
            minimum_batches = batch_count
            break
    if minimum_batches is None:
        diagnostic = _diagnose_infeasible(case, evaluator)
        return {
            "schema": "meshcutover.plan.v1",
            "case_id": case["case_id"],
            "status": "infeasible",
            "satisfiable": False,
            "objective": None,
            "plan": None,
            **diagnostic,
        }

    group_count = len(case["group_ids"])
    fixed = [0] * group_count
    for group_index in range(group_count):
        gid = case["group_ids"][group_index]
        unit_index = case["group_to_unit"][gid]
        forced_label = None
        for earlier_index in range(group_index):
            earlier_gid = case["group_ids"][earlier_index]
            if fixed[earlier_index] and case["group_to_unit"][earlier_gid] == unit_index:
                forced_label = fixed[earlier_index]
                break

        if forced_label is not None:
            fixed[group_index] = forced_label
            if not _completion_exists(case, evaluator, unit_size_mask,
                                      minimum_batches, tuple(fixed)):
                return None
            continue

        chosen = None
        for label in range(1, minimum_batches + 1):
            fixed[group_index] = label
            if _completion_exists(case, evaluator, unit_size_mask,
                                  minimum_batches, tuple(fixed)):
                chosen = label
                break
        if chosen is None:
            return None
        fixed[group_index] = chosen
    sequence = tuple(fixed)

    batches = []
    for label in range(1, minimum_batches + 1):
        groups = [gid for i, gid in enumerate(case["group_ids"]) if sequence[i] == label]
        window_id = case["windows"][label - 1]["id"] if label - 1 < len(case["windows"]) else None
        batches.append({
            "schema": "meshcutover.plan-batch.v1",
            "id": window_id or f"batch-{label}",
            "window_id": window_id,
            "groups": groups,
            "isolation_operations": [],
        })
    plan_document = {
        "schema": "meshcutover.plan.v1",
        "initial_isolation_operations": [],
        "batches": batches,
    }
    objective = {
        "weighted_downtime": unit_cost_mask[full],
        "batch_count": minimum_batches,
        **_canonical_sequences(case, sequence, batches),
    }
    return {
        "schema": "meshcutover.plan.v1",
        "case_id": case["case_id"],
        "status": "optimal",
        "satisfiable": True,
        "solver": "lex_greedy_mask_feasibility_v1",
        "objective": objective,
        "plan": plan_document,
    }


def plan_case(case: dict, include_relaxations: bool = True,
              include_audit: bool = True) -> dict:
    if len(case["group_ids"]) > 16:
        from .errors import CaseError
        raise CaseError("plan supports at most 16 switch groups", "$.switch_groups")

    path_index = build_path_index(case)
    evaluator = StateEvaluator(case, path_index)

    unit_count = len(case["units"])
    op_count = len(case["operation_ids"])
    full_unit_mask = (1 << unit_count) - 1
    full_op_mask = (1 << op_count) - 1

    unit_sizes = [u["migration_units"] for u in case["units"]]
    unit_costs = [u["weighted_downtime"] for u in case["units"]]
    op_costs = [case["operations"][oid]["weighted_downtime"] for oid in case["operation_ids"]]
    unit_size_mask = _mask_sum(unit_count, unit_sizes)
    unit_cost_mask = _mask_sum(unit_count, unit_costs)
    op_cost_mask = _mask_sum(op_count, op_costs)

    capacity = case["batch_capacity"]
    max_batches = case["max_batches"]
    if max_batches is None and case["windows"]:
        max_batches = len(case["windows"])

    group_count = len(case["group_ids"])
    zero_sequence = tuple(0 for _ in range(group_count))

    # Fast exact path when no isolation operation is needed. If all candidate
    # operations have strictly positive cost, a feasible no-operation plan
    # already reaches the mandatory group-cost lower bound and no operation
    # plan can win on weighted downtime. With zero-cost operations, fall back
    # to the operation-aware DP because they may improve batch count/tie-break.
    fast_report = _fast_no_operation_plan(case, evaluator, unit_cost_mask)
    all_operations_positive = all(
        case["operations"][oid]["weighted_downtime"] > 0
        for oid in case["operation_ids"]
    )
    cost_lower_bound_is_unique = op_count == 0 or all_operations_positive
    if fast_report is not None:
        if not fast_report["satisfiable"] and op_count == 0:
            if include_relaxations:
                fast_report["relaxed_resolves"] = _relaxed_resolves(case)
            return fast_report
        if fast_report["satisfiable"] and cost_lower_bound_is_unique:
            if include_audit:
                audit_report = audit_case_plan(case, fast_report["plan"], trace_level="compact")
                fast_report["audit_status"] = audit_report["status"]
                fast_report["audit_first_failure"] = audit_report["first_failure"]
                fast_report["audit"] = audit_report
            if include_relaxations:
                fast_report["relaxed_resolves"] = _relaxed_resolves(case)
            return fast_report

    # All safe baseline isolation subsets are roots. A selected operation may
    # also be activated at a later batch through a transition action.
    by_unit_mask: dict[int, dict[int, Label]] = {}
    root_bucket: dict[int, Label] = {}
    for omask in range(full_op_mask + 1):
        if evaluator.is_safe(0, omask):
            root_bucket[omask] = Label(
                cost=op_cost_mask[omask],
                batches=0,
                sequence=zero_sequence,
                operation_mask=omask,
            )
    if root_bucket:
        by_unit_mask[0] = root_bucket

    for umask in range(full_unit_mask + 1):
        bucket = by_unit_mask.get(umask)
        if not bucket:
            continue
        remaining = full_unit_mask ^ umask
        add_unit = remaining
        while add_unit:
            new_umask = umask | add_unit
            capacity_ok = capacity is None or unit_size_mask[add_unit] <= capacity
            if capacity_ok:
                target_bucket = by_unit_mask.setdefault(new_umask, {})
                for omask, label in bucket.items():
                    if max_batches is not None and label.batches + 1 > max_batches:
                        continue
                    remaining_ops = full_op_mask ^ omask
                    add_ops = remaining_ops
                    while True:
                        new_omask = omask | add_ops
                        if evaluator.is_safe(new_umask, new_omask):
                            new_batches = label.batches + 1
                            sequence = list(label.sequence)
                            for unit_index, unit in enumerate(case["units"]):
                                if add_unit & (1 << unit_index):
                                    for gid in unit["groups"]:
                                        sequence[case["group_index"][gid]] = new_batches
                            candidate = Label(
                                cost=label.cost + unit_cost_mask[add_unit] + op_cost_mask[add_ops],
                                batches=new_batches,
                                sequence=tuple(sequence),
                                operation_mask=new_omask,
                                parent=label,
                                action={
                                    "add_unit_mask": add_unit,
                                    "add_operation_mask": add_ops,
                                },
                            )
                            existing = target_bucket.get(new_omask)
                            if existing is None or candidate.objective_key() < existing.objective_key():
                                target_bucket[new_omask] = candidate
                        if add_ops == 0:
                            break
                        add_ops = (add_ops - 1) & remaining_ops
            add_unit = (add_unit - 1) & remaining

    final_bucket = by_unit_mask.get(full_unit_mask, {})
    report: dict[str, Any]
    if not final_bucket:
        diagnostic = _diagnose_infeasible(case, evaluator)
        report = {
            "schema": "meshcutover.plan.v1",
            "case_id": case["case_id"],
            "status": "infeasible",
            "satisfiable": False,
            "objective": None,
            "plan": None,
            **diagnostic,
        }
    else:
        best = min(final_bucket.values(), key=lambda label: label.objective_key())
        plan_document = _build_plan_from_label(case, best)
        sequences = _canonical_sequences(case, best.sequence, plan_document["batches"])
        report = {
            "schema": "meshcutover.plan.v1",
            "case_id": case["case_id"],
            "status": "optimal",
            "satisfiable": True,
            "solver": "exact_mask_dynamic_programming",
            "objective": {
                "weighted_downtime": best.cost,
                "batch_count": best.batches,
                **sequences,
            },
            "plan": plan_document,
        }
        if include_audit:
            audit_report = audit_case_plan(case, plan_document, trace_level="compact")
            report["audit_status"] = audit_report["status"]
            report["audit_first_failure"] = audit_report["first_failure"]
            report["audit"] = audit_report

    if include_relaxations:
        report["relaxed_resolves"] = _relaxed_resolves(case)
    return report


def _relax_document_for_business(document: dict, business_id: str) -> tuple[dict, dict]:
    relaxed = copy.deepcopy(document)
    relaxation = document.get("relaxation", {}) if isinstance(document.get("relaxation"), dict) else {}
    rel_type = relaxation.get("type", "single_best_effort_path")
    by = int(relaxation.get("by", 1))
    minimum = int(relaxation.get("minimum", 1))

    target = None
    for service in relaxed.get("services", []):
        if service.get("id") == business_id:
            target = service
            break
    if target is None:
        raise ValueError(f"unknown protected business {business_id}")

    change = {"business_id": business_id, "type": rel_type}
    if rel_type == "single_best_effort_path":
        old_required = int(target.get("required_paths", target.get("path_count",
                          relaxed.get("path_policy", {}).get("required_paths", 2))))
        old_failure = int(target.get("failure_required_paths",
                          relaxed.get("path_policy", {}).get("failure_required_paths", old_required)))
        target["required_paths"] = 1
        target["path_count"] = 1
        target["failure_required_paths"] = 0
        target["require_each_replica"] = False
        target["distinct_replicas"] = False
        target["failure_require_each_replica"] = False
        change.update({
            "required_paths": {"from": old_required, "to": 1},
            "failure_required_paths": {"from": old_failure, "to": 0},
            "require_each_replica": False,
            "applied": old_required != 1 or old_failure != 0,
        })
    elif rel_type == "waive_disjoint_failure_domains":
        target["disjoint_failure_domains"] = False
        change["disjoint_failure_domains"] = False
        change["applied"] = True
    elif rel_type == "reduce_failure_required_paths":
        old = int(target.get("failure_required_paths",
                             relaxed.get("path_policy", {}).get("failure_required_paths", 2)))
        new = max(0, old - by)
        target["failure_required_paths"] = new
        change.update({"field": "failure_required_paths", "from": old, "to": new,
                       "applied": new != old})
    else:
        old = int(target.get("required_paths", target.get("path_count",
                  relaxed.get("path_policy", {}).get("required_paths", 2))))
        new = max(minimum, old - by)
        target["required_paths"] = new
        target["path_count"] = new
        # A one-path target cannot additionally require one path to every
        # declared replica; those affinity constraints are part of the same
        # two-path redundancy guarantee being relaxed once.
        target["require_each_replica"] = False
        target["distinct_replicas"] = False
        change.update({"field": "required_paths", "from": old, "to": new,
                       "require_each_replica": False})
        also_failure = relaxation.get("also_reduce_failure_paths", True) is not False
        if also_failure:
            old_failure = int(target.get("failure_required_paths",
                              relaxed.get("path_policy", {}).get("failure_required_paths", old)))
            new_failure = max(0, old_failure - by)
            target["failure_required_paths"] = new_failure
            target["failure_require_each_replica"] = False
            change["failure_required_paths"] = {"from": old_failure, "to": new_failure}
        change["applied"] = new != old
    return relaxed, change


def _relaxed_resolves(case: dict) -> list[dict]:
    results = []
    for business_id in case["protected_businesses"]:
        relaxed_document, change = _relax_document_for_business(case["raw"], business_id)
        relaxed_case = parse_case(relaxed_document)
        result = plan_case(relaxed_case, include_relaxations=False, include_audit=False)
        results.append({
            "business_id": business_id,
            "one_shot_relaxation": change,
            "status": result["status"],
            "satisfiable": result["satisfiable"],
            "objective": result.get("objective"),
            "plan": result.get("plan"),
            "reason_code": result.get("reason_code"),
            "message": result.get("message"),
        })
    return results
