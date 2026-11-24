from __future__ import annotations

from typing import Any

from .errors import PlanDocumentError
from .model import as_int, norm_id


def _extract_plan_document(document: Any) -> dict:
    if isinstance(document, dict) and isinstance(document.get("plan"), dict) and "batches" in document["plan"]:
        return document["plan"]
    if isinstance(document, dict) and "batches" in document:
        return document
    raise PlanDocumentError("PLAN must be an object containing a batches list", "$")


def parse_plan_document(document: Any, case: dict) -> dict:
    raw_plan = _extract_plan_document(document)
    raw_batches = raw_plan.get("batches")
    if not isinstance(raw_batches, list):
        raise PlanDocumentError("plan.batches must be a list", "$.plan.batches")

    known_groups = set(case["group_ids"])
    known_ops = set(case["operation_ids"])

    initial_ops_raw = raw_plan.get(
        "initial_isolation_operations",
        raw_plan.get("pre_isolation_operations", []),
    )
    if not isinstance(initial_ops_raw, list):
        raise PlanDocumentError("initial_isolation_operations must be a list", "$.plan.initial_isolation_operations")
    initial_ops = [norm_id(x, "$.plan.initial_isolation_operations") for x in initial_ops_raw]
    for oid in initial_ops:
        if oid not in known_ops:
            raise PlanDocumentError("unknown isolation operation", "$.plan.initial_isolation_operations")
    if len(set(initial_ops)) != len(initial_ops):
        raise PlanDocumentError("initial isolation operations must be unique", "$.plan.initial_isolation_operations")

    scheduled_groups: set[str] = set()
    used_ops = set(initial_ops)
    used_windows: set[str] = set()
    normalized_batches = []
    cumulative_op_mask = 0
    for oid in initial_ops:
        cumulative_op_mask |= 1 << case["operation_index"][oid]

    if case["max_batches"] is not None and len(raw_batches) > case["max_batches"]:
        raise PlanDocumentError(
            f"plan uses {len(raw_batches)} batches, max_batches={case['max_batches']}",
            "$.plan.batches",
        )
    if case["windows"] and len(raw_batches) > len(case["windows"]):
        raise PlanDocumentError("plan uses more batches than declared batch windows", "$.plan.batches")

    window_order = {w["id"]: i for i, w in enumerate(case["windows"])}
    last_window_order = -1

    for i, raw_batch in enumerate(raw_batches):
        path = f"$.plan.batches[{i}]"
        if not isinstance(raw_batch, dict):
            raise PlanDocumentError("batch must be an object", path)
        batch_id = norm_id(raw_batch.get("id", f"batch-{i + 1}"), f"{path}.id")
        group_values = raw_batch.get("groups", raw_batch.get("switch_groups", []))
        if not isinstance(group_values, list):
            raise PlanDocumentError("batch.groups must be a list", f"{path}.groups")
        group_ids = [norm_id(g, f"{path}.groups") for g in group_values]
        if not group_ids:
            raise PlanDocumentError("a migration batch must contain at least one switch group", f"{path}.groups")
        for gid in group_ids:
            if gid not in known_groups:
                raise PlanDocumentError(f"unknown switch group {gid}", f"{path}.groups")
            if gid in scheduled_groups:
                raise PlanDocumentError(f"switch group {gid} is scheduled more than once", f"{path}.groups")
        batch_group_set = set(group_ids)

        # Joint switch units must occur in exactly one same batch.
        unit_masks_here = set()
        for gid in group_ids:
            unit_index = case["group_to_unit"][gid]
            unit = case["units"][unit_index]
            missing = set(unit["groups"]) - batch_group_set
            if missing:
                raise PlanDocumentError(
                    "joint switch groups must be in the same batch; missing " + ", ".join(sorted(missing)),
                    f"{path}.groups",
                )
            unit_masks_here.add(unit_index)

        for gid in group_ids:
            scheduled_groups.add(gid)

        size = sum(case["switch_groups"][gid]["migration_units"] for gid in group_ids)
        window_id = raw_batch.get("window_id", raw_batch.get("window"))
        if window_id is not None:
            window_id = norm_id(window_id, f"{path}.window_id")
            if window_id not in window_order:
                raise PlanDocumentError("unknown batch window_id", f"{path}.window_id")
            this_order = window_order[window_id]
            if this_order <= last_window_order:
                raise PlanDocumentError("batch windows must be used in strictly increasing declared order",
                                        f"{path}.window_id")
            if window_id in used_windows:
                raise PlanDocumentError("batch window reused", f"{path}.window_id")
            used_windows.add(window_id)
            last_window_order = this_order
            window = case["windows"][this_order]
            capacity = raw_batch.get("capacity", window["capacity"])
        else:
            if i < len(case["windows"]):
                window = case["windows"][i]
                window_id = window["id"]
                capacity = raw_batch.get("capacity", window["capacity"])
            else:
                window_id = None
                capacity = raw_batch.get("capacity", case["batch_capacity"])
            if window_id is not None:
                if window_order[window_id] <= last_window_order:
                    raise PlanDocumentError("batch windows must be in increasing declared order", path)
                used_windows.add(window_id)
                last_window_order = window_order[window_id]

        capacity = as_int(capacity, f"{path}.capacity", case["batch_capacity"], 1)
        if capacity is not None and size > capacity:
            raise PlanDocumentError(
                f"batch migration units {size} exceed quota {capacity}",
                f"{path}.groups",
            )

        op_values = raw_batch.get("isolation_operations", raw_batch.get("operations", []))
        if not isinstance(op_values, list):
            raise PlanDocumentError("batch isolation_operations must be a list",
                                    f"{path}.isolation_operations")
        op_ids = [norm_id(op, f"{path}.isolation_operations") for op in op_values]
        activate_mask = 0
        for oid in op_ids:
            if oid not in known_ops:
                raise PlanDocumentError("unknown isolation operation", f"{path}.isolation_operations")
            if oid in used_ops:
                raise PlanDocumentError("isolation operation was already activated",
                                        f"{path}.isolation_operations")
            used_ops.add(oid)
            activate_mask |= 1 << case["operation_index"][oid]
        cumulative_op_mask |= activate_mask

        group_mask = 0
        for unit_index in unit_masks_here:
            group_mask |= 1 << unit_index

        normalized_batches.append({
            "index": i + 1,
            "id": batch_id,
            "window_id": window_id,
            "group_ids": sorted(group_ids),
            "unit_mask": group_mask,
            "cumulative_group_mask": 0,  # filled below
            "activated_operation_ids": op_ids,
            "activate_operation_mask": activate_mask,
            "cumulative_operation_mask": cumulative_op_mask,
            "migration_units": size,
            "capacity": capacity,
        })

    missing_groups = known_groups - scheduled_groups
    if missing_groups:
        raise PlanDocumentError(
            "plan does not schedule switch groups: " + ", ".join(sorted(missing_groups)),
            "$.plan.batches",
        )

    cumulative_group_mask = 0
    for batch in normalized_batches:
        cumulative_group_mask |= batch["unit_mask"]
        batch["cumulative_group_mask"] = cumulative_group_mask

    return {
        "initial_operation_ids": initial_ops,
        "initial_operation_mask": sum(1 << case["operation_index"][oid] for oid in initial_ops),
        "batches": normalized_batches,
        "raw": raw_plan,
    }
