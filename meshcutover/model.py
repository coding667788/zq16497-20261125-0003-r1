from __future__ import annotations

import json
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .errors import CaseError


def norm_id(value: Any, path: str = "$.id") -> str:
    if not isinstance(value, str):
        raise CaseError("id must be a string", path)
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized:
        raise CaseError("id must not be empty", path)
    return normalized


def load_json_document(source: str | Path) -> Any:
    text = Path(source).read_text(encoding="utf-8-sig")
    try:
        return json.loads(text, parse_float=Decimal)
    except json.JSONDecodeError as exc:
        raise CaseError(
            f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}",
            "$",
        ) from exc


def load_json_text(text: str) -> Any:
    try:
        return json.loads(text, parse_float=Decimal)
    except json.JSONDecodeError as exc:
        raise CaseError(
            f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}",
            "$",
        ) from exc


def as_decimal(value: Any, path: str, default: Decimal | None = None,
               nonnegative: bool = True) -> Decimal | None:
    if value is None:
        return default
    if isinstance(value, bool):
        raise CaseError("expected a number, got boolean", path)
    try:
        if isinstance(value, Decimal):
            result = value
        elif isinstance(value, int):
            result = Decimal(value)
        elif isinstance(value, str):
            result = Decimal(value.strip())
        else:
            raise InvalidOperation
    except (InvalidOperation, ValueError) as exc:
        raise CaseError("expected a nonnegative decimal number", path) from exc
    if nonnegative and result < 0:
        raise CaseError("value must be nonnegative", path)
    return result


def as_int(value: Any, path: str, default: int | None = None,
           minimum: int | None = None) -> int | None:
    result = as_decimal(value, path, Decimal(default) if default is not None else None)
    if result is None:
        return None
    if result != result.to_integral_value():
        raise CaseError("expected an integer", path)
    integer = int(result)
    if minimum is not None and integer < minimum:
        raise CaseError(f"expected an integer >= {minimum}", path)
    return integer


def string_list(value: Any, path: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [norm_id(value, path)]
    if not isinstance(value, list):
        raise CaseError("expected a string or list of strings", path)
    return [norm_id(item, f"{path}[{i}]") for i, item in enumerate(value)]


def _effect(value: Any, path: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, Decimal)) and not isinstance(value, bool):
        if value == 1:
            return True
        if value == 0:
            return False
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"allow", "allowed", "permit", "yes", "true", "1"}:
            return True
        if lowered in {"deny", "denied", "reject", "no", "false", "0"}:
            return False
    raise CaseError("policy effect must be allow/deny or boolean", path)


def _resolve_cost(item: dict, path: str) -> Decimal:
    explicit = as_decimal(item.get("weighted_downtime", item.get("weighted_downtime_seconds")),
                          f"{path}.weighted_downtime")
    if explicit is not None:
        return explicit
    weight = as_decimal(item.get("weight"), f"{path}.weight", Decimal(1))
    downtime = as_decimal(item.get("downtime_seconds", item.get("downtime")),
                          f"{path}.downtime_seconds", Decimal(0))
    return weight * downtime


def _parse_scopes(item: dict, path: str) -> list[str]:
    raw = item.get("scopes", item.get("scope", item.get("service_scope", item.get("service_scopes"))))
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    raise CaseError("scope/scopes must be a string or list of strings", path)


def _make_inspection_resolver(nodes: dict[str, dict], default_raw: Any, base_path: str):
    def resolve(raw: Any, path: str) -> list[dict]:
        if raw is None:
            raw = default_raw
        if raw is None:
            raise CaseError("an ordered two-node inspection sequence is required", path)
        if not isinstance(raw, list) or len(raw) != 2:
            raise CaseError("inspection sequence must contain exactly two entries", path)

        steps: list[dict] = []
        groups: list[str] = []
        for i, entry in enumerate(raw):
            step_path = f"{path}[{i}]"
            if isinstance(entry, str):
                text = norm_id(entry, step_path)
                if text in nodes:
                    entry = {"node": text}
                else:
                    entry = {"ops_group": text}
            if not isinstance(entry, dict):
                raise CaseError("inspection step must be a node id, ops group, or object", step_path)
            node_id = entry.get("node", entry.get("node_id"))
            group = entry.get("ops_group", entry.get("group"))
            if node_id is not None:
                node_id = norm_id(node_id, f"{step_path}.node")
                if node_id not in nodes:
                    raise CaseError("inspection node does not exist", f"{step_path}.node")
                group = nodes[node_id].get("ops_group")
                if not group:
                    raise CaseError("inspection node has no ops_group", f"{step_path}.node")
                steps.append({"kind": "node", "node": node_id, "ops_group": group})
            elif group is not None:
                group = norm_id(group, f"{step_path}.ops_group")
                steps.append({"kind": "ops_group", "ops_group": group})
            else:
                raise CaseError("inspection step requires node or ops_group", step_path)
            groups.append(steps[-1]["ops_group"])

        if groups[0] == groups[1]:
            raise CaseError("the two inspection nodes must belong to different ops groups", path)
        return steps

    return resolve


def parse_case(document: Any) -> dict:
    if not isinstance(document, dict):
        raise CaseError("case document must be a JSON object")

    schema = document.get("schema", "meshcutover.case.v1")
    if not isinstance(schema, str) or not schema.startswith("meshcutover.case."):
        raise CaseError("unsupported schema; expected meshcutover.case.v1", "$.schema")

    case_id = norm_id(document.get("case_id", document.get("id", "unnamed-case")), "$.case_id")

    # Declared physical failure domains ------------------------------------------------
    raw_domains = document.get("failure_domains", document.get("domains", []))
    if not isinstance(raw_domains, list):
        raise CaseError("failure_domains must be a list", "$.failure_domains")
    domain_ids: set[str] = set()
    for i, item in enumerate(raw_domains):
        if isinstance(item, str):
            domain_id = norm_id(item, f"$.failure_domains[{i}]")
        elif isinstance(item, dict):
            domain_id = norm_id(item.get("id"), f"$.failure_domains[{i}].id")
        else:
            raise CaseError("failure domain must be a string or object", f"$.failure_domains[{i}]")
        if domain_id in domain_ids:
            raise CaseError("duplicate failure domain", f"$.failure_domains[{i}].id")
        domain_ids.add(domain_id)

    # Certificates --------------------------------------------------------------------
    raw_certs = document.get("certificates", document.get("certificate_registry", {}))
    if not isinstance(raw_certs, dict):
        raise CaseError("certificates must be an object keyed by certificate code", "$.certificates")
    certificates: dict[str, dict] = {}
    for cert_id_raw, cert in raw_certs.items():
        cert_id = norm_id(cert_id_raw, "$.certificates")
        if not isinstance(cert, dict):
            raise CaseError("certificate entry must be an object", f"$.certificates.{cert_id_raw}")
        zone = cert.get("trust_zone", cert.get("zone"))
        if zone is None:
            raise CaseError("certificate requires trust_zone", f"$.certificates.{cert_id}.trust_zone")
        certificates[cert_id] = {
            "id": cert_id,
            "trust_zone": norm_id(zone, f"$.certificates.{cert_id}.trust_zone"),
        }

    # Nodes ---------------------------------------------------------------------------
    raw_nodes = document.get("nodes", [])
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise CaseError("nodes must be a nonempty list", "$.nodes")
    nodes: dict[str, dict] = {}
    for i, raw_node in enumerate(raw_nodes):
        path = f"$.nodes[{i}]"
        if not isinstance(raw_node, dict):
            raise CaseError("node must be an object", path)
        node_id = norm_id(raw_node.get("id"), f"{path}.id")
        if node_id in nodes:
            raise CaseError("duplicate node id", f"{path}.id")
        domain = raw_node.get("failure_domain", raw_node.get("domain"))
        if domain is not None:
            domain = norm_id(domain, f"{path}.failure_domain")
            if domain_ids and domain not in domain_ids:
                raise CaseError("node failure_domain is not declared", f"{path}.failure_domain")
        ops_group = raw_node.get("ops_group", raw_node.get("owner_group"))
        if ops_group is not None:
            ops_group = norm_id(ops_group, f"{path}.ops_group")
        kind = str(raw_node.get("kind", raw_node.get("type", "node")))
        switch_group = raw_node.get("switch_group", raw_node.get("group"))
        if switch_group is not None:
            switch_group = norm_id(switch_group, f"{path}.switch_group")
        fixed_version = raw_node.get("policy_version", raw_node.get("version"))
        if fixed_version is not None:
            fixed_version = str(fixed_version).lower()
            if fixed_version in {"0", "baseline", "phase-a"}:
                fixed_version = "old"
            elif fixed_version in {"1", "candidate", "phase-b"}:
                fixed_version = "new"
            if fixed_version not in {"old", "new"}:
                raise CaseError("policy_version must be old/new", f"{path}.policy_version")
        nodes[node_id] = {
            "id": node_id,
            "kind": kind,
            "failure_domain": domain,
            "ops_group": ops_group,
            "switch_group": switch_group,
            "fixed_version": fixed_version,
            "service_group": raw_node.get("service_group"),
            "labels": raw_node.get("labels", {}),
        }
        if nodes[node_id]["service_group"] is not None:
            nodes[node_id]["service_group"] = norm_id(
                nodes[node_id]["service_group"], f"{path}.service_group"
            )
        if kind == "inspection" and not ops_group:
            raise CaseError("inspection node requires ops_group", f"{path}.ops_group")

    if not domain_ids:
        domain_ids = {node["failure_domain"] for node in nodes.values()
                      if node["failure_domain"] is not None}
    domains = sorted(domain_ids)
    domain_index = {domain: i for i, domain in enumerate(domains)}

    # Policy documents ----------------------------------------------------------------
    policies_raw = document.get("policies", {})
    if not isinstance(policies_raw, dict):
        raise CaseError("policies must be an object", "$.policies")

    def policy_doc(version: str, aliases: tuple[str, ...]) -> dict:
        for alias in (version,) + aliases:
            if alias in policies_raw and isinstance(policies_raw[alias], dict):
                return policies_raw[alias]
        return {}

    policy_docs = {
        "old": policy_doc("old", ("baseline", "v0", "phase_a")),
        "new": policy_doc("new", ("candidate", "v1", "phase_b")),
    }

    # Edges ---------------------------------------------------------------------------
    raw_edges = document.get("edges", [])
    if not isinstance(raw_edges, list):
        raise CaseError("edges must be a list", "$.edges")
    edges: list[dict] = []
    edge_by_id: dict[str, dict] = {}
    adjacency: dict[str, list[tuple[str, str, bool]]] = {node_id: [] for node_id in nodes}

    for i, raw_edge in enumerate(raw_edges):
        path = f"$.edges[{i}]"
        if not isinstance(raw_edge, dict):
            raise CaseError("edge must be an object", path)
        edge_id = raw_edge.get("id", f"edge-{i + 1:03d}")
        edge_id = norm_id(edge_id, f"{path}.id")
        if edge_id in edge_by_id:
            raise CaseError("duplicate edge id", f"{path}.id")
        source_id = norm_id(raw_edge.get("from", raw_edge.get("source")), f"{path}.from")
        target_id = norm_id(raw_edge.get("to", raw_edge.get("target")), f"{path}.to")
        if source_id not in nodes or target_id not in nodes:
            raise CaseError("edge endpoint does not exist", path)

        region = raw_edge.get("region")
        if region is None or not str(region).strip():
            raise CaseError("edge requires region", f"{path}.region")
        region = str(region).strip()
        declared_regions = document.get("regions")
        if declared_regions is not None:
            region_set = set(string_list(declared_regions, "$.regions"))
            if region not in region_set:
                raise CaseError("edge region is not in declared regions", f"{path}.region")

        peer_cert = raw_edge.get("peer_cert", raw_edge.get("peer_certificate"))
        if peer_cert is None:
            raise CaseError("edge requires peer_cert code", f"{path}.peer_cert")
        peer_cert = norm_id(peer_cert, f"{path}.peer_cert")
        if peer_cert not in certificates:
            raise CaseError("peer_cert is not in certificates registry", f"{path}.peer_cert")
        cert_zone = raw_edge.get("cert_zone", raw_edge.get("trust_zone"))
        if cert_zone is None:
            raise CaseError("edge requires cert_zone", f"{path}.cert_zone")
        cert_zone = norm_id(cert_zone, f"{path}.cert_zone")

        scopes = _parse_scopes(raw_edge, path)
        if not scopes:
            raise CaseError("edge requires a nonempty service scope/scopes", f"{path}.scopes")

        inspection_ids = string_list(
            raw_edge.get("inspection_nodes", raw_edge.get("inspections", [])),
            f"{path}.inspection_nodes",
        )
        for insp_id in inspection_ids:
            if insp_id not in nodes:
                raise CaseError("edge inspection node does not exist", f"{path}.inspection_nodes")
            if not nodes[insp_id].get("ops_group"):
                raise CaseError("inspection node has no ops_group", f"{path}.inspection_nodes")

        # Resolve allow/deny for each policy version.
        allow_field = raw_edge.get("allowed", raw_edge.get("policy", raw_edge.get("allow")))
        allows: dict[str, bool] = {}
        for version in ("old", "new"):
            aliases = {
                "old": ("old", "baseline", "v0", "0", "phase_a"),
                "new": ("new", "candidate", "v1", "1", "phase_b"),
            }[version]
            effect: Any = None
            if isinstance(allow_field, bool):
                effect = allow_field
            elif isinstance(allow_field, dict):
                for alias in aliases:
                    if alias in allow_field:
                        effect = allow_field[alias]
                        break
            if effect is None:
                doc = policy_docs[version]
                effects = doc.get("edge_effects", doc.get("effects", {}))
                if isinstance(effects, dict) and edge_id in effects:
                    effect = effects[edge_id]
                else:
                    effect = doc.get("default_effect", doc.get("default", "deny"))
            allows[version] = _effect(effect, f"{path}.allowed.{version}")

        trust_ok: dict[str, bool] = {}
        for version in ("old", "new"):
            zones = policy_docs[version].get(
                "trusted_cert_zones", policy_docs[version].get("trust_zones")
            )
            zone_list = set(string_list(zones, f"$.policies.{version}.trusted_cert_zones")) if zones else set()
            trust_ok[version] = not zone_list or cert_zone in zone_list

        directed = raw_edge.get("directed", raw_edge.get("direction", "directed"))
        if isinstance(directed, str):
            is_directed = directed.strip().lower() not in {"bidirectional", "both", "undirected", "false"}
        else:
            is_directed = bool(directed)

        edge = {
            "id": edge_id,
            "from": source_id,
            "to": target_id,
            "region": region,
            "peer_cert": peer_cert,
            "cert_zone": cert_zone,
            "scopes": scopes,
            "inspection_nodes": inspection_ids,
            "enabled": raw_edge.get("enabled", True) is not False,
            "allow_old": allows["old"],
            "allow_new": allows["new"],
            "trust_old": trust_ok["old"],
            "trust_new": trust_ok["new"],
            "directed": is_directed,
        }
        edges.append(edge)
        edge_by_id[edge_id] = edge
        adjacency[source_id].append((target_id, edge_id, False))
        if not is_directed:
            adjacency[target_id].append((source_id, edge_id, True))

    for node_id in adjacency:
        adjacency[node_id].sort(key=lambda item: (edge_by_id[item[1]]["id"], item[0]))

    resolve_inspection = _make_inspection_resolver(
        nodes,
        document.get("inspection_sequence", document.get("inspection_groups", document.get("inspection_nodes"))),
        "$.inspection_sequence",
    )
    default_inspection = resolve_inspection(
        document.get("inspection_sequence", document.get("inspection_groups", document.get("inspection_nodes"))),
        "$.inspection_sequence",
    )

    path_policy = document.get("path_policy", {})
    if not isinstance(path_policy, dict):
        raise CaseError("path_policy must be an object", "$.path_policy")
    default_required = as_int(
        path_policy.get("required_paths", document.get("required_paths", 2)),
        "$.path_policy.required_paths", 2, 1
    )
    default_failure_required = as_int(
        path_policy.get("failure_required_paths", document.get("failure_required_paths")),
        "$.path_policy.failure_required_paths",
        default_required,
        0,
    )
    default_disjoint = bool(path_policy.get("disjoint_failure_domains",
                                            document.get("disjoint_failure_domains", True)))

    # Requests: critical services and forbidden pairs ---------------------------------
    requests: list[dict] = []

    def build_targets(raw: dict, path: str) -> tuple[list[str], list[str]]:
        source = raw.get("source", raw.get("from", raw.get("client")))
        source = norm_id(source, f"{path}.source")
        if source not in nodes:
            raise CaseError("source node does not exist", f"{path}.source")
        raw_targets = raw.get("replicas", raw.get("targets", raw.get("to")))
        if isinstance(raw_targets, str):
            targets = [norm_id(raw_targets, f"{path}.targets")]
        elif isinstance(raw_targets, list) and raw_targets:
            targets = string_list(raw_targets, f"{path}.targets")
        else:
            raise CaseError("at least one target/replica is required", f"{path}.targets")
        for target in targets:
            if target not in nodes:
                raise CaseError("target node does not exist", f"{path}.targets")
        replicas = raw.get("replicas")
        replica_ids = targets if replicas is not None else []
        return source, targets, replica_ids

    for i, raw_service in enumerate(document.get("services", [])):
        path = f"$.services[{i}]"
        if not isinstance(raw_service, dict):
            raise CaseError("service must be an object", path)
        req_id = norm_id(raw_service.get("id", f"service-{i + 1}"), f"{path}.id")
        source, targets, replica_ids = build_targets(raw_service, path)
        scopes = _parse_scopes(raw_service, path)
        if not scopes:
            raise CaseError("service requires scope/scopes", f"{path}.scope")
        inspection_raw = raw_service.get(
            "inspection_sequence",
            raw_service.get("inspection_groups", raw_service.get("inspection_nodes")),
        )
        inspection = resolve_inspection(inspection_raw, f"{path}.inspection_sequence") if inspection_raw is not None else default_inspection
        required = as_int(raw_service.get("required_paths", raw_service.get("path_count")),
                          f"{path}.required_paths", default_required, 1)
        failure_required = as_int(
            raw_service.get("failure_required_paths", raw_service.get("outage_path_count")),
            f"{path}.failure_required_paths", default_failure_required, 0
        )
        requests.append({
            "id": req_id,
            "kind": "business",
            "source": source,
            "targets": targets,
            "replicas": replica_ids,
            "scopes": scopes,
            "allowed_regions": string_list(raw_service.get("allowed_regions"), f"{path}.allowed_regions"),
            "inspection": inspection,
            "required_paths": required,
            "failure_required_paths": failure_required,
            "disjoint": raw_service.get("disjoint_failure_domains", default_disjoint) is not False,
            "distinct_replicas": raw_service.get("distinct_replicas", True) is not False,
            "require_each_replica": raw_service.get("require_each_replica", bool(replica_ids)) is not False,
            "failure_require_each_replica": bool(raw_service.get("failure_require_each_replica", False)),
            "critical": raw_service.get("critical", True) is not False,
            "enforced": raw_service.get("enforced", raw_service.get("critical", True)) is not False,
            "expect_authorized": True,
        })

    # Explicit forbidden pairs.
    forbidden_raw = document.get("forbidden_pairs", document.get("denied_pairs", []))
    if not isinstance(forbidden_raw, list):
        raise CaseError("forbidden_pairs must be a list", "$.forbidden_pairs")

    def add_forbidden(raw_pair: dict, path: str, index: int,
                      source_override: str | None = None,
                      target_override: str | None = None) -> None:
        req_id = norm_id(raw_pair.get("id", f"forbidden-{index + 1}"), f"{path}.id")
        if source_override is None:
            source = norm_id(raw_pair.get("source", raw_pair.get("from")), f"{path}.source")
        else:
            source = source_override
        if target_override is None:
            target = norm_id(raw_pair.get("target", raw_pair.get("to")), f"{path}.target")
        else:
            target = target_override
        if source not in nodes or target not in nodes:
            raise CaseError("forbidden pair endpoint does not exist", path)
        scopes = _parse_scopes(raw_pair, path)
        inspection_raw = raw_pair.get(
            "inspection_sequence",
            raw_pair.get("inspection_groups", raw_pair.get("inspection_nodes")),
        )
        inspection = resolve_inspection(inspection_raw, f"{path}.inspection_sequence") if inspection_raw is not None else default_inspection
        requests.append({
            "id": req_id,
            "kind": "forbidden",
            "source": source,
            "targets": [target],
            "replicas": [],
            "scopes": scopes,
            "allowed_regions": string_list(raw_pair.get("allowed_regions"), f"{path}.allowed_regions"),
            "inspection": inspection,
            "required_paths": 0,
            "failure_required_paths": 0,
            "disjoint": False,
            "distinct_replicas": False,
            "require_each_replica": False,
            "failure_require_each_replica": False,
            "critical": True,
            "enforced": True,
            "expect_authorized": False,
        })

    forbidden_index = 0
    for i, raw_pair in enumerate(forbidden_raw):
        path = f"$.forbidden_pairs[{i}]"
        if not isinstance(raw_pair, dict):
            raise CaseError("forbidden pair must be an object", path)
        forbidden_index += 1
        add_forbidden(raw_pair, path, forbidden_index)

    # Group-level forbidden expansions.
    service_groups = document.get("service_groups", {})
    if not isinstance(service_groups, dict):
        raise CaseError("service_groups must be an object", "$.service_groups")
    group_members: dict[str, list[str]] = {}
    for group_raw, members_raw in service_groups.items():
        group_name = norm_id(group_raw, "$.service_groups")
        members = string_list(members_raw, f"$.service_groups.{group_raw}")
        for member in members:
            if member not in nodes:
                raise CaseError("service group member is not a node", f"$.service_groups.{group_raw}")
        group_members[group_name] = members
    for node in nodes.values():
        if node["service_group"]:
            group_members.setdefault(node["service_group"], []).append(node["id"])
    for members in group_members.values():
        members.sort()

    group_pairs = document.get("forbidden_group_pairs", [])
    if not isinstance(group_pairs, list):
        raise CaseError("forbidden_group_pairs must be a list", "$.forbidden_group_pairs")
    for i, raw_gp in enumerate(group_pairs):
        path = f"$.forbidden_group_pairs[{i}]"
        if not isinstance(raw_gp, dict):
            raise CaseError("forbidden group pair must be an object", path)
        sg = norm_id(raw_gp.get("source_service_group", raw_gp.get("source_group")), f"{path}.source_group")
        tg = norm_id(raw_gp.get("target_service_group", raw_gp.get("target_group")), f"{path}.target_group")
        if sg not in group_members or tg not in group_members:
            raise CaseError("unknown service group in forbidden_group_pairs", path)
        for source in group_members[sg]:
            for target in group_members[tg]:
                forbidden_index += 1
                synthetic = dict(raw_gp)
                synthetic.pop("id", None)
                synthetic_id = f"{raw_gp.get('id', f'group-pair-{i + 1}')}:{source}->{target}"
                synthetic["id"] = synthetic_id
                add_forbidden(synthetic, f"{path}({source},{target})", forbidden_index, source, target)

    # Switch groups -------------------------------------------------------------------
    raw_groups = document.get("switch_groups", [])
    groups: dict[str, dict] = {}
    if isinstance(raw_groups, list):
        for i, raw_group in enumerate(raw_groups):
            path = f"$.switch_groups[{i}]"
            if not isinstance(raw_group, dict):
                raise CaseError("switch group must be an object", path)
            gid = norm_id(raw_group.get("id"), f"{path}.id")
            if gid in groups:
                raise CaseError("duplicate switch group", f"{path}.id")
            member_ids = string_list(raw_group.get("nodes", raw_group.get("node_ids", [])), f"{path}.nodes")
            for nid in member_ids:
                if nid not in nodes:
                    raise CaseError("switch group node does not exist", f"{path}.nodes")
                existing = nodes[nid]["switch_group"]
                if existing is not None and existing != gid:
                    raise CaseError("node belongs to multiple switch groups", f"{path}.nodes")
                nodes[nid]["switch_group"] = gid
            size = as_int(raw_group.get("migration_units", raw_group.get("quota_cost")),
                          f"{path}.migration_units", len(member_ids), 0)
            groups[gid] = {
                "id": gid,
                "nodes": sorted(member_ids),
                "migration_units": size,
                "weighted_downtime": _resolve_cost(raw_group, path),
            }
    elif raw_groups is not None:
        raise CaseError("switch_groups must be a list", "$.switch_groups")

    for node in nodes.values():
        gid = node["switch_group"]
        if gid is None:
            continue
        if gid not in groups:
            groups[gid] = {"id": gid, "nodes": [], "migration_units": None, "weighted_downtime": Decimal(0)}
        if node["id"] not in groups[gid]["nodes"]:
            groups[gid]["nodes"].append(node["id"])
    for gid, group in groups.items():
        group["nodes"].sort()
        if group["migration_units"] is None:
            group["migration_units"] = len(group["nodes"])

    group_ids = sorted(groups)
    group_index = {gid: i for i, gid in enumerate(group_ids)}

    # Union-find for groups that must switch in one batch.
    parent = {gid: gid for gid in group_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i, raw_set in enumerate(document.get("joint_switch_sets", [])):
        path = f"$.joint_switch_sets[{i}]"
        ids = string_list(raw_set, path)
        if len(ids) < 2:
            raise CaseError("joint switch set needs at least two group ids", path)
        for gid in ids:
            if gid not in groups:
                raise CaseError("unknown switch group in joint set", path)
        for gid in ids[1:]:
            union(ids[0], gid)

    for i, raw_node_set in enumerate(document.get("co_switch_node_sets", [])):
        path = f"$.co_switch_node_sets[{i}]"
        node_ids = string_list(raw_node_set, path)
        gids = []
        for nid in node_ids:
            if nid not in nodes:
                raise CaseError("unknown node in co_switch_node_sets", path)
            gid = nodes[nid]["switch_group"]
            if gid is None:
                raise CaseError("co-switched node must belong to a switch group", path)
            gids.append(gid)
        for gid in gids[1:]:
            union(gids[0], gid)

    unit_map: dict[str, list[str]] = {}
    for gid in group_ids:
        unit_map.setdefault(find(gid), []).append(gid)
    units = []
    for member_groups in unit_map.values():
        member_groups.sort()
        units.append({
            "groups": member_groups,
            "migration_units": sum(groups[g]["migration_units"] for g in member_groups),
            "weighted_downtime": sum((groups[g]["weighted_downtime"] for g in member_groups), Decimal(0)),
        })
    units.sort(key=lambda u: tuple(group_index[g] for g in u["groups"]))
    for i, unit in enumerate(units):
        unit["index"] = i
        unit["bit"] = 1 << i
    group_to_unit = {g: unit["index"] for unit in units for g in unit["groups"]}

    # Batch windows / quota -----------------------------------------------------------
    batch_doc = document.get("batch", {})
    if not isinstance(batch_doc, dict):
        raise CaseError("batch must be an object", "$.batch")
    capacity_raw = batch_doc.get("capacity", document.get("batch_capacity"))
    capacity = as_int(capacity_raw, "$.batch.capacity", None, 1) if capacity_raw is not None else None
    max_batches = as_int(batch_doc.get("max_batches", document.get("max_batches")),
                         "$.batch.max_batches", None, 1)
    windows_raw = batch_doc.get("windows", document.get("batch_windows", []))
    if not isinstance(windows_raw, list):
        raise CaseError("batch_windows must be a list", "$.batch.windows")
    windows = []
    for i, raw_window in enumerate(windows_raw):
        if isinstance(raw_window, str):
            windows.append({"id": norm_id(raw_window, f"$.batch.windows[{i}]"), "capacity": capacity})
        elif isinstance(raw_window, dict):
            wid = norm_id(raw_window.get("id"), f"$.batch.windows[{i}].id")
            wcap = raw_window.get("capacity", capacity)
            windows.append({
                "id": wid,
                "capacity": as_int(wcap, f"$.batch.windows[{i}].capacity", None, 1) if wcap is not None else None,
            })
        else:
            raise CaseError("batch window must be string or object", f"$.batch.windows[{i}]")

    # Candidate hard isolation operations --------------------------------------------
    ops_raw = document.get(
        "isolation_operations",
        document.get("hard_isolation_operations", document.get("candidate_isolation_operations", [])),
    )
    if not isinstance(ops_raw, list):
        raise CaseError("isolation_operations must be a list", "$.isolation_operations")
    operations: dict[str, dict] = {}
    for i, raw_op in enumerate(ops_raw):
        path = f"$.isolation_operations[{i}]"
        if not isinstance(raw_op, dict):
            raise CaseError("isolation operation must be an object", path)
        oid = norm_id(raw_op.get("id"), f"{path}.id")
        if oid in operations:
            raise CaseError("duplicate isolation operation id", f"{path}.id")
        disable_edges = string_list(raw_op.get("disable_edges", raw_op.get("isolate_edges", [])), f"{path}.disable_edges")
        disable_nodes = string_list(raw_op.get("disable_nodes", raw_op.get("isolate_nodes", [])), f"{path}.disable_nodes")
        disable_domains = string_list(
            raw_op.get("disable_failure_domains", raw_op.get("isolate_failure_domains", [])),
            f"{path}.disable_failure_domains",
        )
        for eid in disable_edges:
            if eid not in edge_by_id:
                raise CaseError("operation disables unknown edge", f"{path}.disable_edges")
        for nid in disable_nodes:
            if nid not in nodes:
                raise CaseError("operation disables unknown node", f"{path}.disable_nodes")
        for did in disable_domains:
            if did not in domain_index:
                raise CaseError("operation disables undeclared failure domain", f"{path}.disable_failure_domains")
        operations[oid] = {
            "id": oid,
            "disable_edges": disable_edges,
            "disable_nodes": disable_nodes,
            "disable_failure_domains": disable_domains,
            "weighted_downtime": _resolve_cost(raw_op, path),
        }
    operation_ids = sorted(operations)
    operation_index = {oid: i for i, oid in enumerate(operation_ids)}

    protected_raw = document.get("protected_businesses", document.get("guaranteed_services"))
    if protected_raw is None:
        protected = [r["id"] for r in requests if r["kind"] == "business" and r["critical"]]
    else:
        protected = string_list(protected_raw, "$.protected_businesses")
    business_ids = {r["id"] for r in requests if r["kind"] == "business"}
    for pid in protected:
        if pid not in business_ids:
            raise CaseError("protected business is not a service id", "$.protected_businesses")

    relaxation_raw = document.get("relaxation", {})
    if relaxation_raw is None:
        relaxation_raw = {}
    if not isinstance(relaxation_raw, dict):
        raise CaseError("relaxation must be an object", "$.relaxation")
    relaxation = {
        "type": relaxation_raw.get("type", "reduce_required_paths"),
        "by": as_int(relaxation_raw.get("by"), "$.relaxation.by", 1, 1),
        "minimum": as_int(relaxation_raw.get("minimum"), "$.relaxation.minimum", 1, 1),
        "also_reduce_failure_paths": relaxation_raw.get("also_reduce_failure_paths", True) is not False,
    }

    return {
        "schema": schema,
        "case_id": case_id,
        "nodes": nodes,
        "edges": edges,
        "edge_by_id": edge_by_id,
        "adjacency": adjacency,
        "domains": domains,
        "domain_index": domain_index,
        "certificates": certificates,
        "requests": requests,
        "switch_groups": groups,
        "group_ids": group_ids,
        "group_index": group_index,
        "units": units,
        "group_to_unit": group_to_unit,
        "batch_capacity": capacity,
        "max_batches": max_batches,
        "windows": windows,
        "operations": operations,
        "operation_ids": operation_ids,
        "operation_index": operation_index,
        "protected_businesses": protected,
        "relaxation": relaxation,
        "limits": document.get("limits", {}),
        "raw": document,
    }
