from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any, Sequence

from .audit import audit_case_plan
from .errors import CaseError, PlanDocumentError
from .model import load_json_document, load_json_text, parse_case
from .planner import plan_case


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def serialize_report(report: dict, compact: bool = False) -> bytes:
    text = json.dumps(
        report,
        ensure_ascii=False,
        separators=(",", ":") if compact else (",", ": "),
        indent=None if compact else 2,
        default=_json_default,
    )
    return text.encode("utf-8")


def _write_report(report: dict, args: argparse.Namespace, exit_code: int) -> int:
    payload = serialize_report(report, compact=getattr(args, "compact", False))
    output = getattr(args, "output", None)
    if output:
        Path(output).write_bytes(payload + b"\n")
    try:
        sys.stdout.buffer.write(payload + b"\n")
        sys.stdout.buffer.flush()
    except OSError:
        # The downstream pipe/pager may already have exited. An --output
        # file, if requested, was written before reaching this point.
        pass
    return exit_code


def _read_json_argument(path_value: str) -> Any:
    if path_value == "-":
        return load_json_text(sys.stdin.read())
    return load_json_document(path_value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meshcutover",
        description="Offline isolated acceptance and batching planner for abstract service cutovers.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="audit CASE [PLAN] with compliance traces")
    audit.add_argument("case", help="path to UTF-8 JSON case document, or - for stdin")
    audit.add_argument("plan", nargs="?", default=None,
                       help="path to plan JSON; if omitted, CASE.plan or CASE itself is used")
    audit.add_argument("--trace-level", choices=("full", "compact", "none"), default="full")
    audit.add_argument("--compact", action="store_true", help="emit minified JSON")
    audit.add_argument("--output", "-o", help="also write the UTF-8 JSON report to this path")

    plan = subparsers.add_parser("plan", help="find the exact minimum-cost batch plan for CASE")
    plan.add_argument("case", help="path to UTF-8 JSON case document, or - for stdin")
    plan.add_argument("--compact", action="store_true", help="emit minified JSON")
    plan.add_argument("--no-relax", action="store_true", help="skip per-business relaxed resolves")
    plan.add_argument("--no-audit", action="store_true", help="omit embedded compact audit")
    plan.add_argument("--output", "-o", help="also write the UTF-8 JSON report to this path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        case_document = _read_json_argument(args.case)
        case = parse_case(case_document)

        if args.command == "audit":
            if args.plan:
                plan_document = _read_json_argument(args.plan)
            else:
                plan_document = case_document
            report = audit_case_plan(case, plan_document, trace_level=args.trace_level)
            return _write_report(report, args, 0 if report["status"] == "pass" else 1)

        report = plan_case(
            case,
            include_relaxations=not args.no_relax,
            include_audit=not args.no_audit,
        )
        return _write_report(report, args, 0 if report["satisfiable"] else 1)

    except PlanDocumentError as exc:
        return _write_report(exc.to_json(), args, 2)
    except CaseError as exc:
        return _write_report(exc.to_json(), args, 2)
    except FileNotFoundError as exc:
        report = {
            "status": "input_error",
            "error": {"type": "file_not_found", "message": str(exc)},
        }
        return _write_report(report, args, 2)
    except Exception as exc:  # noqa: BLE001 - CLI boundary returns JSON.
        report = {
            "status": "internal_error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
        return _write_report(report, args, 3)


if __name__ == "__main__":
    raise SystemExit(main())
