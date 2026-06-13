from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from rsfuzzer.discovery import extract_endpoints
from rsfuzzer.discovery import extract_endpoints_from_traffic
from rsfuzzer.discovery import load_openapi_spec
from rsfuzzer.discovery import load_traffic_flows
from rsfuzzer.discovery import merge_endpoints
from rsfuzzer.discovery import write_endpoint_catalog
from rsfuzzer.profiles import load_profile
from rsfuzzer.testing import load_catalog
from rsfuzzer.testing import role_pair_from_args
from rsfuzzer.testing import run_catalog_scan
from rsfuzzer.testing import run_check
from rsfuzzer.testing import run_differential_case
from rsfuzzer.testing import write_test_report
from rsfuzzer.mutations import MutationCase
from rsfuzzer.mutations import permute_case


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rsfuzzer",
        description="API logic and authorization fuzzer.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Discover API endpoints.")
    discover.add_argument("--openapi", help="Path to OpenAPI file.", default=None)
    discover.add_argument("--traffic", help="Path to traffic capture file.", default=None)
    discover.add_argument(
        "--out",
        default="artifacts/endpoints.json",
        help="Output path for normalized endpoint catalog.",
    )
    discover.set_defaults(func=run_discover)

    test = subparsers.add_parser("test", help="Run fuzzing tests.")
    test.add_argument(
        "--profile-file",
        required=True,
        help="Path to profile YAML (base_url, roles, fixtures, checks).",
    )
    test.add_argument(
        "--catalog",
        default="artifacts/endpoints.json",
        help="Endpoint catalog JSON from 'discover'.",
    )
    test.add_argument(
        "--roles",
        required=True,
        help="Two comma-separated role names for catalog scan, e.g. user_alice,user_bob.",
    )
    test.add_argument("--scope", default="*", help="fnmatch pattern for catalog paths (e.g. /api/*).")
    test.add_argument(
        "--out",
        default="artifacts/test_report.json",
        help="JSON report output path.",
    )
    test.add_argument(
        "--no-scan",
        action="store_true",
        help="Skip GET catalog scan; only run explicit checks from profile.",
    )
    test.add_argument(
        "--max",
        type=int,
        default=0,
        metavar="N",
        help="With catalog scan: per GET endpoint and role, run up to N extra requests using the mutation engine (same as `mutate`). 0 disables.",
    )
    test.add_argument(
        "--mutate-light",
        action="store_true",
        help="Smaller mutation set when --max > 0.",
    )
    test.add_argument(
        "--mutate-parts",
        default="query,headers",
        help="With --max > 0: comma-separated axes body, query, headers. "
        "Including body also scans POST/PATCH/PUT from the catalog with JSON payloads.",
    )
    test.set_defaults(func=run_test)

    mutate = subparsers.add_parser(
        "mutate",
        help="Generate mutated requests from strategies (stdout JSON lines, dry-run).",
    )
    mutate.add_argument("--method", default="POST", help="HTTP method.")
    mutate.add_argument("--path", default="/api/orders", help="URL path.")
    mutate.add_argument("--max", type=int, default=30, help="Max variants to print.")
    mutate.add_argument(
        "--light",
        action="store_true",
        help="Smaller strategy set (faster smoke).",
    )
    mutate.add_argument(
        "--parts",
        default="body,query,headers",
        help="Comma-separated: body, query, headers.",
    )
    mutate.set_defaults(func=run_mutate)

    report = subparsers.add_parser("report", help="Generate report artifacts.")
    report.add_argument("--format", choices=["md", "json"], default="md")
    report.add_argument("--out", default="reports/latest.md", help="Output report path.")
    report.set_defaults(func=run_report)

    return parser


def run_discover(args: argparse.Namespace) -> int:
    print(f"[discover] openapi={args.openapi} traffic={args.traffic} out={args.out}")

    if not args.openapi and not args.traffic:
        print("[discover] Provide at least one source: --openapi or --traffic.")
        return 2

    openapi_endpoints = []
    traffic_endpoints = []
    openapi_path: Path | None = None
    traffic_path: Path | None = None

    try:
        if args.openapi:
            openapi_path = Path(args.openapi)
            if not openapi_path.exists():
                print(f"[discover] OpenAPI file not found: {openapi_path}")
                return 2
            spec = load_openapi_spec(openapi_path)
            openapi_endpoints = extract_endpoints(spec)

        if args.traffic:
            traffic_path = Path(args.traffic)
            if not traffic_path.exists():
                print(f"[discover] Traffic file not found: {traffic_path}")
                return 2
            flows = load_traffic_flows(traffic_path)
            traffic_endpoints = extract_endpoints_from_traffic(flows)

        endpoints = merge_endpoints(openapi_endpoints + traffic_endpoints)
        write_endpoint_catalog(
            endpoints,
            Path(args.out),
            source_openapi=str(openapi_path) if openapi_path else None,
            source_traffic=str(traffic_path) if traffic_path else None,
        )
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"[discover] Failed to process discovery sources: {exc}")
        return 1

    print(f"[discover] Extracted {len(endpoints)} endpoints.")
    print(f"[discover] Catalog written to: {args.out}")
    return 0


def run_test(args: argparse.Namespace) -> int:
    profile_path = Path(args.profile_file)
    catalog_path = Path(args.catalog)
    out_path = Path(args.out)

    print(f"[test] profile-file={profile_path} catalog={catalog_path} roles={args.roles}")

    if not profile_path.exists():
        print(f"[test] Profile not found: {profile_path}")
        return 2
    if not catalog_path.exists():
        print(f"[test] Catalog not found: {catalog_path}")
        return 2

    try:
        profile = load_profile(profile_path)
        role_pair = role_pair_from_args(profile, args.roles)
        catalog = load_catalog(catalog_path)
    except Exception as exc:
        print(f"[test] Failed to load inputs: {exc}")
        return 1

    check_results: list = []
    for check in profile.checks:
        check_results.extend(run_check(profile, check))

    differential_results: list = []
    for dcase in profile.differential:
        differential_results.extend(run_differential_case(profile, dcase))

    scan_rows: list = []
    scan_failed = False
    if not args.no_scan:
        try:
            mutate_parts = tuple(
                p.strip() for p in args.mutate_parts.split(",") if p.strip()
            ) or ("query", "headers")
            scan_rows, _ = run_catalog_scan(
                profile,
                catalog,
                role_pair,
                args.scope,
                mutate_max=args.max,
                mutate_light=args.mutate_light,
                mutate_parts=mutate_parts,
            )
        except Exception as exc:
            scan_failed = True
            print(f"[test] Catalog scan aborted early: {exc}")

    write_test_report(
        out_path,
        profile_path,
        catalog_path,
        role_pair,
        args.scope,
        check_results,
        differential_results,
        scan_rows,
    )

    failed = [c for c in check_results + differential_results if not c.passed]
    print(f"[test] Checks: {len(check_results)} total.")
    print(f"[test] Differential: {len(differential_results)} requests, {sum(1 for c in differential_results if not c.passed)} failed.")
    print(f"[test] Failed (checks + differential): {len(failed)}.")
    if not args.no_scan:
        n_mut = sum(1 for r in scan_rows if r.from_mutations)
        n_err = sum(1 for r in scan_rows if r.status_code == 0 or r.client_error)
        print(f"[test] Scan rows: {len(scan_rows)} ({n_mut} mutation-engine, {n_err} errors).")
        if scan_failed:
            print("[test] Warning: catalog scan did not finish; partial results in report.")
    print(f"[test] Report written to: {out_path}")

    return 1 if failed else 0


def run_mutate(args: argparse.Namespace) -> int:
    parts_tuple = tuple(p.strip() for p in args.parts.split(",") if p.strip())
    case = MutationCase(
        method=args.method.upper(),
        path=args.path,
        base_headers={"x-user-id": "u1", "x-role": "user", "Content-Type": "application/json"},
        base_query={"expand": "items"},
        base_body={"status": "paid", "total": 100},
    )
    n = 0
    for req in permute_case(
        case,
        light=args.light,
        max_variants=args.max,
        parts=parts_tuple,
    ):
        row = {
            "method": req.method,
            "path": req.path,
            "headers": req.headers,
            "query": req.query,
            "body": req.body,
            "traces": [asdict(t) for t in req.traces],
        }
        print(json.dumps(row, ensure_ascii=True))
        n += 1
        if n >= args.max:
            break
    print(f"[mutate] emitted {n} variants", flush=True)
    return 0


def run_report(args: argparse.Namespace) -> int:
    print(f"[report] format={args.format} out={args.out}")
    print("[report] TODO: implement JSON/Markdown report generation.")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
