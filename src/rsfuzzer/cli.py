from __future__ import annotations

import argparse
from pathlib import Path

from rsfuzzer.discovery import extract_endpoints
from rsfuzzer.discovery import load_openapi_spec
from rsfuzzer.discovery import write_endpoint_catalog


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
    test.add_argument("--profile", default="local", help="Target profile name.")
    test.add_argument("--roles", default="user,admin", help="Comma-separated roles.")
    test.add_argument("--scope", default="*", help="Endpoint scope filter.")
    test.set_defaults(func=run_test)

    report = subparsers.add_parser("report", help="Generate report artifacts.")
    report.add_argument("--format", choices=["md", "json"], default="md")
    report.add_argument("--out", default="reports/latest.md", help="Output report path.")
    report.set_defaults(func=run_report)

    return parser


def run_discover(args: argparse.Namespace) -> int:
    print(f"[discover] openapi={args.openapi} traffic={args.traffic} out={args.out}")

    if not args.openapi:
        print("[discover] --openapi is required for now.")
        print("[discover] TODO: traffic ingestion will be implemented next.")
        return 2

    openapi_path = Path(args.openapi)
    if not openapi_path.exists():
        print(f"[discover] OpenAPI file not found: {openapi_path}")
        return 2

    try:
        spec = load_openapi_spec(openapi_path)
        endpoints = extract_endpoints(spec)
        write_endpoint_catalog(endpoints, Path(args.out), source_openapi=str(openapi_path))
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        print(f"[discover] Failed to process OpenAPI: {exc}")
        return 1

    print(f"[discover] Extracted {len(endpoints)} endpoints.")
    print(f"[discover] Catalog written to: {args.out}")
    return 0


def run_test(args: argparse.Namespace) -> int:
    print(f"[test] profile={args.profile} roles={args.roles} scope={args.scope}")
    print("[test] TODO: implement differential authz and logic fuzzing engine.")
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
