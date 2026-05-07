import json

from rsfuzzer.cli import build_parser
from rsfuzzer.cli import run_discover


def test_parser_has_expected_commands() -> None:
    parser = build_parser()

    args = parser.parse_args(["discover"])
    assert args.command == "discover"

    args = parser.parse_args(["test"])
    assert args.command == "test"

    args = parser.parse_args(["report"])
    assert args.command == "report"


def test_discover_from_openapi_writes_catalog(tmp_path) -> None:
    openapi_file = tmp_path / "openapi.json"
    out_file = tmp_path / "catalog.json"
    openapi_file.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "security": [{"bearerAuth": []}],
                "paths": {
                    "/api/orders/{orderId}": {
                        "parameters": [{"name": "orderId", "in": "path"}],
                        "get": {
                            "operationId": "getOrder",
                            "summary": "Get one order",
                            "parameters": [{"name": "expand", "in": "query"}],
                        },
                        "patch": {
                            "operationId": "updateOrder",
                            "requestBody": {
                                "content": {
                                    "application/json": {},
                                    "application/merge-patch+json": {},
                                }
                            },
                            "security": [{"adminAuth": []}],
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    parser = build_parser()
    args = parser.parse_args(["discover", "--openapi", str(openapi_file), "--out", str(out_file)])

    rc = run_discover(args)
    assert rc == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["endpoint_count"] == 2
    assert {e["method"] for e in data["endpoints"]} == {"GET", "PATCH"}

    get_ep = next(e for e in data["endpoints"] if e["method"] == "GET")
    assert get_ep["path"] == "/api/orders/{orderId}"
    assert get_ep["auth_schemes"] == ["bearerAuth"]
    assert get_ep["path_params"] == ["orderId"]
    assert get_ep["query_params"] == ["expand"]

    patch_ep = next(e for e in data["endpoints"] if e["method"] == "PATCH")
    assert patch_ep["auth_schemes"] == ["adminAuth"]
    assert patch_ep["body_content_types"] == ["application/json", "application/merge-patch+json"]


def test_discover_requires_openapi_for_now() -> None:
    parser = build_parser()
    args = parser.parse_args(["discover"])
    assert run_discover(args) == 2
