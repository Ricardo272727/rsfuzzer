import json
from unittest.mock import patch

from rsfuzzer.cli import build_parser
from rsfuzzer.cli import run_discover
from rsfuzzer.cli import run_test
from rsfuzzer.profiles import load_profile
from rsfuzzer.testing import HttpResult
from rsfuzzer.testing import run_differential_case


def test_parser_has_expected_commands(tmp_path) -> None:
    parser = build_parser()

    args = parser.parse_args(["discover"])
    assert args.command == "discover"

    profile_file = tmp_path / "profile.yaml"
    profile_file.write_text(
        "base_url: http://127.0.0.1\n"
        "roles:\n"
        "  a:\n"
        "    headers: {x: '1'}\n"
        "  b:\n"
        "    headers: {x: '2'}\n",
        encoding="utf-8",
    )
    args = parser.parse_args(
        ["test", "--profile-file", str(profile_file), "--roles", "a,b", "--no-scan"]
    )
    assert args.command == "test"
    assert args.max == 0

    args = parser.parse_args(
        [
            "test",
            "--profile-file",
            str(profile_file),
            "--roles",
            "a,b",
            "--max",
            "15",
            "--mutate-light",
            "--mutate-parts",
            "headers",
        ]
    )
    assert args.max == 15
    assert args.mutate_light is True
    assert args.mutate_parts == "headers"

    args = parser.parse_args(["report"])
    assert args.command == "report"

    args = parser.parse_args(["mutate", "--max", "5", "--light", "--parts", "body"])
    assert args.command == "mutate"


@patch("rsfuzzer.testing.http_request")
def test_run_test_runs_checks_and_writes_report(mock_http, tmp_path) -> None:
    profile_file = tmp_path / "profile.yaml"
    profile_file.write_text(
        """
base_url: http://127.0.0.1
roles:
  user_alice:
    headers:
      x-user-id: u1
      x-role: user
  user_bob:
    headers:
      x-user-id: u2
      x-role: user
fixtures:
  path_params:
    id: "101"
checks:
  - id: order_gate
    method: GET
    path: /api/orders/{id}
    expect:
      user_alice: 200
      user_bob: 403
""".strip(),
        encoding="utf-8",
    )
    catalog_file = tmp_path / "catalog.json"
    catalog_file.write_text(
        json.dumps({"endpoints": [{"method": "GET", "path": "/api/orders", "path_params": []}]}),
        encoding="utf-8",
    )
    report_file = tmp_path / "report.json"

    mock_http.side_effect = [
        HttpResult(200, "ok"),
        HttpResult(403, "no"),
    ]

    parser = build_parser()
    args = parser.parse_args(
        [
            "test",
            "--profile-file",
            str(profile_file),
            "--catalog",
            str(catalog_file),
            "--roles",
            "user_alice,user_bob",
            "--no-scan",
            "--out",
            str(report_file),
        ]
    )
    rc = run_test(args)
    assert rc == 0
    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["check_failures"] == []


@patch("rsfuzzer.testing.http_request")
def test_differential_matrix_passes_when_bob_always_forbidden(mock_http, tmp_path) -> None:
    profile_file = tmp_path / "profile.yaml"
    profile_file.write_text(
        """
base_url: http://127.0.0.1
roles:
  user_alice:
    headers:
      x-user-id: u1
      x-role: user
  user_bob:
    headers:
      x-user-id: u2
      x-role: user
fixtures:
  path_params:
    id: "101"
differential:
  - id: surf
    method: GET
    path: /api/orders/{id}
    path_params:
      id: "101"
    query_mutations:
      - {}
      - { debug: "1" }
    header_mutations:
      - {}
      - { X-Trusted-Subject: u1 }
    expect:
      user_alice: 200
      user_bob: 403
""".strip(),
        encoding="utf-8",
    )

    def side_effect(method, url, headers, body):
        if headers.get("x-user-id") == "u1":
            return HttpResult(200, "ok")
        return HttpResult(403, "no")

    mock_http.side_effect = side_effect
    profile = load_profile(profile_file)
    results = run_differential_case(profile, profile.differential[0])
    assert len(results) == 8
    assert all(r.passed for r in results)


@patch("rsfuzzer.testing.http_request")
def test_differential_matrix_fails_when_bob_gets_success(mock_http, tmp_path) -> None:
    profile_file = tmp_path / "profile.yaml"
    profile_file.write_text(
        """
base_url: http://127.0.0.1
roles:
  user_alice:
    headers:
      x-user-id: u1
      x-role: user
  user_bob:
    headers:
      x-user-id: u2
      x-role: user
fixtures:
  path_params:
    id: "101"
differential:
  - id: surf
    method: GET
    path: /api/orders/{id}
    path_params:
      id: "101"
    query_mutations:
      - { expand: internal }
    header_mutations:
      - {}
    expect:
      user_alice: 200
      user_bob: 403
""".strip(),
        encoding="utf-8",
    )
    mock_http.return_value = HttpResult(200, "leak")
    profile = load_profile(profile_file)
    results = run_differential_case(profile, profile.differential[0])
    assert any(not r.passed for r in results)


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


def test_discover_from_traffic_writes_catalog(tmp_path) -> None:
    traffic_file = tmp_path / "flows.json"
    out_file = tmp_path / "catalog.json"
    traffic_file.write_text(
        json.dumps(
            {
                "flows": [
                    {
                        "request": {
                            "method": "GET",
                            "pretty_url": "https://api.local/orders/123?expand=items",
                        },
                        "response": {"status_code": 200},
                    },
                    {
                        "request": {
                            "method": "GET",
                            "pretty_url": "https://api.local/orders/999?expand=payments",
                        },
                        "response": {"status_code": 404},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    parser = build_parser()
    args = parser.parse_args(["discover", "--traffic", str(traffic_file), "--out", str(out_file)])
    rc = run_discover(args)

    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["endpoint_count"] == 1
    endpoint = data["endpoints"][0]
    assert endpoint["path"] == "/orders/{id}"
    assert endpoint["sources"] == ["traffic"]
    assert endpoint["status_codes"] == [200, 404]
    assert endpoint["query_params"] == ["expand"]


def test_discover_merges_openapi_and_traffic_sources(tmp_path) -> None:
    openapi_file = tmp_path / "openapi.json"
    traffic_file = tmp_path / "flows.ndjson"
    out_file = tmp_path / "catalog.json"

    openapi_file.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "paths": {
                    "/api/orders/{id}": {
                        "get": {"security": [{"bearerAuth": []}]},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    traffic_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "request": {
                            "method": "GET",
                            "pretty_url": "https://api.local/api/orders/123?expand=items",
                            "headers": {"content-type": "application/json; charset=utf-8"},
                        },
                        "response": {"status_code": 200},
                    }
                ),
                json.dumps(
                    {
                        "request": {
                            "method": "POST",
                            "pretty_url": "https://api.local/api/orders",
                            "headers": {"content-type": "application/json"},
                        },
                        "response": {"status_code": 201},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    parser = build_parser()
    args = parser.parse_args(
        [
            "discover",
            "--openapi",
            str(openapi_file),
            "--traffic",
            str(traffic_file),
            "--out",
            str(out_file),
        ]
    )
    rc = run_discover(args)
    assert rc == 0

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["endpoint_count"] == 2

    get_ep = next(e for e in data["endpoints"] if e["method"] == "GET")
    assert get_ep["path"] == "/api/orders/{id}"
    assert get_ep["sources"] == ["openapi", "traffic"]
    assert get_ep["auth_schemes"] == ["bearerAuth"]
    assert get_ep["status_codes"] == [200]
    assert get_ep["hosts"] == ["api.local"]
