from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from rsfuzzer.profiles import load_profile
from rsfuzzer.testing import HttpResult
from rsfuzzer.testing import fixture_body
from rsfuzzer.testing import run_catalog_scan


@patch("rsfuzzer.testing.http_request")
def test_catalog_scan_mutation_pass_per_role_budget(mock_http: object, tmp_path: Path) -> None:
    mock_http.return_value = HttpResult(200, "ok")
    profile_file = tmp_path / "p.yaml"
    profile_file.write_text(
        """
base_url: http://127.0.0.1
roles:
  a:
    headers:
      x: "1"
  b:
    headers:
      x: "2"
fixtures: {}
""".strip(),
        encoding="utf-8",
    )
    profile = load_profile(profile_file)
    catalog = {
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/items",
                "path_params": [],
                "query_params": [],
            }
        ]
    }
    rows, _ = run_catalog_scan(
        profile,
        catalog,
        ("a", "b"),
        "*",
        mutate_max=2,
        mutate_light=True,
        mutate_parts=("headers",),
    )
    assert mock_http.call_count == 2 + 2 * 2
    assert len(rows) == mock_http.call_count
    assert sum(1 for r in rows if r.from_mutations) == 4
    assert all(r.mutation_traces for r in rows if r.from_mutations)


@patch("rsfuzzer.testing.http_request")
def test_catalog_scan_body_fuzzes_post_and_patch(mock_http: object, tmp_path: Path) -> None:
    mock_http.return_value = HttpResult(200, "ok")
    profile_file = tmp_path / "p.yaml"
    profile_file.write_text(
        """
base_url: http://127.0.0.1
roles:
  a:
    headers: { x-user-id: u1 }
  b:
    headers: { x-user-id: u2 }
fixtures:
  path_params:
    id: "101"
  bodies:
    "/api/orders":
      total: 50
    "/api/orders/{id}/status":
      status: draft
""".strip(),
        encoding="utf-8",
    )
    profile = load_profile(profile_file)
    catalog = {
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/orders",
                "path_params": [],
                "query_params": [],
            },
            {
                "method": "PATCH",
                "path": "/api/orders/{id}/status",
                "path_params": ["id"],
                "query_params": [],
            },
        ]
    }
    rows, _ = run_catalog_scan(
        profile,
        catalog,
        ("a", "b"),
        "*",
        mutate_max=3,
        mutate_light=True,
        mutate_parts=("body",),
    )
    # 2 endpoints × 2 roles baseline + 2 × 2 × 3 mutations
    assert mock_http.call_count == 4 + 12
    mutation_rows = [r for r in rows if r.from_mutations]
    assert len(mutation_rows) == 12
    assert {r.method for r in rows} == {"POST", "PATCH"}

    bodies_sent = [call.args[3] for call in mock_http.call_args_list if call.args[3] is not None]
    assert bodies_sent
    assert any("total" in b or "_boundary" in b or "__proto__" in str(b) for b in bodies_sent)
    assert any("status" in b or "owner" in str(b).lower() or "_injection" in b for b in bodies_sent)


def test_fixture_body_prefers_profile_over_default(tmp_path: Path) -> None:
    profile_file = tmp_path / "p.yaml"
    profile_file.write_text(
        """
base_url: http://127.0.0.1
roles:
  a:
    headers: {}
fixtures:
  bodies:
    "/api/orders/{id}/status":
      status: cancelled
""".strip(),
        encoding="utf-8",
    )
    profile = load_profile(profile_file)
    assert fixture_body(profile, "/api/orders/{id}/status", "PATCH") == {"status": "cancelled"}
