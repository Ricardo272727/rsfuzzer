from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from rsfuzzer.testing import HttpResult
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
    from rsfuzzer.profiles import load_profile

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
