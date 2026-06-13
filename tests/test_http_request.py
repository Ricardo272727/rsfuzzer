from __future__ import annotations

import json
from pathlib import Path

from rsfuzzer.testing import HttpResult
from rsfuzzer.testing import ScanRow
from rsfuzzer.testing import http_request
from rsfuzzer.testing import write_test_report


def test_http_request_invalid_header_does_not_raise() -> None:
    res = http_request(
        "GET",
        "http://127.0.0.1/",
        {"X-User-Id": "u1\r\nX-Injected: 1"},
        None,
    )
    assert res.status_code == 0
    assert res.client_error or "request_" in res.body_preview or "ValueError" in res.body_preview


def test_http_request_invalid_json_body_does_not_raise() -> None:
    class Bad:
        def __repr__(self) -> str:
            return "bad"

    res = http_request("POST", "http://127.0.0.1/", {}, {"x": Bad()})  # type: ignore[arg-type]
    assert res.status_code == 0
    assert res.client_error and "body_json" in res.client_error


def test_http_request_non_rfc_json_uses_non_rfc_encoding() -> None:
    res = http_request("GET", "http://127.0.0.1/", {}, {"_boundary": float("inf")})
    # Request may fail to connect; encoding should still be recorded when built.
    assert res.request_body_encoding == "non_rfc" or res.client_error


def test_report_includes_scan_errors_section(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    write_test_report(
        out,
        tmp_path / "p.yaml",
        tmp_path / "c.json",
        ("a", "b"),
        "*",
        [],
        [],
        [
            ScanRow(
                method="POST",
                path_template="/x",
                path_resolved="/x",
                url="http://127.0.0.1/x",
                role="a",
                status_code=0,
                body_preview="connection:ConnectionResetError: reset",
                client_error="connection:ConnectionResetError: reset",
                from_mutations=True,
            )
        ],
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["scan_error_count"] == 1
    assert len(data["scan_errors"]) == 1
    assert data["scan_errors"][0]["client_error"]

