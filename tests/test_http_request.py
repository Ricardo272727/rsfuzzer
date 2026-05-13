from __future__ import annotations

from rsfuzzer.testing import http_request


def test_http_request_invalid_header_does_not_raise() -> None:
    res = http_request(
        "GET",
        "http://127.0.0.1/",
        {"X-User-Id": "u1\r\nX-Injected: 1"},
        None,
    )
    assert res.status_code == 0
    assert "request_" in res.body_preview or "client_error" in res.body_preview or "ValueError" in res.body_preview


def test_http_request_invalid_json_body_does_not_raise() -> None:
    class Bad:
        def __repr__(self) -> str:
            return "bad"

    res = http_request("POST", "http://127.0.0.1/", {}, {"x": Bad()})  # type: ignore[arg-type]
    assert res.status_code == 0
    assert "body_json" in res.body_preview or "TypeError" in res.body_preview
