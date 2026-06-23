from __future__ import annotations

import re
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace

_REDIRECT_KEY = re.compile(
    r"(redirect|return|next|continue|callback|dest|destination|forward|"
    r"goto|go|target|success|cancel|back|ref|out|url|link|location|to)",
    re.IGNORECASE,
)

_EVIL = "evil.example.com"


def _is_redirect_key(key: str) -> bool:
    return bool(_REDIRECT_KEY.search(key))


def _redirect_payloads(*, light: bool) -> Iterator[tuple[str, str]]:
    """
    Open-redirect / URL-validation bypass payloads. These exploit lax parsers that
    treat scheme-relative, backslash, or userinfo forms as same-origin.
    """
    core: list[tuple[str, str]] = [
        ("scheme_relative", f"//{_EVIL}"),
        ("absolute_https", f"https://{_EVIL}"),
        ("backslash_confuse", f"/\\{_EVIL}"),
        ("scheme_no_slash", f"https:{_EVIL}"),
        ("userinfo_trick", f"https://expected.example.com@{_EVIL}"),
        ("double_slash_encoded", f"%2f%2f{_EVIL}"),
    ]
    extra: list[tuple[str, str]] = [
        ("backslash_pair", f"\\/\\/{_EVIL}"),
        ("whitespace_prefix", f"/%09/{_EVIL}"),
        ("triple_slash", f"///{_EVIL}"),
        ("subdomain_confuse", f"https://expected.example.com.{_EVIL}"),
        ("at_after_path", f"https://{_EVIL}/expected.example.com"),
        ("javascript_scheme", "javascript:alert(document.domain)"),
        ("data_scheme", "data:text/html,<script>alert(1)</script>"),
        ("crlf_in_redirect", f"https://{_EVIL}%0d%0aSet-Cookie:x=1"),
        ("loopback_redirect", "http://127.0.0.1/"),
    ]
    for name, payload in (core if light else core + extra):
        yield name, payload


class OpenRedirectStrategy:
    """
    Open redirect probes on redirect/return-style fields. Overlaps usefully with
    SSRF (server-side fetch of attacker URL) and with auth flows that bounce back
    to a client-supplied location after login.
    """

    id = "open_redirect"
    category = "open_redirect"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        payloads = list(_redirect_payloads(light=self._light))
        for name, payload in payloads:
            merged = _merge_body(base, {"_redirect": payload})
            yield merged, MutationTrace(
                self.id, self.category, {"inject_key": "_redirect", "probe": name}
            )
        if body:
            keys = [k for k in body if _is_redirect_key(str(k))]
            for key in keys[: (1 if self._light else 3)]:
                for name, payload in payloads[: (3 if self._light else 6)]:
                    clone = dict(body)
                    clone[key] = payload
                    yield clone, MutationTrace(
                        self.id, self.category, {"key": key, "probe": name}
                    )

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        payloads = list(_redirect_payloads(light=self._light))
        keys = [k for k in query if _is_redirect_key(str(k))]
        if not keys:
            for name, payload in payloads:
                q = dict(query)
                q["redirect"] = payload
                yield q, MutationTrace(
                    self.id, self.category, {"param": "redirect", "probe": name}
                )
            return
        for key in keys[: (2 if self._light else 4)]:
            for name, payload in payloads:
                q = dict(query)
                q[key] = payload
                yield q, MutationTrace(self.id, self.category, {"param": key, "probe": name})

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()
