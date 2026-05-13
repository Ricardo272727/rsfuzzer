from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.types import MutationTrace


def _forwarded_variants(*, light: bool) -> Iterator[tuple[str, str]]:
    base = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Forwarded-For", "::1"),
        ("X-Forwarded-For", "10.0.0.1, 198.51.100.2"),
        ("X-Real-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("Client-IP", "10.0.0.5"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Cluster-Client-IP", "127.0.0.1"),
        ("Forwarded", "for=192.0.2.1;proto=https"),
        ("X-Forwarded-Host", "localhost"),
        ("X-Custom-Bypass-Rate-Limit", "1"),
        ("X-RateLimit-Bypass", "true"),
    ]
    for pair in base[: (5 if light else len(base))]:
        yield pair


class RateLimitBypassStrategy:
    """Headers that sometimes influence IP-based or header-trust rate limiting."""

    id = "rate_limit_bypass"
    category = "rate_limit"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        yield from ()

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for i in range(1, (4 if self._light else 9)):
            h = dict(headers)
            h["X-Forwarded-For"] = f"10.0.0.{i}"
            yield h, MutationTrace(self.id, self.category, {"mode": "incremental_spoof_ip", "i": i})
        for name, val in _forwarded_variants(light=self._light):
            h = dict(headers)
            h[name] = val
            yield h, MutationTrace(self.id, self.category, {"header": name, "value_preview": val[:40]})
