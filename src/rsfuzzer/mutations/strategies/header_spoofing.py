from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.types import MutationTrace


class HeaderSpoofingStrategy:
    """
    Trust-boundary header tampering (complements AuthSessionStrategy JWT/cookie focus):
    impersonation IDs, tenant overrides, forged internal service headers.
    """

    id = "header_spoofing"
    category = "header_spoofing"

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
        variants: list[tuple[str, str]] = [
            ("X-User-Id", "admin"),
            ("X-User-Id", "0"),
            ("X-User-Id", "999999"),
            ("X-Remote-User", "admin"),
            ("X-Auth-Request-Email", "admin@example.com"),
            ("X-Role", "admin"),
            ("X-Tenant-Id", "system"),
            ("X-Account-Id", "00000000-0000-0000-0000-000000000001"),
            ("X-Service-Token", "internal"),
            ("X-Internal-Auth", "true"),
            ("X-Debug", "1"),
            ("Api-Key", "sk_live_admin_placeholder"),
            ("X-Api-Key", "bypass"),
        ]
        if self._light:
            variants = variants[:7]
        for name, val in variants:
            h = dict(headers)
            h[name] = val
            yield h, MutationTrace(self.id, self.category, {"header": name})
        h2 = dict(headers)
        h2["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiJ9.e30.admin_sig"
        yield h2, MutationTrace(self.id, self.category, {"mode": "bearer_opaque"})
        if not self._light:
            h3 = dict(headers)
            h3["Authorization"] = "Basic YWRtaW46YWRtaW4="
            yield h3, MutationTrace(self.id, self.category, {"mode": "basic_admin"})
