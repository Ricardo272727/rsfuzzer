from __future__ import annotations

import re
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.types import MutationTrace

_ID_KEY = re.compile(
    r"(^|_)(id|uuid|uid|user|account|owner|order|resource|tenant|org)(_|$)",
    re.IGNORECASE,
)


def _is_id_key(key: str) -> bool:
    return bool(_ID_KEY.search(key)) or key.lower() in {"id", "uuid", "sub"}


def _neighbor_values(value: Any, *, light: bool) -> Iterator[Any]:
    if isinstance(value, bool):
        yield not value
        return
    if isinstance(value, int):
        for delta in (0, 1, -1, 2, -2)[: (3 if light else 5)]:
            yield value + delta
        yield 0
        yield 2**31 - 1
        if not light:
            yield -(2**31)
        return
    if isinstance(value, float):
        yield value + 1.0
        yield int(value)
        return
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            n = int(s)
            for delta in (1, -1)[: (1 if light else 2)]:
                yield str(n + delta)
            yield "0" * max(1, len(s)) + s if len(s) < 12 else s + "0"
            if not light:
                yield str(n + 10_000)
                yield f"{n:016d}"
            return
        if len(s) == 36 and s.count("-") == 4:
            tail = s[-12:]
            alt = s[:-12] + ("0" * 8 + "0001")[-12:]
            yield alt
            if not light:
                yield "00000000-0000-0000-0000-000000000000"
        yield s + "_bypass"
        yield ""
        if not light:
            yield "null"
            yield "undefined"


def _mutate_mapping(
    mapping: dict[str, Any],
    *,
    light: bool,
) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
    keys = [k for k in mapping if _is_id_key(str(k))]
    cap = 3 if light else 6
    for key in keys[:cap]:
        raw = mapping[key]
        for alt in _neighbor_values(raw, light=light):
            if alt is None:
                continue
            clone = dict(mapping)
            clone[key] = alt
            trace = MutationTrace(
                "id_boundary",
                "horizontal_escalation",
                {"key": key, "original": repr(raw)[:80], "mutated": repr(alt)[:80]},
            )
            yield clone, trace


class IdBoundaryStrategy:
    """Horizontal IDOR-style probes: neighbor IDs, UUID and integer edges on id-like keys."""

    id = "id_boundary"
    category = "horizontal_escalation"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        if not body:
            trace = MutationTrace(self.id, self.category, {"synthetic": "user_id"})
            yield {"user_id": "2"}, trace
            return
        yield from _mutate_mapping(dict(body), light=self._light)

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for new_q, tr in _mutate_mapping({k: v for k, v in query.items()}, light=self._light):
            yield {k: str(v) for k, v in new_q.items()}, tr

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for new_h, tr in _mutate_mapping({k: v for k, v in headers.items()}, light=self._light):
            yield {k: str(v) for k, v in new_h.items()}, tr
