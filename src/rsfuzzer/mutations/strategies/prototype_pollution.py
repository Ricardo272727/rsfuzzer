from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _dangerous_key_variants() -> Iterator[str]:
    yield "__proto__"
    yield "constructor"
    yield "prototype"
    yield "__proto"
    yield "constructor.prototype"


def _payload_shapes() -> Iterator[dict[str, Any]]:
    yield {"polluted": True}
    yield {"isAdmin": True}
    yield {"role": "admin"}
    yield {"enabled": 1}


class PrototypePollutionStrategy:
    id = "prototype_pollution"
    category = "prototype_pollution"

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        for key in _dangerous_key_variants():
            for inner in _payload_shapes():
                overlay = {key: inner}
                merged = _merge_body(body, overlay)
                trace = MutationTrace(
                    self.id,
                    self.category,
                    {"overlay_key": key, "inner_keys": list(inner.keys())},
                )
                yield merged, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for key in ("__proto__", "constructor", "prototype"):
            q = dict(query)
            q[key] = "1"
            trace = MutationTrace(self.id, self.category, {"query_key": key})
            yield q, trace

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()
