from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


class ResourceExhaustionStrategy:
    id = "resource_exhaustion"
    category = "resource_exhaustion"

    def __init__(
        self,
        array_lengths: tuple[int, ...] = (1000, 10_000),
        string_lengths: tuple[int, ...] = (10_000, 50_000),
        repeat_unit: str = "A",
    ) -> None:
        self.array_lengths = array_lengths
        self.string_lengths = string_lengths
        self.repeat_unit = repeat_unit

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        for n in self.array_lengths:
            merged = _merge_body(base, {"_huge_array": [0] * min(n, 50_000)})
            trace = MutationTrace(self.id, self.category, {"array_len": n})
            yield merged, trace
        for n in self.string_lengths:
            s = self.repeat_unit * min(n, 100_000)
            merged = _merge_body(base, {"_huge_string": s})
            trace = MutationTrace(self.id, self.category, {"string_len": len(s)})
            yield merged, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()
