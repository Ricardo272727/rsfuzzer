from __future__ import annotations

import sys
from typing import Any
from typing import Callable
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _numeric_edge_factory() -> Iterator[int | float]:
    yield 0
    yield -1
    yield 1
    yield 255
    yield 256
    yield sys.maxsize
    yield -sys.maxsize - 1
    yield 2**31 - 1
    yield -(2**31)
    yield float("inf")
    yield float("-inf")


def _string_edge_factory() -> Iterator[str]:
    yield ""
    yield " "
    yield "0"
    yield "-1"
    yield "2147483647"
    yield "9223372036854775807"


class BoundaryStrategy:
    id = "boundaries"
    category = "boundary_values"

    def __init__(
        self,
        inject_key: str = "_boundary",
        numeric_gen: Callable[[], Iterator[int | float]] | None = None,
        string_gen: Callable[[], Iterator[str]] | None = None,
    ) -> None:
        self.inject_key = inject_key
        self._numeric_gen = numeric_gen or _numeric_edge_factory
        self._string_gen = string_gen or _string_edge_factory

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        for n in self._numeric_gen():
            m = _merge_body(base, {self.inject_key: n})
            trace = MutationTrace(self.id, self.category, {"value": repr(n)})
            yield m, trace
        for s in self._string_gen():
            m = _merge_body(base, {self.inject_key: s})
            trace = MutationTrace(self.id, self.category, {"value": s})
            yield m, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for k in list(query.keys())[:3] or ["x"]:
            for v in ("", "-1", "0", "999999999999999999", "2147483648"):
                q = dict(query)
                q[k] = v
                trace = MutationTrace(self.id, self.category, {"key": k, "value": v})
                yield q, trace

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()
