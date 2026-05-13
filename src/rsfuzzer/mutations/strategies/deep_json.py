from __future__ import annotations

import copy
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _nest(depth: int, leaf: Any) -> Any:
    cur: Any = leaf
    for _ in range(depth):
        cur = {"child": cur}
    return cur


class DeepJsonStrategy:
    """Parameterized deep trees — depth/width from small caps, not one giant blob."""

    id = "deep_json"
    category = "deep_nesting"

    def __init__(self, depths: tuple[int, ...] = (32, 64, 128), branch: int = 2) -> None:
        self.depths = depths
        self.branch = max(1, branch)

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {"seed": True}
        for d in self.depths:
            deep = _nest(d, {"leaf": "x"})
            merged = _merge_body(base, {"_deep": deep})
            trace = MutationTrace(self.id, self.category, {"depth": d})
            yield merged, trace

        wide = base
        for i in range(self.branch):
            wide = {f"k{i}": wide}
        trace = MutationTrace(
            self.id,
            self.category,
            {"branching": self.branch, "note": "recursive_shape"},
        )
        yield wide, trace

        if body:
            layered = copy.deepcopy(body)
            # JSON-serializable stand-in for a self-referential object (true cycles break json.dumps).
            layered["_self"] = {"$ref": "#"}
            trace = MutationTrace(self.id, self.category, {"shape": "self_ref_placeholder"})
            yield layered, trace

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
