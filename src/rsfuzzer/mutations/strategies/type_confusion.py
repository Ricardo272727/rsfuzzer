from __future__ import annotations

import copy
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.types import MutationTrace


def _alternatives_for_scalar(value: Any) -> Iterator[Any]:
    t = type(value)
    if t is bool:
        yield from (0, 1, "true", "false", [], {})
        return
    if t is int:
        yield from (str(value), float(value), [value], {str(value): 1}, None, "")
        return
    if t is float:
        yield from (str(value), int(value) if value == int(value) else value, [value], None)
        return
    if t is str:
        yield from (len(value), [value], {value: 1}, None, 0, [])
        return
    if value is None:
        yield from ("", 0, [], {}, "null")
        return
    yield from (None, str(value), repr(value))


def _mutate_leaves(obj: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[Any, MutationTrace]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = path + (k,)
            for alt in _alternatives_for_scalar(v):
                clone = copy.deepcopy(obj)
                clone[k] = alt
                trace = MutationTrace(
                    "type_confusion",
                    "type_confusion",
                    {"path": list(new_path), "original_type": type(v).__name__},
                )
                yield clone, trace
            yield from _mutate_leaves(v, new_path)
    elif isinstance(obj, list) and obj:
        for i, item in enumerate(obj[:3]):
            for alt in _alternatives_for_scalar(item):
                clone = copy.deepcopy(obj)
                clone[i] = alt
                trace = MutationTrace(
                    "type_confusion",
                    "type_confusion",
                    {"path": list(path) + [f"[{i}]"], "original_type": type(item).__name__},
                )
                yield clone, trace


class TypeConfusionStrategy:
    id = "type_confusion"
    category = "type_confusion"

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        if not body:
            for alt in _alternatives_for_scalar(1):
                trace = MutationTrace(self.id, self.category, {"synthetic_key": "value"})
                yield {"value": alt}, trace
            return
        yield from _mutate_leaves(body)

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for k, v in list(query.items())[:5]:
            for alt in (v, str(v), "[]", "{}", "null", "true", "0"):
                q = dict(query)
                q[k] = str(alt)
                trace = MutationTrace(self.id, self.category, {"key": k})
                yield q, trace

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()
