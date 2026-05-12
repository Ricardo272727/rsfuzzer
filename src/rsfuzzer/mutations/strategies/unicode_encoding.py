from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _transforms(s: str) -> Iterator[tuple[str, str]]:
    yield "null_byte", s + "\x00"
    yield "crlf_inject", s + "\r\nX-Injected: 1"
    yield "bom_prefix", "\ufeff" + s
    yield "rtl", "\u202e" + s
    yield "homoglyph_a", s.replace("a", "а") if "a" in s else s + "а"
    yield "double_encode", s.replace("'", "%2527") if "'" in s else s + "%2527"


class UnicodeEncodingStrategy:
    id = "unicode_encoding"
    category = "unicode_encoding"

    def __init__(self, target_key: str = "_fuzz") -> None:
        self.target_key = target_key

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        seed = next(iter(base.values()), "test") if base else "test"
        seed_s = seed if isinstance(seed, str) else repr(seed)
        for tname, out in _transforms(seed_s):
            merged = _merge_body(base, {self.target_key: out})
            trace = MutationTrace(self.id, self.category, {"transform": tname})
            yield merged, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for k, v in list(query.items())[:2]:
            for tname, out in _transforms(v):
                q = dict(query)
                q[k] = out
                trace = MutationTrace(self.id, self.category, {"key": k, "transform": tname})
                yield q, trace

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for hk in list(headers.keys())[:2]:
            v = headers[hk]
            for tname, out in _transforms(v):
                h = dict(headers)
                h[hk] = out
                trace = MutationTrace(self.id, self.category, {"header": hk, "transform": tname})
                yield h, trace
