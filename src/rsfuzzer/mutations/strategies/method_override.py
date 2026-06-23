from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace

# Headers frameworks honor to rewrite the effective HTTP verb.
_OVERRIDE_HEADERS = (
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-Method",
)

# Verbs worth smuggling: state-changing ones an authz layer may only guard on the
# original method, plus odd verbs proxies/WAFs route inconsistently.
_VERBS = ("DELETE", "PUT", "PATCH", "GET", "HEAD", "POST", "TRACE", "PURGE")


class MethodOverrideStrategy:
    """
    HTTP verb tampering for Broken Function Level Authorization (OWASP API5).
    Many stacks authorize on the wire method but dispatch on an override header,
    `_method` param, or body field, letting a permitted verb act as a forbidden one.
    """

    id = "method_override"
    category = "method_override"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def _verbs(self) -> tuple[str, ...]:
        return _VERBS[:4] if self._light else _VERBS

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        for verb in self._verbs():
            for key in ("_method", "_http_method"):
                merged = _merge_body(base, {key: verb})
                yield merged, MutationTrace(
                    self.id, self.category, {"field": key, "verb": verb}
                )
                if self._light:
                    break

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for verb in self._verbs():
            for key in ("_method", "_http_method"):
                q = dict(query)
                q[key] = verb
                yield q, MutationTrace(self.id, self.category, {"param": key, "verb": verb})
                if self._light:
                    break

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        names = _OVERRIDE_HEADERS[:2] if self._light else _OVERRIDE_HEADERS
        for name in names:
            for verb in self._verbs():
                h = dict(headers)
                h[name] = verb
                yield h, MutationTrace(self.id, self.category, {"header": name, "verb": verb})
