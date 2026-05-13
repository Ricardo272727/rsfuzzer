from __future__ import annotations

import copy
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.types import MutationTrace


class ParameterPollutionStrategy:
    """
    Duplicate / conflicting parameter shapes. Query is dict-shaped here; we simulate
    HPP via composite values and PHP-style bracket keys for parsers that merge oddly.
    """

    id = "parameter_pollution"
    category = "parameter_pollution"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        if not body:
            return
        items = list(body.items())[: (3 if self._light else 8)]
        for k, v in items:
            if isinstance(v, (dict, list)):
                continue
            clone = copy.deepcopy(dict(body))
            clone[k] = [v, "polluted_second"]
            trace = MutationTrace(
                self.id,
                self.category,
                {"mode": "array_duplicate", "key": k},
            )
            yield clone, trace
            clone2 = copy.deepcopy(dict(body))
            clone2[f"{k}[]"] = v
            clone2[k] = "primary"
            trace2 = MutationTrace(
                self.id,
                self.category,
                {"mode": "bracket_shadow", "key": k},
            )
            yield clone2, trace2

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        keys = list(query.keys())[: (2 if self._light else 5)]
        if not keys:
            q = dict(query)
            q["id"] = "1&id=2"
            yield q, MutationTrace(self.id, self.category, {"mode": "synthetic_hpp_value"})
            return
        for k in keys:
            v = query[k]
            q = dict(query)
            q[k] = f"{v}&{k}=__hpp_second__"
            yield q, MutationTrace(self.id, self.category, {"mode": "ampersand_in_value", "key": k})
            q2 = dict(query)
            q2[f"{k}[]"] = "__alt__"
            yield q2, MutationTrace(self.id, self.category, {"mode": "php_array_key", "key": k})
            if not self._light:
                q3 = dict(query)
                q3[k] = f"{v},{v},__dup__"
                yield q3, MutationTrace(self.id, self.category, {"mode": "csv_repeat", "key": k})

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for name in ("Content-Type", "Accept"):
            if name not in headers:
                continue
            h = dict(headers)
            h[name] = f"{h[name]}, {h[name]}; boundary=polluted"
            yield h, MutationTrace(self.id, self.category, {"mode": "duplicate_header_value", "name": name})
            if self._light:
                break
