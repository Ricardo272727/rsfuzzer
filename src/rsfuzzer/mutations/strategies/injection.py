from __future__ import annotations

from typing import Any
from typing import Callable
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _named_templates() -> Iterator[tuple[str, Callable[[str], str]]]:
    yield "sqli_or_eq", lambda m: f"' OR '{m}'='{m}"
    yield "sqli_or_dq", lambda m: f"\" OR \"{m}\"=\"{m}"
    yield "sqli_waitfor", lambda m: f"'; WAITFOR DELAY '0:0:{m}'--"
    yield "ssti_mustache", lambda m: f"{{{{{m}}}}}"
    yield "ssti_dollar", lambda m: f"${{{m}}}"
    yield "sqli_tautology", lambda _m: "' OR 1=1--"
    yield "sqli_drop", lambda m: f"'; DROP TABLE {m}--"
    yield "nosql_gt", lambda _m: '{"$gt": ""}'
    yield "nosql_ne", lambda _m: '{"$ne": null}'
    yield "cmd_pipe", lambda m: f"| {m}"
    yield "cmd_backtick", lambda m: f"`{m}`"
    yield "cmd_dollar", lambda m: f"$({m})"
    yield "path_unix", lambda m: f"../{m}"
    yield "path_win", lambda m: f"..\\{m}"
    yield "mssql_shell", lambda m: f"'; exec xp_cmdshell '{m}'--"
    yield "ldap_or", lambda m: f"*)(uid=*))(|(uid=*"


def _markers() -> Iterator[str]:
    for i in range(8):
        yield f"m{i}"
    yield "x"
    yield "admin"


class InjectionStrategy:
    id = "injection"
    category = "injection"

    def __init__(
        self,
        inject_key: str = "_injection",
        *,
        max_templates: int | None = None,
        max_markers: int | None = None,
    ) -> None:
        self.inject_key = inject_key
        self.max_templates = max_templates
        self.max_markers = max_markers

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        tpls = list(_named_templates())
        if self.max_templates is not None:
            tpls = tpls[: self.max_templates]
        markers = list(_markers())
        if self.max_markers is not None:
            markers = markers[: self.max_markers]
        for tname, fn in tpls:
            for marker in markers:
                payload = fn(marker)
                merged = _merge_body(base, {self.inject_key: payload})
                trace = MutationTrace(
                    self.id,
                    self.category,
                    {"template": tname, "marker": marker},
                )
                yield merged, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        tpls = list(_named_templates())[:8]
        if self.max_templates is not None:
            tpls = tpls[: self.max_templates]
        markers = ("1", "x")
        if self.max_markers is not None:
            markers = tuple(list(markers)[: self.max_markers])
        for tname, fn in tpls:
            for marker in markers:
                q = dict(query)
                q["_q"] = fn(marker)
                trace = MutationTrace(self.id, self.category, {"template": tname, "marker": marker})
                yield q, trace

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()


def narrow_injection_around(
    base_payload: str,
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
    radius: int = 8,
) -> Iterator[str]:
    """Local search around an interesting payload (hook for heuristic depth)."""
    yield base_payload
    for c in charset[:radius]:
        yield base_payload + c
        yield c + base_payload
