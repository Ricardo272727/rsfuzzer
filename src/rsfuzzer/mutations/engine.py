from __future__ import annotations

from typing import Any
from typing import Iterator
from typing import Sequence

from rsfuzzer.mutations.registry import default_strategies
from rsfuzzer.mutations.strategies.injection import narrow_injection_around
from rsfuzzer.mutations.types import MutationCase
from rsfuzzer.mutations.types import MutatedRequest
from rsfuzzer.mutations.types import MutationTrace


class MutationEngine:
    """
    Drives strategies over an entire request template (body, query, headers).
    One variant = one axis mutated at a time (single trace) unless you compose manually.
    """

    def __init__(
        self,
        strategies: Sequence[Any],
        *,
        max_variants: int = 50_000,
    ) -> None:
        self.strategies = list(strategies)
        self.max_variants = max_variants

    def expand(
        self,
        case: MutationCase,
        *,
        parts: tuple[str, ...] = ("body", "query", "headers"),
    ) -> Iterator[MutatedRequest]:
        n = 0
        for strat in self.strategies:
            if n >= self.max_variants:
                return
            if "body" in parts:
                for new_body, tr in strat.mutate_body(case.base_body):
                    if n >= self.max_variants:
                        return
                    yield MutatedRequest(
                        method=case.method,
                        path=case.path,
                        headers=dict(case.base_headers),
                        query=dict(case.base_query),
                        body=new_body,
                        traces=(tr,),
                    )
                    n += 1
            if "query" in parts:
                for new_q, tr in strat.mutate_query(case.base_query):
                    if n >= self.max_variants:
                        return
                    yield MutatedRequest(
                        method=case.method,
                        path=case.path,
                        headers=dict(case.base_headers),
                        query=new_q,
                        body=dict(case.base_body) if case.base_body is not None else None,
                        traces=(tr,),
                    )
                    n += 1
            if "headers" in parts:
                for new_h, tr in strat.mutate_headers(case.base_headers):
                    if n >= self.max_variants:
                        return
                    yield MutatedRequest(
                        method=case.method,
                        path=case.path,
                        headers=new_h,
                        query=dict(case.base_query),
                        body=dict(case.base_body) if case.base_body is not None else None,
                        traces=(tr,),
                    )
                    n += 1

    def expand_around_interest(
        self,
        case: MutationCase,
        anchor: MutatedRequest,
        signals: dict[str, Any],
    ) -> Iterator[MutatedRequest]:
        """
        Second-phase mutations when a heuristic flags an interesting response.
        `signals` may include: status_code, body_snippet, category, focus_key, payload_hint.
        """
        category = signals.get("category", "")
        if category == "injection" or signals.get("deepen_injection"):
            hint = signals.get("payload_hint") or ""
            if isinstance(hint, str) and hint:
                for p in narrow_injection_around(hint):
                    body = dict(case.base_body) if case.base_body else {}
                    key = str(signals.get("focus_key") or "_injection")
                    body[key] = p
                    trace = MutationTrace(
                        "engine",
                        "interest_expansion",
                        {"phase": "injection_narrow", "around": hint[:80]},
                    )
                    yield MutatedRequest(
                        method=case.method,
                        path=case.path,
                        headers=dict(anchor.headers),
                        query=dict(anchor.query),
                        body=body,
                        traces=anchor.traces + (trace,),
                    )
        if category == "ssrf" or signals.get("deepen_ssrf"):
            from rsfuzzer.mutations.strategies.ssrf import SsrfStrategy

            strat = SsrfStrategy(light=False)
            for new_body, tr in strat.mutate_body(case.base_body):
                yield MutatedRequest(
                    method=case.method,
                    path=case.path,
                    headers=dict(anchor.headers),
                    query=dict(anchor.query),
                    body=new_body,
                    traces=anchor.traces + (tr,),
                )
        if category == "mass_assignment" or signals.get("deepen_mass_assignment"):
            from rsfuzzer.mutations.strategies.mass_assignment import MassAssignmentStrategy

            strat = MassAssignmentStrategy(light=False)
            for new_body, tr in strat.mutate_body(case.base_body):
                yield MutatedRequest(
                    method=case.method,
                    path=case.path,
                    headers=dict(anchor.headers),
                    query=dict(anchor.query),
                    body=new_body,
                    traces=anchor.traces + (tr,),
                )
        if signals.get("deepen_json"):
            depth = int(signals.get("json_depth", 64))
            from rsfuzzer.mutations.strategies.deep_json import DeepJsonStrategy

            strat = DeepJsonStrategy(depths=(depth, depth * 2))
            for new_body, tr in strat.mutate_body(case.base_body):
                yield MutatedRequest(
                    method=case.method,
                    path=case.path,
                    headers=dict(anchor.headers),
                    query=dict(anchor.query),
                    body=new_body,
                    traces=anchor.traces + (tr,),
                )
                return


def permute_case(
    case: MutationCase,
    *,
    light: bool = False,
    max_variants: int = 50_000,
    parts: tuple[str, ...] = ("body", "query", "headers"),
) -> Iterator[MutatedRequest]:
    engine = MutationEngine(default_strategies(light=light), max_variants=max_variants)
    yield from engine.expand(case, parts=parts)


def expand_around_interest(
    case: MutationCase,
    anchor: MutatedRequest,
    signals: dict[str, Any],
    *,
    light: bool = False,
) -> Iterator[MutatedRequest]:
    eng = MutationEngine(default_strategies(light=light), max_variants=5_000)
    yield from eng.expand_around_interest(case, anchor, signals)
