from __future__ import annotations

from rsfuzzer.mutations import MutationCase
from rsfuzzer.mutations import MutationEngine
from rsfuzzer.mutations import MutatedRequest
from rsfuzzer.mutations import MutationTrace
from rsfuzzer.mutations import expand_around_interest
from rsfuzzer.mutations import permute_case
from rsfuzzer.mutations.registry import default_strategies
from rsfuzzer.mutations.strategies.injection import InjectionStrategy
from rsfuzzer.mutations.strategies.prototype_pollution import PrototypePollutionStrategy


def test_permute_case_emits_traces_with_light_mode() -> None:
    case = MutationCase(
        method="POST",
        path="/api/orders",
        base_body={"total": 1},
    )
    out = list(permute_case(case, light=True, max_variants=80, parts=("body",)))
    assert len(out) >= 5
    assert all(isinstance(m, MutatedRequest) for m in out)
    assert all(m.traces and m.traces[0].strategy_id for m in out)


def test_injection_strategy_is_parametric_not_single_string() -> None:
    strat = InjectionStrategy(max_templates=2, max_markers=2)
    payloads = [p for p, _ in strat.mutate_body({"x": 1})]
    assert len(payloads) == 4
    assert any("__proto__" not in str(p) for p in payloads)


def test_prototype_pollution_generates_key_product() -> None:
    strat = PrototypePollutionStrategy()
    items = list(strat.mutate_body({"a": 1}))
    keys = {t.detail.get("overlay_key") for _, t in items}
    assert "__proto__" in keys
    assert "constructor" in keys


def test_expand_around_interest_injection() -> None:
    case = MutationCase("POST", "/x", base_body={"q": 1})
    anchor = MutatedRequest(
        method="POST",
        path="/x",
        headers={},
        query={},
        body={"q": 1},
        traces=(MutationTrace("t", "c", {}),),
    )
    out = list(
        expand_around_interest(
            case,
            anchor,
            {"category": "injection", "payload_hint": "OR", "focus_key": "_injection"},
            light=True,
        )
    )
    assert len(out) >= 1
    assert any("_injection" in (m.body or {}) for m in out)


def test_engine_respects_max_variants() -> None:
    eng = MutationEngine([PrototypePollutionStrategy()], max_variants=3)
    case = MutationCase("POST", "/x", base_body={})
    assert len(list(eng.expand(case, parts=("body",)))) <= 3
