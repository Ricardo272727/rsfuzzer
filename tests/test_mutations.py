from __future__ import annotations

from rsfuzzer.mutations import MutationCase
from rsfuzzer.mutations import MutationEngine
from rsfuzzer.mutations import MutatedRequest
from rsfuzzer.mutations import MutationTrace
from rsfuzzer.mutations import expand_around_interest
from rsfuzzer.mutations import permute_case
from rsfuzzer.mutations.registry import default_strategies
from rsfuzzer.mutations.strategies.injection import InjectionStrategy
from rsfuzzer.mutations.strategies.mass_assignment import MassAssignmentStrategy
from rsfuzzer.mutations.strategies.method_override import MethodOverrideStrategy
from rsfuzzer.mutations.strategies.open_redirect import OpenRedirectStrategy
from rsfuzzer.mutations.strategies.prototype_pollution import PrototypePollutionStrategy
from rsfuzzer.mutations.strategies.ssrf import SsrfStrategy


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


def test_ssrf_targets_url_keys_and_metadata_endpoints() -> None:
    strat = SsrfStrategy()
    bodies = [b for b, _ in strat.mutate_body({"image_url": "http://ok.example.com/a.png"})]
    # The url-like key must be overwritten with an internal/metadata destination.
    assert any(b.get("image_url") == "http://169.254.169.254/latest/meta-data/" for b in bodies)
    # And a synthetic probe key is always added for endpoints without url fields.
    assert any("_url" in b for b in bodies)
    headers = [h for h, _ in strat.mutate_headers({})]
    assert any(h.get("X-Forwarded-Host") == "169.254.169.254" for h in headers)


def test_mass_assignment_overlays_protected_fields() -> None:
    strat = MassAssignmentStrategy()
    items = list(strat.mutate_body({"name": "alice"}))
    bodies = [b for b, _ in items]
    assert any(b.get("is_admin") is True for b in bodies)
    assert any(b.get("balance") == 999_999_999 for b in bodies)
    # Non-light mode emits a combined "kitchen sink" overlay flipping many flags.
    assert any({"is_admin", "verified", "role_id"} <= set(b.keys()) for b in bodies)


def test_method_override_smuggles_verbs_across_axes() -> None:
    strat = MethodOverrideStrategy()
    headers = [h for h, _ in strat.mutate_headers({})]
    assert any(h.get("X-HTTP-Method-Override") == "DELETE" for h in headers)
    queries = [q for q, _ in strat.mutate_query({})]
    assert any(q.get("_method") == "DELETE" for q in queries)
    bodies = [b for b, _ in strat.mutate_body({"x": 1})]
    assert any(b.get("_method") == "PUT" for b in bodies)


def test_open_redirect_bypasses_naive_same_origin_checks() -> None:
    strat = OpenRedirectStrategy()
    queries = [q for q, _ in strat.mutate_query({"next": "/home"})]
    assert any(q.get("next") == "//evil.example.com" for q in queries)
    bodies = [b for b, _ in strat.mutate_body({})]
    assert any(b.get("_redirect", "").endswith("evil.example.com") for b in bodies)


def test_new_strategies_registered_in_defaults() -> None:
    ids = {s.id for s in default_strategies()}
    assert {"ssrf", "mass_assignment", "method_override", "open_redirect"} <= ids


def test_expand_around_interest_ssrf() -> None:
    case = MutationCase("POST", "/fetch", base_body={"callback_url": "http://ok/"})
    anchor = MutatedRequest(
        method="POST",
        path="/fetch",
        headers={},
        query={},
        body={"callback_url": "http://ok/"},
        traces=(MutationTrace("t", "c", {}),),
    )
    out = list(expand_around_interest(case, anchor, {"category": "ssrf"}))
    assert out
    assert any(
        b.get("callback_url", "").startswith("http://169.254.169.254")
        or b.get("_url", "").startswith("http://169.254.169.254")
        for b in (m.body or {} for m in out)
    )
