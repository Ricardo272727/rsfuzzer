from __future__ import annotations

from typing import Any

from rsfuzzer.mutations.strategies import AuthSessionStrategy
from rsfuzzer.mutations.strategies import BoundaryStrategy
from rsfuzzer.mutations.strategies import DeepJsonStrategy
from rsfuzzer.mutations.strategies import HttpProtocolStrategy
from rsfuzzer.mutations.strategies import InjectionStrategy
from rsfuzzer.mutations.strategies import MultipartAbuseStrategy
from rsfuzzer.mutations.strategies import PrototypePollutionStrategy
from rsfuzzer.mutations.strategies import ResourceExhaustionStrategy
from rsfuzzer.mutations.strategies import TypeConfusionStrategy
from rsfuzzer.mutations.strategies import UnicodeEncodingStrategy


def default_strategies(*, light: bool = False) -> list[Any]:
    """
    Registered mutation strategies (generators). Use light=True for fast smoke tests
    (skips largest injection cartesian product and huge exhaustion sizes).
    """
    core: list[Any] = [
        PrototypePollutionStrategy(),
        DeepJsonStrategy(depths=(16, 48) if light else (32, 64, 128)),
        TypeConfusionStrategy(),
        BoundaryStrategy(),
        UnicodeEncodingStrategy(),
        MultipartAbuseStrategy(),
        AuthSessionStrategy(),
        HttpProtocolStrategy(),
    ]
    if light:
        core.append(
            ResourceExhaustionStrategy(
                array_lengths=(100, 500),
                string_lengths=(1000, 5000),
            )
        )
        core.append(InjectionStrategy(inject_key="_injection"))
        return _limit_injection_templates(core, max_templates=6, max_markers=4)
    core.append(ResourceExhaustionStrategy())
    core.append(InjectionStrategy(inject_key="_injection"))
    return core


def _limit_injection_templates(
    strategies: list[Any],
    *,
    max_templates: int,
    max_markers: int,
) -> list[Any]:
    out: list[Any] = []
    for s in strategies:
        if isinstance(s, InjectionStrategy):
            out.append(
                InjectionStrategy(
                    inject_key=s.inject_key,
                    max_templates=max_templates,
                    max_markers=max_markers,
                )
            )
        else:
            out.append(s)
    return out
