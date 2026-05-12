"""Payload mutation engine: strategy-based generators, not static payload lists."""

from rsfuzzer.mutations.engine import MutationEngine
from rsfuzzer.mutations.engine import expand_around_interest
from rsfuzzer.mutations.engine import permute_case
from rsfuzzer.mutations.registry import default_strategies
from rsfuzzer.mutations.types import MutationCase
from rsfuzzer.mutations.types import MutatedRequest
from rsfuzzer.mutations.types import MutationTrace

__all__ = [
    "MutationCase",
    "MutatedRequest",
    "MutationTrace",
    "MutationEngine",
    "default_strategies",
    "permute_case",
    "expand_around_interest",
]
