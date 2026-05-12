from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Literal


PartKind = Literal["body", "query", "headers", "path"]


@dataclass(frozen=True)
class MutationTrace:
    strategy_id: str
    category: str
    detail: dict[str, Any]


@dataclass
class MutationCase:
    """Base request template to permute (not only the user / role)."""

    method: str
    path: str
    base_headers: dict[str, str] = field(default_factory=dict)
    base_query: dict[str, str] = field(default_factory=dict)
    base_body: dict[str, Any] | None = None


@dataclass(frozen=True)
class MutatedRequest:
    """Fully materialized request + audit trail."""

    method: str
    path: str
    headers: dict[str, str]
    query: dict[str, str]
    body: dict[str, Any] | None
    traces: tuple[MutationTrace, ...]
