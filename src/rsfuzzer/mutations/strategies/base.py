from __future__ import annotations

from typing import Any
from typing import Iterator
from typing import Protocol

from rsfuzzer.mutations.types import MutationTrace


class MutationStrategy(Protocol):
    """Each strategy yields variants by *generating* from parameters, not from fixed CVE strings."""

    id: str
    category: str

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        ...

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        ...

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        ...


def _merge_body(
    base: dict[str, Any] | None,
    overlay: dict[str, Any],
) -> dict[str, Any]:
    out = dict(base) if base else {}
    out.update(overlay)
    return out
