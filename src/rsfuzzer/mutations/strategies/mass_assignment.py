from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace

_FAR_PAST = "1970-01-01T00:00:00Z"


def _protected_overlays(*, light: bool) -> Iterator[tuple[str, dict[str, Any]]]:
    """
    Server-controlled / protected object properties a client should not be able to
    set (OWASP API3 Broken Object Property Level Authorization). If the API binds
    request bodies directly to a model, these silently overwrite trusted fields.
    """
    core: list[tuple[str, dict[str, Any]]] = [
        ("id_override", {"id": 1}),
        ("is_admin", {"is_admin": True}),
        ("admin_flag", {"admin": True}),
        ("verified", {"verified": True}),
        ("email_verified", {"email_verified": True}),
        ("is_active", {"is_active": True}),
        ("balance", {"balance": 999_999_999}),
        ("credit", {"credit": 999_999_999}),
        ("price_zero", {"price": 0}),
        ("discount_full", {"discount": 100}),
        ("status_approved", {"status": "approved"}),
        ("approved", {"approved": True}),
        ("owner_override", {"owner_id": 1}),
        ("role_id", {"role_id": 1}),
        ("is_premium", {"is_premium": True}),
    ]
    extra: list[tuple[str, dict[str, Any]]] = [
        ("created_at", {"created_at": _FAR_PAST}),
        ("updated_at", {"updated_at": _FAR_PAST}),
        ("deleted_flag", {"deleted": False}),
        ("password_hash", {"password_hash": "$2b$10$abcdefghijklmnopqrstuv"}),
        ("reset_token", {"reset_token": "attacker-controlled"}),
        ("api_key", {"api_key": "ak_injected"}),
        ("group_id", {"group_id": 1}),
        ("account_id", {"account_id": 1}),
        ("tenant_override", {"tenant_id": "system"}),
        ("subscription", {"subscription": "enterprise"}),
        ("quota", {"quota": 10**9}),
        ("mfa_disable", {"mfa_enabled": False}),
        ("verified_at", {"verified_at": _FAR_PAST}),
        ("internal_flag", {"internal": True}),
    ]
    if light:
        yield from core[:9]
    else:
        yield from core
        yield from extra
        # High-signal "kitchen sink": flip every dangerous flag at once.
        combined: dict[str, Any] = {}
        for _name, overlay in core + extra:
            combined.update(overlay)
        yield "all_protected_fields", combined


class MassAssignmentStrategy:
    """
    Mass assignment / auto-binding abuse. Overlays protected, server-owned
    attributes onto the request body (and a few onto query) to detect APIs that
    trust client-supplied object properties.
    """

    id = "mass_assignment"
    category = "mass_assignment"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        for name, overlay in _protected_overlays(light=self._light):
            merged = _merge_body(body, overlay)
            trace = MutationTrace(
                self.id,
                self.category,
                {"overlay": name, "keys": list(overlay.keys())},
            )
            yield merged, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        pairs = [
            ("is_admin", "true"),
            ("verified", "true"),
            ("role_id", "1"),
            ("owner_id", "1"),
            ("status", "approved"),
        ]
        for k, v in (pairs[:3] if self._light else pairs):
            q = dict(query)
            q[k] = v
            yield q, MutationTrace(self.id, self.category, {"param": k, "value": v})

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()
