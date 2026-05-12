from __future__ import annotations

import base64
import json
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _b64_json(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class AuthSessionStrategy:
    id = "auth_session"
    category = "auth_session"

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        yield from ()

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        h0 = dict(headers)

        bad_jwt_parts = [
            "aa.bb.cc",
            "..",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
            f"{_b64_json({'alg': 'none'})}.{_b64_json({'sub': 'admin'})}.",
            f"{_b64_json({'alg': 'HS256'})}.{_b64_json({'sub': 'admin'})}.sig",
        ]
        for p in bad_jwt_parts:
            h = dict(h0)
            h["Authorization"] = f"Bearer {p}"
            trace = MutationTrace(self.id, self.category, {"jwt_shape": p[:40]})
            yield h, trace

        for dup in ("Cookie", "Authorization"):
            h = dict(h0)
            h[dup] = f"{h.get(dup, '')}; session=admin; session=user"
            trace = MutationTrace(self.id, self.category, {"duplicated_semantics": dup})
            yield h, trace

        h = dict(h0)
        h["X-Forwarded-User"] = "admin"
        h["X-Original-URL"] = "/api/admin/users"
        trace = MutationTrace(self.id, self.category, {"trust_header_injection": True})
        yield h, trace
