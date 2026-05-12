from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.types import MutationTrace


class HttpProtocolStrategy:
    """
    Header-level mutations that survive urllib; raw TE/CL smuggling needs a lower-level socket client.
    Documented for extension: chunked, duplicate CL, malformed line endings.
    """

    id = "http_protocol"
    category = "http_protocol"

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

        pairs = [
            ("Transfer-Encoding", "chunked"),
            ("Connection", "keep-alive\r\nX-Evil: 1"),
            ("Content-Length", "0"),
            ("Content-Length", "999999"),
        ]
        for k, v in pairs:
            h = dict(h0)
            h[k] = v
            trace = MutationTrace(self.id, self.category, {"set": k, "note": "may_need_raw_http"})
            yield h, trace

        h = dict(h0)
        h["Content-Length"] = "1"
        h["X-Ignore-Cl"] = "1"
        trace = MutationTrace(self.id, self.category, {"pattern": "conflicting_length_hint"})
        yield h, trace
