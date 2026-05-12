from __future__ import annotations

from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace


def _boundary_variants() -> Iterator[tuple[str, str]]:
    yield "empty_line", "\r\n\r\n"
    yield "double_dash", "----boundary----"
    yield "null_in_boundary", "----bound\x00ary----"
    yield "crlf_in_boundary", "----bound\r\nary----"


def _filename_variants() -> Iterator[str]:
    yield "../../../etc/passwd"
    yield "..\\..\\..\\windows\\system32\\config\\sam"
    yield "nul"
    yield "con"
    yield "file\x00.jpg"
    yield "shell.php.jpg"
    yield "😀.txt"


class MultipartAbuseStrategy:
    """Emits *metadata* for multipart abuse; actual raw framing needs a multipart-capable client."""

    id = "multipart_abuse"
    category = "multipart_file"

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        for bname, bval in _boundary_variants():
            for fname in list(_filename_variants())[:4]:
                meta = {
                    "_multipart_simulation": {
                        "boundary": bval,
                        "filename": fname,
                        "declared_mime": "image/jpeg",
                        "actual_sniff": "text/plain",
                    }
                }
                merged = _merge_body(base, meta)
                trace = MutationTrace(
                    self.id,
                    self.category,
                    {"boundary_style": bname, "filename": fname},
                )
                yield merged, trace

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        yield from ()

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        for ctype in (
            "multipart/form-data; boundary=----x",
            "multipart/form-data; boundary=----x; boundary=----y",
            "application/json; boundary=fake",
        ):
            h = dict(headers)
            h["Content-Type"] = ctype
            trace = MutationTrace(self.id, self.category, {"content_type": ctype})
            yield h, trace
