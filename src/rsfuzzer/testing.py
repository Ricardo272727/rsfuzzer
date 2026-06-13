from __future__ import annotations

import fnmatch
import http.client
import json
import math
import urllib.error
import urllib.request
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from rsfuzzer.mutations import MutationCase
from rsfuzzer.mutations import permute_case
from rsfuzzer.profiles import AuthzCheck
from rsfuzzer.profiles import DifferentialCase
from rsfuzzer.profiles import Profile


@dataclass
class HttpResult:
    status_code: int
    body_preview: str
    client_error: str | None = None
    request_body_encoding: str | None = None


@dataclass
class ScanRow:
    method: str
    path_template: str
    path_resolved: str
    url: str
    role: str
    status_code: int
    body_preview: str
    skipped_reason: str | None = None
    from_mutations: bool = False
    mutation_traces: list[dict[str, Any]] | None = None
    client_error: str | None = None
    request_body_encoding: str | None = None


@dataclass
class CheckResult:
    check_id: str
    role: str
    expected: int
    actual: int
    url: str
    passed: bool


def load_catalog(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "endpoints" not in data:
        msg = "Catalog must be a JSON object with an 'endpoints' list."
        raise ValueError(msg)
    return data


def path_matches_scope(path_template: str, scope: str) -> bool:
    if scope in {"", "*"}:
        return True
    return fnmatch.fnmatchcase(path_template, scope)


def resolve_path_param(name: str, fixtures: dict[str, Any], local: dict[str, str]) -> str | None:
    path_params = fixtures.get("path_params")
    if not isinstance(path_params, dict):
        path_params = {}
    merged = {**path_params, **local}
    if name in merged:
        return str(merged[name])
    aliases = fixtures.get("param_aliases")
    if isinstance(aliases, dict) and isinstance(aliases.get(name), str):
        target = aliases[name]
        if target in merged:
            return str(merged[target])
    if name == "id-like" and "id" in merged:
        return str(merged["id"])
    if name == "id" and "id-like" in merged:
        return str(merged["id-like"])
    return None


def expand_path(
    template: str,
    param_names: list[str],
    fixtures: dict[str, Any],
    local_path_params: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    local = local_path_params or {}
    out = template
    for name in param_names:
        value = resolve_path_param(name, fixtures, local)
        if value is None:
            return None, f"missing fixture for path param '{name}'"
        out = out.replace("{" + name + "}", value)
    if "{" in out and "}" in out:
        return None, "unresolved placeholders in path"
    return out, None


def fixtures_query_dict(endpoint_query_keys: list[str], fixtures: dict[str, Any]) -> dict[str, str]:
    qp = fixtures.get("query_params")
    if not isinstance(qp, dict):
        return {}
    out: dict[str, str] = {}
    for key in endpoint_query_keys:
        if key in qp:
            out[str(key)] = str(qp[key])
    return out


def build_query_string(endpoint_query_keys: list[str], fixtures: dict[str, Any]) -> str:
    pairs = list(fixtures_query_dict(endpoint_query_keys, fixtures).items())
    if not pairs:
        return ""
    return urlencode(pairs)


def _client_error_preview(exc: BaseException, prefix: str) -> str:
    msg = f"{prefix}{type(exc).__name__}: {exc}"
    return msg.replace("\r", "\\r").replace("\n", "\\n")[:500]


def _encode_request_body(body: dict[str, Any]) -> tuple[bytes | None, str | None, str | None]:
    """
    Serialize JSON body for HTTP. Returns (payload bytes, client_error if unsent, encoding kind).
    Non-RFC values (Infinity/NaN) are sent intentionally for parser fuzzing.
    """
    try:
        raw = json.dumps(body, ensure_ascii=False, allow_nan=False)
        return raw.encode("utf-8"), None, "strict"
    except ValueError:
        try:
            raw = json.dumps(body, ensure_ascii=False, allow_nan=True)
            return raw.encode("utf-8"), None, "non_rfc"
        except (TypeError, ValueError) as exc:
            return None, _client_error_preview(exc, "body_json:"), None
    except TypeError as exc:
        return None, _client_error_preview(exc, "body_json:"), None


def _trace_to_dict(trace: Any) -> dict[str, Any]:
    d = asdict(trace)
    d["detail"] = _sanitize_for_json(d.get("detail", {}))
    return d


def _sanitize_for_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _sanitize_for_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_json(v) for v in value]
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return str(value)
    return value


def _json_report_default(obj: Any) -> Any:
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        return str(obj)
    raise TypeError(type(obj).__name__)


def _http_failure(exc: BaseException, prefix: str = "connection:") -> HttpResult:
    return HttpResult(
        status_code=0,
        body_preview="",
        client_error=_client_error_preview(exc, prefix),
    )


def http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any] | None,
) -> HttpResult:
    """
    Perform one HTTP request. Never raises for malformed URLs/headers/body or transport
    failures: returns status_code 0 and a short ``body_preview`` reason so scans continue.
    """
    try:
        data = None
        body_encoding: str | None = None
        hdrs = dict(headers)
        if body is not None:
            data, body_note, body_encoding = _encode_request_body(body)
            if data is None:
                return HttpResult(
                    0,
                    body_preview=body_note or "body_json:encode_failed",
                    client_error=body_note,
                )
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        err = _client_error_preview(exc, "request_build:")
        return HttpResult(0, body_preview=err, client_error=err)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read(4096)
            text = raw.decode("utf-8", errors="replace")
            return HttpResult(
                status_code=resp.status,
                body_preview=text[:500],
                request_body_encoding=body_encoding,
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read(4096) if exc.fp else b""
        text = raw.decode("utf-8", errors="replace")
        return HttpResult(
            status_code=exc.code,
            body_preview=text[:500],
            request_body_encoding=body_encoding,
        )
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, BaseException):
            res = _http_failure(reason)
        else:
            res = HttpResult(0, body_preview="", client_error=f"connection:{reason}")
        res.request_body_encoding = body_encoding
        return res
    except (http.client.RemoteDisconnected, http.client.IncompleteRead) as exc:
        res = _http_failure(exc)
        res.request_body_encoding = body_encoding
        return res
    except ConnectionError as exc:
        res = _http_failure(exc)
        res.request_body_encoding = body_encoding
        return res
    except (ValueError, OSError) as exc:
        res = _http_failure(exc, "request_send:")
        res.request_body_encoding = body_encoding
        return res
    except Exception as exc:  # pragma: no cover - unexpected client/runtime errors
        res = _http_failure(exc, "request_failed:")
        res.request_body_encoding = body_encoding
        return res


def _differential_body_variants(case: DifferentialCase) -> list[dict[str, Any] | None]:
    m = case.method.upper()
    if m in ("GET", "HEAD", "DELETE", "OPTIONS", "TRACE"):
        return [None]
    if case.body_mutations:
        base = dict(case.body) if case.body else {}
        return [{**base, **dict(extra)} for extra in case.body_mutations]
    if case.body is not None:
        return [dict(case.body)]
    return [{}]


def run_differential_case(profile: Profile, case: DifferentialCase) -> list[CheckResult]:
    path, err = expand_path(
        case.path,
        _path_param_names_from_template(case.path),
        profile.fixtures,
        case.path_params,
    )
    if path is None:
        return [
            CheckResult(
                check_id=f"{case.id}|setup_error",
                role=role_name,
                expected=expected,
                actual=-1,
                url="",
                passed=False,
            )
            for role_name, expected in case.expect.items()
        ]

    base = profile.base_url
    results: list[CheckResult] = []
    body_variants = _differential_body_variants(case)

    for qi, q_extra in enumerate(case.query_mutations):
        for hi, h_extra in enumerate(case.header_mutations):
            for bi, body in enumerate(body_variants):
                query_dict = {**case.base_query, **dict(q_extra)}
                qs = urlencode(sorted(query_dict.items())) if query_dict else ""
                url = f"{base}{path}"
                if qs:
                    url = f"{url}?{qs}"
                suffix = f"|q{qi}|h{hi}|b{bi}"

                for role_name, expected in case.expect.items():
                    role_cfg = profile.roles.get(role_name)
                    check_id = f"{case.id}{suffix}"
                    if role_cfg is None:
                        results.append(
                            CheckResult(
                                check_id=check_id,
                                role=role_name,
                                expected=expected,
                                actual=-1,
                                url=url,
                                passed=False,
                            )
                        )
                        continue
                    headers = {
                        **role_cfg.headers,
                        **{str(k): str(v) for k, v in dict(h_extra).items()},
                    }
                    res = http_request(case.method, url, headers, body)
                    actual = res.status_code
                    results.append(
                        CheckResult(
                            check_id=check_id,
                            role=role_name,
                            expected=expected,
                            actual=actual,
                            url=url,
                            passed=actual == expected,
                        )
                    )
    return results


def run_check(profile: Profile, check: AuthzCheck) -> list[CheckResult]:
    path, err = expand_path(
        check.path,
        _path_param_names_from_template(check.path),
        profile.fixtures,
        check.path_params,
    )
    if path is None:
        return [
            CheckResult(
                check_id=check.id,
                role=role_name,
                expected=expected,
                actual=-1,
                url="",
                passed=False,
            )
            for role_name, expected in check.expect.items()
        ]

    query = build_query_string(list(check.query_params.keys()), {"query_params": check.query_params})
    base = profile.base_url
    url = f"{base}{path}"
    if query:
        url = f"{url}?{query}"

    results: list[CheckResult] = []
    for role_name, expected in check.expect.items():
        role_cfg = profile.roles.get(role_name)
        if role_cfg is None:
            results.append(
                CheckResult(
                    check_id=check.id,
                    role=role_name,
                    expected=expected,
                    actual=-1,
                    url=url,
                    passed=False,
                )
            )
            continue
        res = http_request(check.method, url, role_cfg.headers, check.body)
        actual = res.status_code
        passed = actual == expected
        results.append(
            CheckResult(
                check_id=check.id,
                role=role_name,
                expected=expected,
                actual=actual,
                url=url,
                passed=passed,
            )
        )
    return results


def _path_param_names_from_template(template: str) -> list[str]:
    names: list[str] = []
    parts = template.split("{")
    for part in parts[1:]:
        if "}" not in part:
            continue
        name = part.split("}", 1)[0]
        if name:
            names.append(name)
    return names


_READ_METHODS = frozenset({"GET", "HEAD"})
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _effective_mutate_parts(method: str, mutate_parts: tuple[str, ...]) -> tuple[str, ...]:
    """GET/HEAD never send a JSON body; drop ``body`` so variants are not wasted."""
    if method.upper() in _READ_METHODS:
        return tuple(p for p in mutate_parts if p != "body")
    return mutate_parts


def _catalog_scan_methods(mutate_parts: tuple[str, ...]) -> frozenset[str]:
    """Methods included in catalog baseline / mutation passes."""
    methods = set(_READ_METHODS)
    if "body" in mutate_parts:
        methods |= _BODY_METHODS
    return frozenset(methods)


def fixture_body(profile: Profile, path_template: str, method: str) -> dict[str, Any]:
    """JSON body seed for catalog POST/PATCH/PUT (profile ``fixtures.bodies`` or built-in default)."""
    bodies = profile.fixtures.get("bodies")
    if isinstance(bodies, dict):
        raw = bodies.get(path_template)
        if raw is None:
            raw = bodies.get(f"{method.upper()} {path_template}")
        if isinstance(raw, dict):
            return {str(k): v for k, v in raw.items()}
    defaults: dict[tuple[str, str], dict[str, Any]] = {
        ("POST", "/api/orders"): {"total": 100},
        ("PATCH", "/api/orders/{id}/status"): {"status": "shipped"},
    }
    return dict(defaults.get((method.upper(), path_template), {}))


def _resolve_catalog_endpoint(
    ep: dict[str, Any],
    profile: Profile,
    scope: str,
    allowed_methods: frozenset[str],
) -> tuple[str, str, str, list[str], list[str], dict[str, str], dict[str, Any] | None, str | None] | None:
    """
    Returns (method, path_template, path_resolved, path_param_names, query_keys, query_dict,
    baseline_body, skip_reason). baseline_body is None for read methods.
    """
    method = str(ep.get("method", "")).upper()
    path_t = str(ep.get("path", ""))
    if not path_t or not path_matches_scope(path_t, scope):
        return None
    if method not in allowed_methods:
        return None

    param_names = ep.get("path_params") or []
    if not isinstance(param_names, list):
        param_names = []
    str_names = [str(x) for x in param_names]

    path_resolved, skip_reason = expand_path(path_t, str_names, profile.fixtures)
    if path_resolved is None:
        return method, path_t, "", str_names, [], {}, None, skip_reason

    q_keys = ep.get("query_params") or []
    if not isinstance(q_keys, list):
        q_keys = []
    str_qkeys = [str(x) for x in q_keys]
    qd = fixtures_query_dict(str_qkeys, profile.fixtures)

    baseline_body: dict[str, Any] | None = None
    if method in _BODY_METHODS:
        baseline_body = fixture_body(profile, path_t, method)

    return method, path_t, path_resolved, str_names, str_qkeys, qd, baseline_body, None


def _build_catalog_url(base_url: str, path_resolved: str, query: dict[str, str]) -> str:
    url = f"{base_url}{path_resolved}"
    if query:
        url = f"{url}?{urlencode(sorted(query.items()))}"
    return url


def _scan_row_from_http(
    *,
    method: str,
    path_template: str,
    path_resolved: str,
    url: str,
    role: str,
    res: HttpResult,
    from_mutations: bool = False,
    mutation_traces: list[dict[str, Any]] | None = None,
    loop_error: str | None = None,
) -> ScanRow:
    preview = res.body_preview
    if not preview and res.client_error:
        preview = res.client_error
    if loop_error:
        preview = loop_error
    return ScanRow(
        method=method,
        path_template=path_template,
        path_resolved=path_resolved,
        url=url,
        role=role,
        status_code=res.status_code,
        body_preview=preview[:500],
        from_mutations=from_mutations,
        mutation_traces=mutation_traces,
        client_error=loop_error or res.client_error,
        request_body_encoding=res.request_body_encoding,
    )


def run_catalog_scan(
    profile: Profile,
    catalog: dict[str, Any],
    role_names: tuple[str, str],
    scope: str,
    *,
    mutate_max: int = 0,
    mutate_light: bool = False,
    mutate_parts: tuple[str, ...] = ("query", "headers"),
) -> tuple[list[ScanRow], set[tuple[str, str, str]]]:
    """Catalog scan: read methods always; POST/PATCH/PUT when ``body`` is in ``mutate_parts``.

    If ``mutate_max`` > 0, each eligible endpoint × role gets up to that many extra requests
    via ``permute_case`` (same registry as ``rsfuzzer mutate``).
    """
    r_a, r_b = role_names
    if r_a not in profile.roles or r_b not in profile.roles:
        msg = f"Unknown role in --roles: {r_a!r} or {r_b!r}"
        raise ValueError(msg)

    rows: list[ScanRow] = []
    seen: set[tuple[str, str, str]] = set()
    endpoints = catalog.get("endpoints", [])
    if not isinstance(endpoints, list):
        return rows, seen

    scan_methods = _catalog_scan_methods(mutate_parts if mutate_parts else ("query", "headers"))

    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        resolved = _resolve_catalog_endpoint(ep, profile, scope, scan_methods)
        if resolved is None:
            continue
        method, path_t, path_resolved, _str_names, str_qkeys, qd, baseline_body, skip_reason = resolved
        if skip_reason is not None:
            rows.append(
                ScanRow(
                    method=method,
                    path_template=path_t,
                    path_resolved="",
                    url="",
                    role="",
                    status_code=-1,
                    body_preview="",
                    skipped_reason=skip_reason,
                )
            )
            continue

        url = _build_catalog_url(profile.base_url, path_resolved, qd)

        for role_name in (r_a, r_b):
            key = (method, url, role_name)
            if key in seen:
                continue
            seen.add(key)
            role_cfg = profile.roles[role_name]
            send_body = baseline_body if method in _BODY_METHODS else None
            res = http_request(method, url, role_cfg.headers, send_body)
            rows.append(
                _scan_row_from_http(
                    method=method,
                    path_template=path_t,
                    path_resolved=path_resolved,
                    url=url,
                    role=role_name,
                    res=res,
                )
            )

    if mutate_max <= 0:
        return rows, seen

    parts = mutate_parts if mutate_parts else ("query", "headers")
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        resolved = _resolve_catalog_endpoint(ep, profile, scope, scan_methods)
        if resolved is None:
            continue
        method, path_t, path_resolved, _str_names, _str_qkeys, qd, baseline_body, skip_reason = resolved
        if skip_reason is not None:
            continue

        eff_parts = _effective_mutate_parts(method, parts)
        if not eff_parts:
            continue

        base_body = baseline_body if method in _BODY_METHODS else None

        for role_name in (r_a, r_b):
            role_cfg = profile.roles[role_name]
            case = MutationCase(
                method=method,
                path=path_resolved,
                base_headers=dict(role_cfg.headers),
                base_query=qd,
                base_body=base_body,
            )
            for req in permute_case(
                case,
                light=mutate_light,
                max_variants=mutate_max,
                parts=eff_parts,
            ):
                m_url = _build_catalog_url(profile.base_url, path_resolved, req.query)
                merged_headers = {**role_cfg.headers, **req.headers}
                send_body: dict[str, Any] | None = None
                if "body" in eff_parts and method in _BODY_METHODS:
                    send_body = req.body
                try:
                    res = http_request(method, m_url, merged_headers, send_body)
                    mutation_traces = [_trace_to_dict(t) for t in req.traces]
                    rows.append(
                        _scan_row_from_http(
                            method=method,
                            path_template=path_t,
                            path_resolved=path_resolved,
                            url=m_url,
                            role=role_name,
                            res=res,
                            from_mutations=True,
                            mutation_traces=mutation_traces,
                        )
                    )
                except Exception as exc:
                    rows.append(
                        _scan_row_from_http(
                            method=method,
                            path_template=path_t,
                            path_resolved=path_resolved,
                            url=m_url,
                            role=role_name,
                            res=HttpResult(0, body_preview=""),
                            from_mutations=True,
                            mutation_traces=[_trace_to_dict(t) for t in req.traces],
                            loop_error=_client_error_preview(exc, "scan_row:"),
                        )
                    )

    return rows, seen


def write_test_report(
    out_path: Path,
    profile_path: Path,
    catalog_path: Path,
    role_pair: tuple[str, str],
    scope: str,
    check_results: list[CheckResult],
    differential_results: list[CheckResult],
    scan_rows: list[ScanRow],
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    combined = check_results + differential_results
    failed_checks = [asdict(x) for x in combined if not x.passed]
    scan_dicts = [asdict(x) for x in scan_rows]
    scan_errors = [
        row
        for row in scan_dicts
        if row.get("status_code") == 0 or row.get("client_error")
    ]
    payload = {
        "profile": str(profile_path),
        "catalog": str(catalog_path),
        "roles": list(role_pair),
        "scope": scope,
        "checks": [asdict(x) for x in check_results],
        "differential": [asdict(x) for x in differential_results],
        "checks_all": [asdict(x) for x in combined],
        "check_failures": failed_checks,
        "scan": scan_dicts,
        "scan_error_count": len(scan_errors),
        "scan_errors": scan_errors,
    }
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True, default=_json_report_default),
        encoding="utf-8",
    )


def role_pair_from_args(profile: Profile, roles_csv: str) -> tuple[str, str]:
    parts = [p.strip() for p in roles_csv.split(",") if p.strip()]
    if len(parts) != 2:
        msg = "--roles must be exactly two comma-separated role names, e.g. user_alice,user_bob"
        raise ValueError(msg)
    a, b = parts
    if a not in profile.roles or b not in profile.roles:
        msg = f"Roles must exist in profile file. Known: {sorted(profile.roles.keys())}"
        raise ValueError(msg)
    return a, b
