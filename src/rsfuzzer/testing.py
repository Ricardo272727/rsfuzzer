from __future__ import annotations

import fnmatch
import json
import urllib.error
import urllib.request
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from rsfuzzer.profiles import AuthzCheck
from rsfuzzer.profiles import DifferentialCase
from rsfuzzer.profiles import Profile
@dataclass
class HttpResult:
    status_code: int
    body_preview: str


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


def build_query_string(endpoint_query_keys: list[str], fixtures: dict[str, Any]) -> str:
    qp = fixtures.get("query_params")
    if not isinstance(qp, dict):
        return ""
    pairs: list[tuple[str, str]] = []
    for key in endpoint_query_keys:
        if key in qp:
            pairs.append((key, str(qp[key])))
    if not pairs:
        return ""
    return urlencode(pairs)


def http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any] | None,
) -> HttpResult:
    data = None
    hdrs = dict(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read(4096)
            text = raw.decode("utf-8", errors="replace")
            return HttpResult(status_code=resp.status, body_preview=text[:500])
    except urllib.error.HTTPError as exc:
        raw = exc.read(4096) if exc.fp else b""
        text = raw.decode("utf-8", errors="replace")
        return HttpResult(status_code=exc.code, body_preview=text[:500])
    except urllib.error.URLError as exc:
        return HttpResult(status_code=0, body_preview=f"request_error: {exc.reason}")


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


def run_catalog_scan(
    profile: Profile,
    catalog: dict[str, Any],
    role_names: tuple[str, str],
    scope: str,
) -> tuple[list[ScanRow], set[tuple[str, str, str]]]:
    """GET-only catalog scan for MVP. Returns rows and dedupe keys (method, url, role)."""
    r_a, r_b = role_names
    if r_a not in profile.roles or r_b not in profile.roles:
        msg = f"Unknown role in --roles: {r_a!r} or {r_b!r}"
        raise ValueError(msg)

    rows: list[ScanRow] = []
    seen: set[tuple[str, str, str]] = set()
    endpoints = catalog.get("endpoints", [])
    if not isinstance(endpoints, list):
        return rows, seen

    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        method = str(ep.get("method", "")).upper()
        path_t = str(ep.get("path", ""))
        if not path_t:
            continue
        if not path_matches_scope(path_t, scope):
            continue
        if method not in {"GET", "HEAD"}:
            continue

        param_names = ep.get("path_params") or []
        if not isinstance(param_names, list):
            param_names = []
        str_names = [str(x) for x in param_names]

        path_resolved, skip_reason = expand_path(path_t, str_names, profile.fixtures)
        if path_resolved is None:
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

        q_keys = ep.get("query_params") or []
        if not isinstance(q_keys, list):
            q_keys = []
        qs = build_query_string([str(x) for x in q_keys], profile.fixtures)
        url = f"{profile.base_url}{path_resolved}"
        if qs:
            url = f"{url}?{qs}"

        for role_name in (r_a, r_b):
            key = (method, url, role_name)
            if key in seen:
                continue
            seen.add(key)
            role_cfg = profile.roles[role_name]
            res = http_request(method, url, role_cfg.headers, None)
            rows.append(
                ScanRow(
                    method=method,
                    path_template=path_t,
                    path_resolved=path_resolved,
                    url=url,
                    role=role_name,
                    status_code=res.status_code,
                    body_preview=res.body_preview,
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
    payload = {
        "profile": str(profile_path),
        "catalog": str(catalog_path),
        "roles": list(role_pair),
        "scope": scope,
        "checks": [asdict(x) for x in check_results],
        "differential": [asdict(x) for x in differential_results],
        "checks_all": [asdict(x) for x in combined],
        "check_failures": failed_checks,
        "scan": [asdict(x) for x in scan_rows],
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


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
