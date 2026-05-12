from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class RoleConfig:
    headers: dict[str, str]


@dataclass(frozen=True)
class AuthzCheck:
    id: str
    method: str
    path: str
    path_params: dict[str, str]
    query_params: dict[str, str]
    body: dict[str, Any] | None
    expect: dict[str, int]


@dataclass(frozen=True)
class DifferentialCase:
    """Cartesian product of query/header/body mutations; each combo must match expect per role."""

    id: str
    method: str
    path: str
    path_params: dict[str, str]
    base_query: dict[str, str]
    query_mutations: tuple[dict[str, str], ...]
    header_mutations: tuple[dict[str, str], ...]
    body: dict[str, Any] | None
    body_mutations: tuple[dict[str, Any], ...]
    expect: dict[str, int]


@dataclass(frozen=True)
class Profile:
    base_url: str
    roles: dict[str, RoleConfig]
    fixtures: dict[str, Any]
    checks: list[AuthzCheck]
    differential: list[DifferentialCase]


def load_profile(path: Path) -> Profile:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        msg = "Profile root must be a mapping."
        raise ValueError(msg)

    base_url = raw.get("base_url")
    if not isinstance(base_url, str) or not base_url.strip():
        msg = "Profile must define a non-empty string 'base_url'."
        raise ValueError(msg)
    base_url = base_url.rstrip("/")

    roles_raw = raw.get("roles", {})
    if not isinstance(roles_raw, dict) or not roles_raw:
        msg = "Profile must define a non-empty 'roles' mapping."
        raise ValueError(msg)

    roles: dict[str, RoleConfig] = {}
    for name, cfg in roles_raw.items():
        if not isinstance(name, str) or not isinstance(cfg, dict):
            continue
        headers = cfg.get("headers", {})
        if not isinstance(headers, dict):
            msg = f"Role '{name}' must have 'headers' as a mapping."
            raise ValueError(msg)
        str_headers = {str(k): str(v) for k, v in headers.items()}
        roles[name] = RoleConfig(headers=str_headers)

    fixtures = raw.get("fixtures", {})
    if fixtures is None:
        fixtures = {}
    if not isinstance(fixtures, dict):
        msg = "Profile 'fixtures' must be a mapping if present."
        raise ValueError(msg)

    checks: list[AuthzCheck] = []
    for entry in raw.get("checks", []) or []:
        if not isinstance(entry, dict):
            continue
        cid = entry.get("id")
        method = entry.get("method")
        path = entry.get("path")
        if not isinstance(cid, str) or not isinstance(method, str) or not isinstance(path, str):
            continue
        path_params = entry.get("path_params", {}) or {}
        query_params = entry.get("query_params", {}) or {}
        if not isinstance(path_params, dict) or not isinstance(query_params, dict):
            continue
        body = entry.get("body")
        if body is not None and not isinstance(body, dict):
            msg = f"Check '{cid}' body must be a mapping or omitted."
            raise ValueError(msg)
        expect = entry.get("expect", {}) or {}
        if not isinstance(expect, dict) or not expect:
            continue
        expect_status: dict[str, int] = {}
        for role_name, status in expect.items():
            if isinstance(role_name, str) and isinstance(status, int):
                expect_status[role_name] = status
        if not expect_status:
            continue
        checks.append(
            AuthzCheck(
                id=cid,
                method=method.upper(),
                path=path,
                path_params={str(k): str(v) for k, v in path_params.items()},
                query_params={str(k): str(v) for k, v in query_params.items()},
                body=body,
                expect=expect_status,
            )
        )

    differential: list[DifferentialCase] = []
    for entry in raw.get("differential", []) or []:
        if not isinstance(entry, dict):
            continue
        did = entry.get("id")
        method = entry.get("method")
        path = entry.get("path")
        if not isinstance(did, str) or not isinstance(method, str) or not isinstance(path, str):
            continue
        path_params = entry.get("path_params", {}) or {}
        base_query = entry.get("base_query", {}) or {}
        if not isinstance(path_params, dict) or not isinstance(base_query, dict):
            continue

        qm = entry.get("query_mutations")
        if qm is None:
            qm = [{}]
        if not isinstance(qm, list) or not all(isinstance(x, dict) for x in qm):
            msg = f"Differential '{did}' query_mutations must be a list of mappings."
            raise ValueError(msg)

        hm = entry.get("header_mutations")
        if hm is None:
            hm = [{}]
        if not isinstance(hm, list) or not all(isinstance(x, dict) for x in hm):
            msg = f"Differential '{did}' header_mutations must be a list of mappings."
            raise ValueError(msg)

        body = entry.get("body")
        if body is not None and not isinstance(body, dict):
            msg = f"Differential '{did}' body must be a mapping or omitted."
            raise ValueError(msg)

        bm = entry.get("body_mutations")
        if bm is None:
            bm = []
        if not isinstance(bm, list) or not all(isinstance(x, dict) for x in bm):
            msg = f"Differential '{did}' body_mutations must be a list of mappings."
            raise ValueError(msg)

        expect = entry.get("expect", {}) or {}
        if not isinstance(expect, dict) or not expect:
            continue
        expect_status: dict[str, int] = {}
        for role_name, status in expect.items():
            if isinstance(role_name, str) and isinstance(status, int):
                expect_status[role_name] = status
        if not expect_status:
            continue

        differential.append(
            DifferentialCase(
                id=did,
                method=method.upper(),
                path=path,
                path_params={str(k): str(v) for k, v in path_params.items()},
                base_query={str(k): str(v) for k, v in base_query.items()},
                query_mutations=tuple({str(k): str(v) for k, v in d.items()} for d in qm),
                header_mutations=tuple({str(k): str(v) for k, v in d.items()} for d in hm),
                body=dict(body) if body else None,
                body_mutations=tuple(dict(x) for x in bm),
                expect=expect_status,
            )
        )

    return Profile(
        base_url=base_url,
        roles=roles,
        fixtures=fixtures,
        checks=checks,
        differential=differential,
    )
