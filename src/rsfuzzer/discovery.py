from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs
from urllib.parse import urlparse

import yaml

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    operation_id: str | None
    summary: str | None
    tags: list[str]
    auth_schemes: list[str]
    path_params: list[str]
    query_params: list[str]
    body_content_types: list[str]
    sources: list[str]
    hosts: list[str]
    status_codes: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "operation_id": self.operation_id,
            "summary": self.summary,
            "tags": self.tags,
            "auth_schemes": self.auth_schemes,
            "path_params": self.path_params,
            "query_params": self.query_params,
            "body_content_types": self.body_content_types,
            "sources": self.sources,
            "hosts": self.hosts,
            "status_codes": self.status_codes,
        }


def load_openapi_spec(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    lowered = path.suffix.lower()

    if lowered == ".json":
        data = json.loads(raw)
    else:
        data = yaml.safe_load(raw)

    if not isinstance(data, dict):
        msg = "OpenAPI file root must be an object."
        raise ValueError(msg)
    if "paths" not in data or not isinstance(data["paths"], dict):
        msg = "OpenAPI file is missing a valid 'paths' section."
        raise ValueError(msg)
    return data


def extract_endpoints(spec: dict[str, Any]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    global_security = spec.get("security", [])

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        common_params = _collect_parameters(path_item.get("parameters", []))

        for method, operation in path_item.items():
            method_lower = method.lower()
            if method_lower not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            op_params = _collect_parameters(operation.get("parameters", []))
            path_params = sorted(set(common_params["path"] + op_params["path"]))
            query_params = sorted(set(common_params["query"] + op_params["query"]))

            security = operation.get("security", global_security)
            endpoint = Endpoint(
                method=method_upper(method_lower),
                path=path,
                operation_id=operation.get("operationId"),
                summary=operation.get("summary"),
                tags=operation.get("tags", []) if isinstance(operation.get("tags"), list) else [],
                auth_schemes=_extract_security_schemes(security),
                path_params=path_params,
                query_params=query_params,
                body_content_types=_extract_body_types(operation.get("requestBody")),
                sources=["openapi"],
                hosts=[],
                status_codes=[],
            )
            endpoints.append(endpoint)

    endpoints.sort(key=lambda e: (e.path, e.method))
    return endpoints


def load_traffic_flows(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []

    parsed: Any
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        flows: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if isinstance(entry, dict):
                flows.append(entry)
        return flows

    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        candidate = parsed.get("flows")
        if isinstance(candidate, list):
            return [x for x in candidate if isinstance(x, dict)]
        return [parsed]
    return []


def extract_endpoints_from_traffic(flows: list[dict[str, Any]]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for flow in flows:
        request = flow.get("request")
        response = flow.get("response")

        method, url = _extract_method_and_url(flow, request)
        if not method or not url:
            continue

        parsed = urlparse(url)
        if not parsed.path:
            continue

        normalized_path, inferred_path_params = _normalize_path(parsed.path)
        query_params = sorted(parse_qs(parsed.query).keys())
        body_type = _extract_request_content_type(flow, request)
        status_code = _extract_status_code(flow, response)
        host = parsed.netloc

        endpoint = Endpoint(
            method=method,
            path=normalized_path,
            operation_id=None,
            summary=None,
            tags=[],
            auth_schemes=[],
            path_params=inferred_path_params,
            query_params=query_params,
            body_content_types=[body_type] if body_type else [],
            sources=["traffic"],
            hosts=[host] if host else [],
            status_codes=[status_code] if status_code is not None else [],
        )
        endpoints.append(endpoint)

    return merge_endpoints(endpoints)


def merge_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    merged: dict[tuple[str, str], Endpoint] = {}

    for endpoint in endpoints:
        key = (endpoint.method, endpoint.path)
        current = merged.get(key)
        if current is None:
            merged[key] = endpoint
            continue

        merged[key] = Endpoint(
            method=endpoint.method,
            path=endpoint.path,
            operation_id=current.operation_id or endpoint.operation_id,
            summary=current.summary or endpoint.summary,
            tags=sorted(set(current.tags + endpoint.tags)),
            auth_schemes=sorted(set(current.auth_schemes + endpoint.auth_schemes)),
            path_params=sorted(set(current.path_params + endpoint.path_params)),
            query_params=sorted(set(current.query_params + endpoint.query_params)),
            body_content_types=sorted(set(current.body_content_types + endpoint.body_content_types)),
            sources=sorted(set(current.sources + endpoint.sources)),
            hosts=sorted(set(current.hosts + endpoint.hosts)),
            status_codes=sorted(set(current.status_codes + endpoint.status_codes)),
        )

    return sorted(merged.values(), key=lambda e: (e.path, e.method))


def write_endpoint_catalog(
    endpoints: list[Endpoint],
    output_path: Path,
    source_openapi: str | None = None,
    source_traffic: str | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    source: dict[str, str] = {}
    if source_openapi:
        source["openapi"] = source_openapi
    if source_traffic:
        source["traffic"] = source_traffic
    payload = {
        "source": source,
        "endpoint_count": len(endpoints),
        "endpoints": [e.to_dict() for e in endpoints],
    }
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _collect_parameters(parameters: Any) -> dict[str, list[str]]:
    collected = {"path": [], "query": []}
    if not isinstance(parameters, list):
        return collected

    for param in parameters:
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        location = param.get("in")
        if not isinstance(name, str) or not isinstance(location, str):
            continue
        if location in {"path", "query"}:
            collected[location].append(name)
    return collected


def _extract_security_schemes(security: Any) -> list[str]:
    if not isinstance(security, list):
        return []
    schemes: list[str] = []
    for requirement in security:
        if isinstance(requirement, dict):
            schemes.extend([k for k in requirement.keys() if isinstance(k, str)])
    return sorted(set(schemes))


def _extract_body_types(request_body: Any) -> list[str]:
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []
    return sorted([key for key in content.keys() if isinstance(key, str)])


def method_upper(method: str) -> str:
    return method.upper()


def _extract_method_and_url(flow: dict[str, Any], request: Any) -> tuple[str | None, str | None]:
    method = _to_str(flow.get("method"))
    url = _to_str(flow.get("url"))
    if isinstance(request, dict):
        method = method or _to_str(request.get("method"))
        url = (
            url
            or _to_str(request.get("pretty_url"))
            or _to_str(request.get("url"))
            or _build_url_from_parts(request)
        )
    if not method or not url:
        return None, None
    return method.upper(), url


def _extract_status_code(flow: dict[str, Any], response: Any) -> int | None:
    code = flow.get("status_code")
    if isinstance(code, int):
        return code
    if isinstance(response, dict) and isinstance(response.get("status_code"), int):
        return response["status_code"]
    return None


def _extract_request_content_type(flow: dict[str, Any], request: Any) -> str | None:
    flow_ct = _content_type_from_headers(flow.get("headers"))
    if flow_ct:
        return flow_ct
    if isinstance(request, dict):
        return _content_type_from_headers(request.get("headers"))
    return None


def _content_type_from_headers(headers: Any) -> str | None:
    if isinstance(headers, dict):
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == "content-type" and isinstance(value, str):
                return value.split(";")[0].strip()
    return None


def _build_url_from_parts(request: dict[str, Any]) -> str | None:
    host = _to_str(request.get("host")) or _to_str(request.get("pretty_host"))
    path = _to_str(request.get("path"))
    scheme = _to_str(request.get("scheme")) or "https"
    if host and path:
        return f"{scheme}://{host}{path}"
    return None


def _to_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _normalize_path(path: str) -> tuple[str, list[str]]:
    """Collapse dynamic path segments to OpenAPI-style names: first is {id}, then {id_2}, {id_3}, ..."""
    params: list[str] = []
    segments = path.split("/")
    normalized: list[str] = []
    dynamic_index = 0
    for segment in segments:
        if _looks_dynamic(segment):
            dynamic_index += 1
            name = "id" if dynamic_index == 1 else f"id_{dynamic_index}"
            normalized.append("{" + name + "}")
            params.append(name)
        else:
            normalized.append(segment)
    return "/".join(normalized), sorted(set(params))


def _looks_dynamic(segment: str) -> bool:
    if not segment:
        return False
    if segment.isdigit():
        return True
    if re.fullmatch(r"[0-9a-fA-F]{24}", segment):
        return True
    if re.fullmatch(r"[0-9a-fA-F-]{36}", segment):
        return True
    return False
