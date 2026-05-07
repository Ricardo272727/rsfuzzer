from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
            )
            endpoints.append(endpoint)

    endpoints.sort(key=lambda e: (e.path, e.method))
    return endpoints


def write_endpoint_catalog(endpoints: list[Endpoint], output_path: Path, source_openapi: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source": {"type": "openapi", "path": source_openapi},
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
