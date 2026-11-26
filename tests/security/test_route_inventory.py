"""The API contract's public list is exact; documentation/debug routes are private."""

from pathlib import Path
import re

import pytest


CONTRACT = Path(__file__).resolve().parents[2] / "spec/API.md"
section = CONTRACT.read_text(encoding="utf-8").split("## 2. Public routes (no session)", 1)[1].split("## 3.", 1)[0]
PUBLIC = set(re.findall(r"`(GET|POST) (/[^` ]+)`", section))


def protected_contract_routes():
    text = CONTRACT.read_text(encoding="utf-8").split("## 5.", 1)[1]
    routes = set()
    for method, path in re.findall(r"`(GET|POST|PUT|PATCH|DELETE) (/[^` ]+)`", text):
        path = re.sub(r"\{index\}", "0", path)
        path = re.sub(r"\{[vn]\}", "1", path)
        path = re.sub(r"\{id\}", "fil_" + "A" * 22, path)
        route = (method, "/api/v1" + path)
        if route not in PUBLIC:
            routes.add(route)
    routes.add(("POST", "/api/v1/session/end"))
    return sorted(routes)


def contains_dependency(node, expected):
    if getattr(node, "call", None) is expected:
        return True
    return any(contains_dependency(child, expected) for child in getattr(node, "dependencies", ()))


def test_every_non_public_route_has_gateway_dependency(app, gateway_dependency):
    from starlette.routing import Mount
    from starlette.staticfiles import StaticFiles

    assert len(PUBLIC) == 10, "Contract public-list parser must not silently become empty."
    failures = []
    for route in app.routes:
        if isinstance(route, Mount):
            # Only the browser's static site is exempt, never nested API apps.
            if isinstance(route.app, StaticFiles) and not route.path.startswith("/api"):
                continue
            failures.append(f"Unexpected uninspected mount: {route.path}")
            continue
        for method in getattr(route, "methods", ()):
            if (method, route.path) not in PUBLIC:
                if not contains_dependency(getattr(route, "dependant", None), gateway_dependency):
                    failures.append(f"{method} {route.path}")
    assert not failures, "Routes missing the gateway dependency: " + ", ".join(failures)


@pytest.mark.parametrize("method,path", protected_contract_routes())
def test_every_non_public_contract_route_without_session_returns_401(client, method, path):
    response = client.request(method, path)
    assert response.status_code == 401, (method, path, response.status_code)
    assert response.json()["error"]["code"] == "QG_NO_SESSION"
    assert response.headers.get("QG-Request-Id")


def test_healthcheck_is_public(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
