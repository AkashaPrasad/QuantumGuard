"""HTTP routers. Every router module lists its routes; `routers()` collects them in a stable order."""

from __future__ import annotations

import importlib

MODULES = ["auth", "invites", "devices", "policy", "files", "incidents", "evidence", "changes", "alerts",
           "services", "messages"]


def routers() -> list:
    out = []
    for name in MODULES:
        try:
            mod = importlib.import_module(f"qg.api.{name}")
        except ModuleNotFoundError as exc:
            if exc.name == f"qg.api.{name}":
                continue
            raise
        out.append(mod.router)
    return out
