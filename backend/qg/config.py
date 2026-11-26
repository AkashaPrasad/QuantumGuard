"""Environment-only configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    keys_dir: Path
    port: int = 8080
    web_dist: Path | None = None
    demo: bool = False
    commit: str = "dev"
    log_stdout: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        web = os.environ.get("QG_WEB_DIST")
        return cls(
            data_dir=Path(os.environ.get("QG_DATA_DIR", "data")).resolve(),
            keys_dir=Path(os.environ.get("QG_KEYS_DIR", "keys")).resolve(),
            port=int(os.environ.get("QG_PORT", "8080")),
            web_dist=Path(web).resolve() if web else None,
            demo=_flag(os.environ.get("QG_DEMO")),
            commit=os.environ.get("QG_COMMIT", "dev"),
        )
