"""Run a scenario from a source checkout: python scenarios/run.py <name>. Same as python -m qg.scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "cli")]

from qg.scenarios.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
