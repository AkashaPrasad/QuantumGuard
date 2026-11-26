import json
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[2] / "spec" / "vectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))
