"""Check declared and resolved Python/JavaScript packages without importing them."""

import json
from pathlib import Path
import re
import sys


BANNED = re.compile(
    r"^(?:scikit-learn|sklearn|torch.*|pytorch.*|tensorflow.*|transformers|"
    r"onnx.*|keras.*|jax(?:lib)?|flax|sentence-transformers|"
    r"huggingface-hub|diffusers|accelerate|xgboost|lightgbm|catboost|"
    r"llama-cpp-python|llama-index.*|langchain.*|openai|anthropic|"
    r"cohere|groq|ollama|vllm|mlflow|timm|spacy|nltk|@tensorflow/.*|"
    r"@huggingface/.*|@xenova/.*|@anthropic-ai/.*|@ai-sdk/.*|ai)$"
)


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def packages(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    if path.name == "uv.lock":
        # uv package entries and dependency tables both use name = "...".
        return set(re.findall(r'\bname\s*=\s*"([^"\n]+)"', text))
    if path.name == "pnpm-lock.yaml":
        # pnpm v6/v9 importer, package and snapshot keys; scoped names kept intact.
        names = set()
        for line in text.splitlines():
            match = re.match(r"\s{2,}['\"]?(/?@?[^\s:'\"]+)['\"]?:", line)
            if match:
                key = match.group(1).lstrip("/")
                if key.startswith("@"):
                    name = key.split("@", 2)[1]
                    names.add("@" + name.split("(", 1)[0])
                    # pnpm v6: /@scope/name/version
                    names.add("/".join(key.split("/")[:2]))
                else:
                    names.add(re.split(r"[@/(]", key, maxsplit=1)[0])
        return names
    data = json.loads(text)
    return {name for group in ("dependencies", "devDependencies", "optionalDependencies") for name in data.get(group, {})}


def main(root: Path) -> int:
    required = (root / "backend/uv.lock", root / "web/pnpm-lock.yaml")
    missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
    if missing:
        print("Missing required lockfiles: " + ", ".join(missing), file=sys.stderr)
        return 2
    violations = []
    for path in (*required, root / "web/package.json"):
        if path.is_file():
            violations.extend(f"{path.relative_to(root)}: {name}" for name in sorted(packages(path)) if BANNED.fullmatch(normalize(name)))
    if violations:
        print("Banned AI/ML dependencies:\n" + "\n".join(violations), file=sys.stderr)
        return 1
    print("No banned AI/ML dependencies in either lockfile or web declarations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else ".")))
