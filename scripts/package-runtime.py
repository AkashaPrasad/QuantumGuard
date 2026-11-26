"""Stage one installable wheel from the server/client namespace source trees."""

import json
from pathlib import Path
import shutil
import sys
import tomllib


def stage(root: Path, output: Path) -> None:
    project = tomllib.loads((root / "backend/pyproject.toml").read_text(encoding="utf-8"))["project"]
    output.mkdir(parents=True, exist_ok=False)
    for source in (root / "backend/qg", root / "cli/qg"):
        if not source.is_dir():
            raise ValueError(f"Missing namespace source: {source}")
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source)
            if "__pycache__" in relative.parts or path.suffix == ".pyc":
                continue
            if path.is_symlink():
                raise ValueError("Runtime package source must not contain symlinks")
            if path.name == "info.txt" or path.name == ".env" or path.name.startswith(".env."):
                raise ValueError("Credential filename in runtime source")
            if not path.is_file():
                continue
            destination = output / "qg" / relative
            if destination.exists():
                raise ValueError(f"Server/client namespace collision: qg/{relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)

    for required in ("qg/app.py", "qg/admin.py"):
        if not (output / required).is_file():
            raise ValueError(f"Core runtime source missing required module: {required}")
    if not (output / "qg/client.py").is_file() and not (output / "qg/client").is_dir():
        raise ValueError("Core runtime source missing qg.client")
    metadata = {
        "name": project["name"],
        "version": project["version"],
        "requires-python": project["requires-python"],
        "dependencies": project.get("dependencies", []),
    }
    text = '[build-system]\nrequires = ["hatchling==1.33.0"]\nbuild-backend = "hatchling.build"\n\n[project]\n'
    text += "\n".join(f"{key} = {json.dumps(value)}" for key, value in metadata.items())
    if project.get("scripts"):
        text += "\n\n[project.scripts]\n"
        text += "\n".join(f"{json.dumps(name)} = {json.dumps(value)}" for name, value in project["scripts"].items())
    text += '\n\n[tool.hatch.build.targets.wheel]\npackages = ["qg"]\n'
    (output / "pyproject.toml").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    stage(Path(sys.argv[1]), Path(sys.argv[2]))
