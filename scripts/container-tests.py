"""Run Python suites and scenarios in the isolated Docker test profile."""

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path("/app")
SCENARIOS = ("normal", "revoke", "interrupt", "verify", "rotate", "privilege")


def main(arguments: list[str]) -> int:
    os.chdir(ROOT)
    # conftest writes claims.json under the repository root. Keep /app read-only
    # by directing that artifact to the profile's writable report volume.
    os.environ["QG_CLAIMS_PATH"] = "/results/claims.json"
    if arguments and arguments[0] == "scenario":
        names = arguments[1:] or list(SCENARIOS)
        if any(name not in (*SCENARIOS, "messaging") for name in names):
            print("Unknown scenario", file=sys.stderr)
            return 2
        for name in names:
            result = subprocess.run([sys.executable, "-m", "qg.scenarios", name], check=False)  # nosec B603
            if result.returncode:
                return result.returncode
        return 0
    command = [sys.executable, "-m", "pytest", "-c", "backend/pyproject.toml", "--rootdir", "/app", "-p", "no:cacheprovider"]
    if arguments:
        return subprocess.run([*command, *arguments], check=False).returncode  # nosec B603
    tooling = subprocess.run(  # nosec B603
        [sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"],
        check=False,
    )
    if tooling.returncode:
        return tooling.returncode
    # --security-strict is registered by tests/security/conftest.py, which pytest only loads
    # as an initial conftest when that directory is named, so the suites run separately.
    result = subprocess.run([*command, "tests", "--ignore=tests/security"], check=False)  # nosec B603
    if result.returncode:
        return result.returncode
    result = subprocess.run([*command, "tests/security", "--security-strict"], check=False)  # nosec B603
    if result.returncode:
        return result.returncode
    return main(["scenario"])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
