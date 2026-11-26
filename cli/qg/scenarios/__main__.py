"""python -m qg.scenarios <normal|revoke|interrupt|verify|rotate|privilege|messaging>"""

from __future__ import annotations

import importlib
import sys
import traceback

from qg.scenarios.harness import result

NAMES = ("normal", "revoke", "interrupt", "verify", "rotate", "privilege", "messaging")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in NAMES:
        print("usage: python -m qg.scenarios " + "|".join(NAMES), file=sys.stderr)
        return 2
    name = argv[0]
    try:
        return importlib.import_module(f"qg.scenarios.{name}").run()
    except Exception as exc:  # noqa: BLE001 - one JSON line even on unexpected failure
        traceback.print_exc(file=sys.stderr)
        return result(name, False, error=f"{type(exc).__name__}: {exc}"[:300])


if __name__ == "__main__":
    sys.exit(main())
