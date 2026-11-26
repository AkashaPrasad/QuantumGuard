"""Fail on high-risk baseline findings even when ZAP classifies them as WARN."""

import json
from pathlib import Path
import sys


def check(report: dict) -> int:
    sites = report.get("site")
    if not isinstance(sites, list) or not sites:
        raise ValueError("ZAP produced no site report")
    high = 0
    medium = 0
    for site in sites:
        for alert in site.get("alerts", []):
            risk = int(alert["riskcode"])
            if risk >= 3:
                high += 1
            elif risk == 2:
                medium += 1
    print(f"ZAP high/critical findings: {high}; medium findings requiring review: {medium}")
    return int(high > 0)


if __name__ == "__main__":
    try:
        raise SystemExit(check(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Invalid ZAP report: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(2) from None
