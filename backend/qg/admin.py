"""Local administration that needs the data and keys directories (the same trust as owning the server).

    python -m qg.admin invite --all --json          one 24-hour single-use code per seeded person
    python -m qg.admin invite --user-id usr_... --json
    python -m qg.admin policy-sign                  accept the current rules.yaml as the signed bundle
    python -m qg.admin policy-down | policy-up      operational switch: policy engine unavailable (fail closed)
    python -m qg.admin decoys --json                ids of planted decoy objects (for drills)

Codes go to this command's standard output only; the server never prints or logs them.
"""

from __future__ import annotations

import argparse
import json
import sys

from qg.config import Settings


def _core():  # noqa: ANN202
    from qg.core import Core

    settings = Settings.from_env()
    return Core(settings, log_sink=lambda _line: None)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m qg.admin")
    sub = p.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("invite")
    g = inv.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true")
    g.add_argument("--user-id", action="append")
    inv.add_argument("--json", action="store_true")
    sub.add_parser("policy-sign")
    sub.add_parser("policy-down")
    sub.add_parser("policy-up")
    dec = sub.add_parser("decoys")
    dec.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    settings = Settings.from_env()

    if args.cmd == "policy-down":
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        (settings.data_dir / "policy.down").write_text("down\n")
        print(json.dumps({"policy": "unavailable"}))
        return 0
    if args.cmd == "policy-up":
        (settings.data_dir / "policy.down").unlink(missing_ok=True)
        print(json.dumps({"policy": "available"}))
        return 0

    core = _core()
    try:
        if args.cmd == "invite":
            try:
                invites = core.issue_bootstrap_invites(None if args.all else args.user_id)
            except KeyError as exc:
                print(json.dumps({"error": "unknown_user", "user_id": str(exc.args[0])}), file=sys.stderr)
                return 1
            if args.json:
                print(json.dumps({"invites": invites}))
            else:
                for i in invites:
                    print(f"{i['name']:<20} {','.join(i['roles']):<10} {i['code']}  (until {i['expires_at']})")
            return 0
        if args.cmd == "policy-sign":
            print(json.dumps({"policy_bundle_hash": core.resign_policy()}))
            return 0
        if args.cmd == "decoys":
            files = [r[0] for r in core.db.all("SELECT file_id FROM files WHERE is_decoy = 1")]
            keys = [r[0] for r in core.db.all(
                "SELECT k.key_id FROM service_keys k JOIN services s ON s.service_id = k.service_id WHERE s.is_decoy = 1")]
            print(json.dumps({"files": files, "service_keys": keys}))
            return 0
    finally:
        core.db.close()
    return 2


if __name__ == "__main__":
    sys.exit(main())
