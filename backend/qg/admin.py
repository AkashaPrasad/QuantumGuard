"""Local administration that needs the data and keys directories (the same trust as owning the server).

    python -m qg.admin invite --all --json          one 24-hour single-use code per seeded person
    python -m qg.admin invite --user-id usr_... --json
    python -m qg.admin policy-sign                  accept the current rules.yaml as the signed bundle
    python -m qg.admin policy-down | policy-up      operational switch: policy engine unavailable (fail closed)
    python -m qg.admin decoys --json                ids of planted decoy objects (for drills)
    python -m qg.admin recovery-kit init [--out PATH]
                                                    issue the recovery kit once: the private half goes to stdout
                                                    or PATH (outside the data and keys volumes); the server keeps
                                                    only the public key
    python -m qg.admin recovery-kit move-legacy --out PATH
                                                    move a kit that an older build left in the keys volume

Codes go to this command's standard output only; the server never prints or logs them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

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
    kit = sub.add_parser("recovery-kit")
    kit.add_argument("action", choices=["init", "move-legacy"])
    kit.add_argument("--out", help="file for the private kit (outside QG_DATA_DIR and QG_KEYS_DIR)")
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

    if args.cmd == "recovery-kit":
        return _recovery_kit(args, settings)

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


def _outside_volumes(path: Path, settings: Settings) -> bool:
    p = path.resolve()
    return not any(p == d or p.is_relative_to(d) for d in (settings.data_dir.resolve(), settings.keys_dir.resolve()))


def _write_kit(doc: dict, out: str | None, settings: Settings) -> None:
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if out is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    path = Path(out)
    if not _outside_volumes(path, settings):
        raise ValueError("the kit must not be written inside the data or keys volume")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _recovery_kit(args: argparse.Namespace, settings: Settings) -> int:
    from qg import keys

    if args.action == "move-legacy":
        legacy = settings.keys_dir / keys.LEGACY_RECOVERY_FILE
        if not legacy.exists():
            print(json.dumps({"error": "no_legacy_kit"}), file=sys.stderr)
            return 1
        if not args.out:
            print(json.dumps({"error": "out_required"}), file=sys.stderr)
            return 2
        try:
            _write_kit(json.loads(legacy.read_text()), args.out, settings)
        except (ValueError, FileExistsError) as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 1
        legacy.unlink()  # the operator now holds the kit at --out
        print(json.dumps({"moved_to": str(Path(args.out).resolve())}), file=sys.stderr)
        return 0

    core = _core()
    try:
        if core.recovery.get() is not None:
            print(json.dumps({"error": "already_issued"}), file=sys.stderr)
            return 1
        now = core.clock.iso()
        doc, public_key = keys.new_recovery_kit(now)
        try:
            _write_kit(doc, args.out, settings)  # the private half reaches the operator before anything uses it
        except (ValueError, FileExistsError, OSError) as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 1
        try:
            keys.activate_recovery_public_key(settings.keys_dir, public_key, now)
        except keys.RecoveryKitError:
            print(json.dumps({"error": "already_issued", "detail": "another kit was issued concurrently; discard "
                              "the kit just written"}), file=sys.stderr)
            return 1
        with core.db.tx() as conn:
            epoch = core.directory.publish(conn, "recovery_kit")["epoch"]
        print(json.dumps({"recovery_kit": "issued", "directory_epoch": epoch,
                          "written_to": str(Path(args.out).resolve()) if args.out else "stdout"}), file=sys.stderr)
        return 0
    finally:
        core.db.close()


if __name__ == "__main__":
    sys.exit(main())
