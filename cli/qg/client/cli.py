"""`qg`: command-line client for QuantumGuard. Standard library argparse only."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .api import ApiError, ClientRefused, Device, QGClient
from .device import DeviceKeys, DeviceState

DEFAULT_KEYSTORE = "~/.qg/device.qgkeystore"
DEFAULT_DEMO_DIR = "~/.qg/demo"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
EVENT_TYPES = {
    "session-revoked": CAEP + "session-revoked",
    "credential-change": CAEP + "credential-change",
    "device-compliance-change": CAEP + "device-compliance-change",
}


class CliError(Exception):
    pass


# ---- helpers ---------------------------------------------------------------------------------------


def _emit(args: argparse.Namespace, obj: Any, text: str | Callable[[], str] | None = None) -> None:
    if getattr(args, "json", False):
        print(json.dumps(obj, sort_keys=True))
    elif text is not None:
        print(text() if callable(text) else text)


def _passphrase() -> str:
    env = os.environ.get("QG_PASSPHRASE")
    return env if env is not None else getpass.getpass("Keystore passphrase: ")


def _keystore_path(args: argparse.Namespace) -> str:
    return os.path.expanduser(getattr(args, "keystore", None) or DEFAULT_KEYSTORE)


def _prepare_dir(path: str) -> None:
    parent = Path(path).parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=0o700)


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_private(path: str, data: bytes, *, force: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise CliError(f"{path} exists; use --force to overwrite") from exc
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)


class Session:
    """A loaded keystore with a signed-in device; saves the state back on exit."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.path = _keystore_path(args)
        self.passphrase = _passphrase()
        self.state = DeviceState.load(self.path, self.passphrase)
        server = getattr(args, "server", None) or self.state.server
        if not self.state.device_id or not server:
            raise CliError("keystore is not enrolled; run `qg enroll` first")
        self.state.server = server
        self.client = QGClient(server)
        self.device: Device = self.client.device(self.state)

    def __enter__(self) -> Device:
        _retry_rate(self.device.login)
        return self.device

    def __exit__(self, *exc: object) -> None:
        self.save()
        self.client.http.close()

    def save(self) -> None:
        self.state.save(self.path, self.passphrase)


def _login_cmd(args: argparse.Namespace) -> Session:
    return Session(args)


def _retry_rate(fn: Callable[[], Any], attempts: int = 15) -> Any:
    """Public endpoints are rate limited per address; wait and retry a few times."""
    for i in range(attempts):
        try:
            return fn()
        except ApiError as exc:
            if exc.status != 429 or i == attempts - 1:
                raise
            time.sleep(2.0)


def _list_all(dev: Device, path: str) -> list[dict[str, Any]]:
    """Read every page of a paginated list ({items, next_before}) or accept a bare list."""
    out: list[dict[str, Any]] = []
    before: str | None = None
    sep = "&" if "?" in path else "?"
    while True:
        data = dev.get(path + (f"{sep}before={before}" if before else ""))
        if isinstance(data, list):
            return out + data
        out += list(data.get("items", []))
        before = data.get("next_before")
        if not before:
            return out


# ---- commands --------------------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    path = _keystore_path(args)
    if os.path.exists(path):
        raise CliError(f"{path} already exists")
    _prepare_dir(path)
    keys = DeviceKeys.generate()
    DeviceState(keys, args.device_name).save(path, _passphrase())
    info = {"keystore": path, "sig_public_key_bytes": len(keys.sig.public_key),
            "kem_public_key_bytes": len(keys.kem.public_key)}
    _emit(args, info, f"keystore written: {path}\nsig public key: {info['sig_public_key_bytes']} bytes\n"
                      f"kem public key: {info['kem_public_key_bytes']} bytes")
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    path = _keystore_path(args)
    pw = _passphrase()
    keys = None
    if os.path.exists(path):
        old = DeviceState.load(path, pw)
        if old.device_id:
            raise CliError(f"{path} is already enrolled")
        keys = old.keys
    _prepare_dir(path)
    client = QGClient(args.server)
    try:
        dev = _retry_rate(lambda: client.enroll(args.code, args.device_name, keys))
        dev.state.save(path, pw)
    finally:
        client.http.close()
    out = {"device_id": dev.state.device_id, "user_id": dev.state.user_id}
    _emit(args, out, f"enrolled device {out['device_id']} for user {out['user_id']}")
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    with _login_cmd(args) as dev:
        info = dict((dev.session.info if dev.session else None) or {})
    info.pop("session_id", None)
    _emit(args, info, lambda: "\n".join(f"{k}: {json.dumps(v) if not isinstance(v, str) else v}"
                                        for k, v in sorted(info.items())))
    return 0


def _commit_out(res: dict[str, Any]) -> dict[str, Any]:
    f = res.get("file") or {}
    return {"file_id": f.get("file_id", res.get("file_id")), "version": f.get("version", res.get("version")),
            "receipt_id": res.get("receipt_id")}


def cmd_protect(args: argparse.Namespace) -> int:
    data = Path(args.path).read_bytes()
    name = args.name or Path(args.path).name
    with _login_cmd(args) as dev:
        res = dev.protect(name, data, args.classification, args.to or [])
    out = _commit_out(res)
    _emit(args, out, f"file_id: {out['file_id']}\nversion: {out['version']}\nreceipt_id: {out['receipt_id']}")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    if os.path.exists(args.out) and not args.force:
        raise CliError(f"{args.out} exists; use --force to overwrite")
    with _login_cmd(args) as dev:
        data = dev.open(args.file_id)
    _write_private(args.out, data, force=args.force)
    _emit(args, {"file_id": args.file_id, "bytes": len(data), "out": args.out},
          f"wrote {len(data)} bytes to {args.out}")
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    """Kit holder (an admin): open a file through its recovery wrap after a recovery_release change was applied."""
    from qg.keys import load_recovery_kit

    if os.path.exists(args.out) and not args.force:
        raise CliError(f"{args.out} exists; use --force to overwrite")
    try:
        kit = load_recovery_kit(Path(args.kit))
    except (OSError, ValueError, KeyError) as exc:
        raise CliError(f"cannot read recovery kit: {exc}") from exc
    with _login_cmd(args) as dev:
        data = dev.recover(args.file_id, args.change, kit)
    _write_private(args.out, data, force=args.force)
    _emit(args, {"file_id": args.file_id, "change_id": args.change, "bytes": len(data), "out": args.out},
          f"recovered {len(data)} bytes to {args.out}")
    return 0


def cmd_files(args: argparse.Namespace) -> int:
    with _login_cmd(args) as dev:
        files = _list_all(dev, "/api/v1/files")
    rows = [{k: f.get(k) for k in ("name", "file_id", "classification", "version", "can_open")} for f in files]

    def text() -> str:
        return "\n".join(f"{r['name']}  {r['file_id']}  {r['classification']}  v{r['version']}  "
                         f"can_open={r['can_open']}" for r in rows) or "no files"

    _emit(args, {"files": rows}, text)
    return 0


def cmd_share(args: argparse.Namespace) -> int:
    with _login_cmd(args) as dev:
        res = dev.share(args.file_id, args.to)
    _emit(args, res if isinstance(res, dict) else {"ok": True}, f"shared {args.file_id} with {len(args.to)} device(s)")
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    with _login_cmd(args) as dev:
        devices = _list_all(dev, "/api/v1/devices" + ("?scope=all" if args.all else ""))

    def text() -> str:
        return "\n".join(f"{d.get('device_id')}  {d.get('name')}  user={d.get('user_id')}  "
                         f"status={d.get('status', 'active')}" for d in devices) or "no devices"

    _emit(args, {"devices": devices}, text)
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    query = "&".join(f"{k}={v}" for k, v in (("status", args.status), ("rule_id", args.rule)) if v)
    with _login_cmd(args) as dev:
        alerts = _list_all(dev, "/api/v1/alerts" + (f"?{query}" if query else ""))

    def text() -> str:
        lines = []
        for a in alerts:
            who = a.get("identity") or {}
            ident = who.get("name") or who.get("device_id") or who.get("source") or "-"
            event = (a.get("event") or {}).get("kind", "-")
            lines.append(f"{a['ts']}  {a['rule_id']}  {a['severity']:<8}  {a['status']:<12}  identity={ident}  "
                         f"service={a.get('service', '-')}  event={event}  {a['summary']}")
        return "\n".join(lines) or "no alerts"

    _emit(args, {"alerts": alerts}, text)
    return 0


def _revoke_out(args: argparse.Namespace, res: dict[str, Any]) -> int:
    keys = ("incident_id", "time_to_enforce_ms", "sessions_ended", "slots_deleted", "receipt_id")
    out = {k: res.get(k) for k in keys}
    _emit(args, out, "\n".join(f"{k}: {v}" for k, v in out.items()))
    return 0


def cmd_report_lost(args: argparse.Namespace) -> int:
    body: dict[str, Any] = {"lost_at": args.lost_at or _now_rfc3339()}
    if args.note:
        body["note"] = args.note
    with _login_cmd(args) as dev:
        res = dev.post(f"/api/v1/devices/{args.device_id}/report-lost", body)
    return _revoke_out(args, res)


def cmd_revoke(args: argparse.Namespace) -> int:
    with _login_cmd(args) as dev:
        res = dev.post(f"/api/v1/devices/{args.device_id}/revoke",
                       {"compromise_time": args.compromise_time, "reason": args.reason})
    return _revoke_out(args, res)


def cmd_rekey(args: argparse.Namespace) -> int:
    if not args.pending:
        raise CliError("only `qg rekey --pending` is supported")
    with _login_cmd(args) as dev:
        shares = dev.catch_up_shares()
        done = dev.rekey_all()
    ids = [_commit_out(d)["file_id"] for d in done]
    out = {"shares_caught_up": shares, "rekeyed": len(done), "file_ids": ids}
    _emit(args, out, f"shares caught up: {shares}\nrekeyed: {len(done)}" + "".join(f"\n  {i}" for i in ids))
    return 0


def cmd_export_bundle(args: argparse.Namespace) -> int:
    with _login_cmd(args) as dev:
        bundle = dev.get(f"/api/v1/incidents/{args.incident_id}/bundle")
    _write_private(args.out, (json.dumps(bundle, sort_keys=True, indent=2) + "\n").encode(), force=True)
    _emit(args, {"incident_id": args.incident_id, "out": args.out}, f"bundle written to {args.out}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from qg.log.verify import verify_bundle  # offline: no network anywhere on this path

    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot read bundle: {exc}") from exc
    pinned = None
    if args.keys:
        try:
            pinned = json.loads(Path(args.keys).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CliError(f"cannot read keys file: {exc}") from exc
        if "server_keys" in pinned and isinstance(pinned["server_keys"], dict):
            pinned = pinned["server_keys"]
    else:
        print("warning: server keys taken from the bundle, not pinned", file=sys.stderr)
    res = verify_bundle(bundle, pinned)
    if args.json:
        print(json.dumps(res, sort_keys=True))
    else:
        for c in res.get("checks", []):
            print(f"[{'ok' if c.get('ok') else 'FAIL'}] {c.get('step')}: {c.get('detail')}")
        if res["ok"]:
            print("bundle verified")
        else:
            if not any(not c.get("ok") for c in res.get("checks", [])):
                print(f"[FAIL] {res['failed_step']}: {res['detail']}")
            if res.get("first_bad_index") is not None:
                print(f"first bad index: {res['first_bad_index']}")
    return 0 if res["ok"] else 1


def cmd_server_keys(args: argparse.Namespace) -> int:
    client = QGClient(args.server)
    try:
        keys = _retry_rate(client.meta)["server_keys"]
    finally:
        client.http.close()
    pinned = {"ed25519_pk": keys["ed25519_pk"], "mldsa_pk": keys["mldsa_pk"]}
    _write_private(args.out, (json.dumps(pinned, sort_keys=True, indent=2) + "\n").encode(), force=True)
    _emit(args, {"out": args.out}, f"server keys written to {args.out}")
    return 0


def cmd_signal(args: argparse.Namespace) -> int:
    now = int(time.time())
    event: dict[str, Any] = {"subject": {"format": "opaque", "id": args.subject}, "event_timestamp": now}
    if args.reason:
        event["reason_admin"] = args.reason
    if args.type == "credential-change":
        event.update({"credential_type": "device", "change_type": "revoke"})
    elif args.type == "device-compliance-change":
        current = args.status or "not-compliant"
        event.update({"previous_status": "compliant" if current == "not-compliant" else "not-compliant",
                      "current_status": current})
    body = {"iss": "qg-cli", "jti": secrets.token_hex(16), "iat": now, "aud": "quantumguard",
            "events": {EVENT_TYPES[args.type]: event}}
    with _login_cmd(args) as dev:
        try:
            res = dev.post("/api/v1/signals", body)
        except ApiError as exc:
            if exc.status != 404:
                raise
            _emit(args, {"sent": False, "status": 404}, "signals endpoint not available on this server (404)")
            return 1
    out = res if isinstance(res, dict) else {"ok": True}
    _emit(args, out, "signal accepted: " + json.dumps(out, sort_keys=True))
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    from qg.crypto import aead, keystore, xwing
    from qg.crypto.sign import MLDSAKey, mldsa_verify

    checks: list[dict[str, Any]] = []

    def check(name: str, fn: Callable[[], bool]) -> None:
        try:
            ok = bool(fn())
        except Exception:  # noqa: BLE001 - a selftest reports every failure as a failed check
            ok = False
        checks.append({"name": name, "ok": ok})

    def xwing_rt() -> bool:
        sk = xwing.XWingPrivateKey.generate()
        ss, ct = xwing.encapsulate(sk.public_key)
        return sk.decapsulate(ct) == ss and len(ss) == 32

    def sign_ctx() -> bool:
        k = MLDSAKey.generate()
        sig = k.sign(b"selftest", "manifest")
        return mldsa_verify(k.public_key, sig, b"selftest", "manifest")

    def sign_other_ctx() -> bool:
        k = MLDSAKey.generate()
        sig = k.sign(b"selftest", "manifest")
        return not mldsa_verify(k.public_key, sig, b"selftest", "share")

    data = os.urandom(3000)

    def aead_rt() -> bool:
        dek = os.urandom(32)
        blobs = aead.encrypt_file(dek, "fil_selftest", 1, data)
        return b"".join(aead.decrypt_chunks(dek, "fil_selftest", 1, blobs, len(blobs))) == data

    def aead_flip() -> bool:
        dek = os.urandom(32)
        blobs = aead.encrypt_file(dek, "fil_selftest", 1, data)
        bad = bytearray(blobs[0])
        bad[len(bad) // 2] ^= 0x01
        try:
            b"".join(aead.decrypt_chunks(dek, "fil_selftest", 1, [bytes(bad), *blobs[1:]], len(blobs)))
        except aead.AeadError:
            return True
        return False

    def keystore_rt() -> bool:
        pw = secrets.token_urlsafe(16)
        seeds = keystore.DeviceSeeds(sig_seed=os.urandom(32), kem_seed=os.urandom(32))
        doc = keystore.seal_keystore(seeds, pw, {"user_id": None, "device_id": None, "device_name": "selftest",
                                                 "server": None, "created_at": ""})
        back = keystore.open_keystore(doc, pw)
        if (back.sig_seed, back.kem_seed) != (seeds.sig_seed, seeds.kem_seed):
            return False
        try:
            keystore.open_keystore(doc, pw + "x")
        except keystore.KeystoreError:
            return True
        return False

    check("xwing round trip", xwing_rt)
    check("ml-dsa-65 sign and verify with context", sign_ctx)
    check("ml-dsa-65 refuses another context", sign_other_ctx)
    check("aes-gcm chunk round trip", aead_rt)
    check("aes-gcm refuses a flipped bit", aead_flip)
    check("keystore seal and open", keystore_rt)
    ok = all(c["ok"] for c in checks)
    if args.json:
        print(json.dumps({"selftest": "pass" if ok else "fail", "checks": checks}))
    else:
        for c in checks:
            print(f"[{'ok' if c['ok'] else 'FAIL'}] {c['name']}")
        print("selftest " + ("pass" if ok else "fail"))
    return 0 if ok else 1


def cmd_demo_seed(args: argparse.Namespace) -> int:
    pw = os.environ.get("QG_PASSPHRASE")
    if not pw:
        raise CliError("QG_PASSPHRASE must be set for `qg demo seed`")
    proc = subprocess.run(
        [sys.executable, "-m", "qg.admin", "invite", "--all", "--json"], env=dict(os.environ),
        capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode != 0:
        raise CliError("could not create invites with qg.admin (run this where the server data directory is)")
    invites = json.loads(proc.stdout)["invites"]
    out_dir = Path(os.path.expanduser(args.dir or DEFAULT_DEMO_DIR))
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    devices: dict[str, Device] = {}
    people: list[dict[str, Any]] = []
    for inv in invites:
        name = inv["name"]
        slug = "".join(ch if ch.isalnum() else "-" for ch in name.lower())
        client = QGClient(args.server)
        code, dn = inv["code"], f"{name.split()[0]} demo laptop"

        def enrol(c: QGClient = client, code: str = code, dn: str = dn) -> Any:
            return c.enroll(code, dn)

        dev = _retry_rate(enrol)
        dev.state.save(str(out_dir / f"{slug}.qgkeystore"), pw)
        devices[name] = dev
        people.append({"name": name, "user_id": dev.state.user_id, "device_id": dev.state.device_id})
    files: list[str] = []
    aiko, daniel = devices.get("Aiko Tanaka"), devices.get("Daniel Mensah")
    if aiko is not None:
        _retry_rate(aiko.login)
        specs = [("quarterly-notes.txt", b"Synthetic demo file: quarterly notes.\n" * 20, "confidential",
                  [daniel.device_id] if daniel else []),
                 ("roadmap-draft.txt", b"Synthetic demo file: roadmap draft.\n" * 20, "internal", [])]
        for fname, content, cls, to in specs:
            res = aiko.protect(fname, content, cls, to)
            files.append(_commit_out(res)["file_id"])
        aiko.state.save(str(out_dir / "aiko-tanaka.qgkeystore"), pw)
    print(json.dumps({"people": people, "files": files}, sort_keys=True))
    return 0


# ---- parser ----------------------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print one JSON object on stdout")
    common.add_argument("--keystore", default=DEFAULT_KEYSTORE, help=f"keystore path (default {DEFAULT_KEYSTORE})")
    common.add_argument("--server", default=None, help="server URL (overrides the keystore label)")

    p = argparse.ArgumentParser(prog="qg", description="QuantumGuard command-line client")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, fn: Callable[[argparse.Namespace], int], help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, parents=[common], help=help_)
        sp.set_defaults(fn=fn)
        return sp

    s = add("keygen", cmd_keygen, "create an unenrolled keystore")
    s.add_argument("--device-name", required=True)
    s = add("enroll", cmd_enroll, "enrol this device with an invite code")
    s.add_argument("--code", required=True)
    s.add_argument("--device-name", required=True)
    s.set_defaults(server_required=True)
    add("whoami", cmd_whoami, "sign in and show the session")
    s = add("protect", cmd_protect, "encrypt and upload a file")
    s.add_argument("path")
    s.add_argument("--name")
    s.add_argument("--classification", choices=["internal", "confidential", "restricted"], default="confidential")
    s.add_argument("--to", action="append", metavar="DEVICE_ID")
    s = add("open", cmd_open, "download and decrypt a file")
    s.add_argument("file_id")
    s.add_argument("--out", required=True)
    s.add_argument("--force", action="store_true")
    s = add("recover", cmd_recover, "kit holder: open a file with the recovery kit after an applied recovery_release")
    s.add_argument("file_id")
    s.add_argument("--change", required=True, metavar="CHANGE_ID", help="applied recovery_release change")
    s.add_argument("--kit", required=True, help="recovery kit file from `python -m qg.admin recovery-kit init`")
    s.add_argument("--out", required=True)
    s.add_argument("--force", action="store_true")
    add("files", cmd_files, "list files")
    s = add("share", cmd_share, "share a file with devices")
    s.add_argument("file_id")
    s.add_argument("--to", action="append", required=True, metavar="DEVICE_ID")
    s = add("alerts", cmd_alerts, "list alerts with the identity, service and event each names (operator, auditor)")
    s.add_argument("--status", choices=["open", "acknowledged"])
    s.add_argument("--rule", metavar="QG-R0NN")
    s = add("devices", cmd_devices, "list devices")
    s.add_argument("--all", action="store_true")
    s = add("report-lost", cmd_report_lost, "report one of your devices lost")
    s.add_argument("device_id")
    s.add_argument("--lost-at")
    s.add_argument("--note")
    s = add("revoke", cmd_revoke, "revoke a device (operator)")
    s.add_argument("device_id")
    s.add_argument("--compromise-time", required=True)
    s.add_argument("--reason", required=True)
    s = add("rekey", cmd_rekey, "re-encrypt pending files")
    s.add_argument("--pending", action="store_true")
    s = add("export-bundle", cmd_export_bundle, "download an incident proof bundle")
    s.add_argument("incident_id")
    s.add_argument("--out", required=True)
    s = add("verify", cmd_verify, "verify a proof bundle offline")
    s.add_argument("bundle")
    s.add_argument("--keys")
    s = add("server-keys", cmd_server_keys, "save the server public keys for pinning")
    s.add_argument("--out", required=True)
    s.set_defaults(server_required=True)
    s = add("signal", cmd_signal, "send a SET-shaped signal")
    s.add_argument("--type", required=True, choices=sorted(EVENT_TYPES))
    s.add_argument("--subject", required=True)
    s.add_argument("--status", choices=["compliant", "not-compliant"])
    s.add_argument("--reason")
    add("selftest", cmd_selftest, "run offline cryptographic self checks")
    demo = sub.add_parser("demo", help="demo helpers")
    dsub = demo.add_subparsers(dest="demo_command", required=True)
    s = dsub.add_parser("seed", parents=[common], help="enrol the seeded people and create sample files")
    s.add_argument("--dir")
    s.set_defaults(fn=cmd_demo_seed, server_required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if getattr(args, "server_required", False) and not args.server:
        print("error: --server is required", file=sys.stderr)
        return 1
    try:
        return int(args.fn(args))
    except ApiError as exc:
        print(f"error: {exc.status} {exc.code}: {exc.reason}", file=sys.stderr)
    except ClientRefused as exc:
        print(f"error: client refused: {exc}", file=sys.stderr)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - one-line message, never a traceback with key material
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
