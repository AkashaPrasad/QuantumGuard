"""Offline verification of a proof bundle with public keys only (spec/SUITE.md section 9.4). Used by
`qg verify`; it never contacts the server."""

from __future__ import annotations

from typing import Any

from qg.crypto.encoding import EncodingError, b64u_decode, canon
from qg.crypto.sign import verify_dual
from qg.crypto.suite import SUITE

from . import merkle


def _fail(step: str, detail: str, checks: list[dict[str, Any]], first_bad_index: int | None = None) -> dict[str, Any]:
    checks.append({"step": step, "ok": False, "detail": detail})
    return {"ok": False, "failed_step": step, "detail": detail, "first_bad_index": first_bad_index,
            "checks": checks}


def verify_bundle(bundle: Any, pinned: dict[str, str] | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    if not isinstance(bundle, dict) or bundle.get("format") != "qg-proof-bundle/1" or bundle.get("suite") != SUITE:
        return _fail("format", "not a QG-1 proof bundle", checks)
    keys = pinned or bundle.get("server_keys") or {}
    try:
        ed = b64u_decode(keys["ed25519_pk"], length=32)
        pq = b64u_decode(keys["mldsa_pk"], length=1952)
    except (KeyError, TypeError, EncodingError):
        return _fail("keys", "server public keys missing or malformed", checks)
    if pinned and bundle.get("server_keys") != {"ed25519_pk": pinned["ed25519_pk"], "mldsa_pk": pinned["mldsa_pk"]}:
        return _fail("keys", "bundle keys differ from the pinned server keys", checks)
    checks.append({"step": "keys", "ok": True, "detail": "pinned" if pinned else "taken from the bundle (not pinned)"})

    cp = bundle.get("checkpoint")
    if not verify_dual(cp, "checkpoint", ed, pq):
        return _fail("checkpoint", "checkpoint signatures do not both verify", checks)
    checks.append({"step": "checkpoint", "ok": True, "detail": f"tree_size {cp['tree_size']}"})
    if not verify_dual(bundle, "report", ed, pq):
        return _fail("report", "bundle signatures do not both verify", checks)
    checks.append({"step": "report", "ok": True, "detail": "bundle signed by the server"})

    try:
        root = b64u_decode(cp["root_hash"], length=32)
        size = cp["tree_size"]
    except (KeyError, EncodingError):
        return _fail("checkpoint", "malformed checkpoint", checks)

    last = -1
    for k, e in enumerate(bundle.get("entries") or []):
        idx = e.get("leaf_index") if isinstance(e, dict) else None
        try:
            receipt = e["receipt"]
            leaf_hash = merkle.leaf_hash(canon(receipt))
            claimed = b64u_decode(e["leaf_hash"], length=32)
            path = [b64u_decode(p, length=32) for p in e["audit_path"]]
        except (KeyError, TypeError, ValueError, EncodingError):
            return _fail("entries", f"entry {k} is malformed", checks, idx)
        if not isinstance(idx, int) or idx <= last or receipt.get("leaf_index") != idx:
            return _fail("entries", f"entry {k} has a bad or out-of-order leaf_index", checks, idx)
        last = idx
        if leaf_hash != claimed:
            return _fail("entries", f"receipt at leaf {idx} does not match its leaf hash", checks, idx)
        if not merkle.verify_inclusion(idx, size, leaf_hash, path, root):
            return _fail("entries", f"inclusion proof for leaf {idx} does not reach the signed root", checks, idx)
    checks.append({"step": "entries", "ok": True, "detail": f"{len(bundle.get('entries') or [])} receipts included"})

    rev = bundle.get("revocation_checkpoint")
    if rev:
        if not verify_dual(rev, "checkpoint", ed, pq):
            return _fail("revocation_checkpoint", "revocation checkpoint signatures do not both verify", checks)
        try:
            proof = [b64u_decode(p, length=32) for p in bundle.get("consistency") or []]
            ok = merkle.verify_consistency(rev["tree_size"], size, proof, b64u_decode(rev["root_hash"], length=32), root)
        except (KeyError, EncodingError):
            ok = False
        if rev["tree_size"] and not ok:
            return _fail("consistency", "log is not an append-only extension of the revocation checkpoint", checks)
        checks.append({"step": "consistency", "ok": True,
                       "detail": f"append-only from {rev['tree_size']} to {size}"})
    directory = bundle.get("directory")
    if directory is not None:
        if not verify_dual(directory, "directory", ed, pq):
            return _fail("directory", "directory signatures do not both verify", checks)
        checks.append({"step": "directory", "ok": True, "detail": f"epoch {directory['epoch']}"})
    return {"ok": True, "failed_step": None, "detail": "all checks passed", "first_bad_index": None,
            "checks": checks}
