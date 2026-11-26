"""Generate QuantumGuard's own QG-1 vectors (canonical JSON, transcripts, request MAC, envelope,
keystore, Merkle, checkpoint). Run once; the committed JSON is what both clients replay.

All key material here is throwaway test data derived from public labels with SHAKE-256, so the
files contain no secret of any running system.

Usage: PYTHONPATH=backend python spec/vectors/generate.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from qg.crypto import aead, kdf, keystore, transcripts, xwing
from qg.crypto.encoding import b64u, canon
from qg.crypto.sign import DualSigner, Ed25519Key, MLDSAKey
from qg.crypto.suite import SUITE
from qg.log import merkle

OUT = Path(__file__).resolve().parent


def det(label: str, n: int) -> bytes:
    """Deterministic test bytes: SHAKE-256 of a public label."""
    return hashlib.shake_256(("QG-1 test vector/" + label).encode()).digest(n)


def plaintext_for(label: str, n: int) -> bytes:
    """Plaintext generator documented in envelope.json: SHAKE-128 of the label, n bytes."""
    return hashlib.shake_128(label.encode()).digest(n)


def write(name: str, doc: dict[str, Any]) -> None:
    (OUT / f"{name}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(name, "written")


def canonical_json() -> dict[str, Any]:
    valid_inputs: list[Any] = [
        {},
        [],
        {"b": 1, "a": 2},
        {"suite": "QG-1", "z": [3, 2, 1], "a": {"y": None, "x": True, "w": False}},
        {"n": -42, "big": 9007199254740991, "neg": -9007199254740991, "zero": 0},
        {"s": "quote\" backslash\\ slash/ tab\t nl\n cr\r bs\b ff\f"},
        {"s": "ctl\u0001\u001f del\u007f"},
        {"s": "Grüße, 東京, emoji \U0001f510"},
        {"A": 1, "_": 2, "a": 3, "Z": 4, "0": 5, "-": 6},
        [{"b": [1, {"d": 1, "c": 2}]}, "x"],
    ]
    valid = [
        {"input": v, "output": canon(v).decode("utf-8"), "output_hex": canon(v).hex()} for v in valid_inputs
    ]
    invalid = [
        {"json": "1.0", "why": "float"},
        {"json": "1e3", "why": "exponent"},
        {"json": "{\"a\":0.5}", "why": "float member"},
        {"json": "-0", "why": "negative zero"},
        {"json": "9007199254740992", "why": "integer above 2^53-1"},
        {"json": "-9007199254740992", "why": "integer below -(2^53-1)"},
        {"json": "{\"a\":1,\"a\":2}", "why": "duplicate key"},
        {"json": "{\"\u00e9\":1}", "why": "non-ASCII key"},
        {"json": "\"\\ud800\"", "why": "lone surrogate"},
        {"json": "NaN", "why": "non-finite"},
    ]
    return {
        "description": "spec/SUITE.md section 2.2. For valid cases canon(input) must equal output_hex exactly. "
        "Invalid cases are JSON texts that a strict parser plus canonicaliser must reject.",
        "valid": valid,
        "invalid": invalid,
    }


def b64u_vectors() -> dict[str, Any]:
    cases = [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", bytes([0xFB, 0xFF, 0xBF])]
    return {
        "valid": [{"hex": c.hex(), "b64u": b64u(c)} for c in cases],
        "invalid": ["Zg==", "Zg=", "Zh", "Z", "Zm9v+", "Zm9v/", "Zm 9v", "Zm9vYg=", "+/8"],
    }


def request_mac() -> dict[str, Any]:
    k_mac = det("k_mac", 48)
    cases = [
        ("GET", "/api/v1/files", 1, b""),
        ("GET", "/api/v1/files?q=lab%20notes&classification=restricted", 2, b""),
        ("POST", "/api/v1/files", 7, canon({"chunk_count": 1, "classification": "restricted", "name": "a.txt", "size_bytes": 5})),
        ("PUT", "/api/v1/files/fil_AAAAAAAAAAAAAAAAAAAAAA/versions/1/chunks/0", 9007199254740991, det("chunk", 64)),
        ("delete", "/api/v1/invites/inv_AAAAAAAAAAAAAAAAAAAAAA", 12, b""),
    ]
    out = []
    for method, path, seq, body in cases:
        mi = transcripts.mac_input(method, path, seq, body)
        out.append(
            {
                "method": method,
                "path": path,
                "seq": seq,
                "body_hex": body.hex(),
                "mac_input_hex": mi.hex(),
                "mac_b64u": transcripts.request_mac(k_mac, method, path, seq, body),
                "request_hash_b64u": transcripts.request_hash(method, path, seq, body),
            }
        )
    return {
        "description": "spec/SUITE.md section 6. METHOD is upper-cased before use.",
        "k_mac": k_mac.hex(),
        "cases": out,
    }


def transcripts_vectors() -> dict[str, Any]:
    kem = xwing.XWingPrivateKey.from_seed(det("device kem", 32))
    sig = MLDSAKey.from_seed(det("device sig", 32))
    kem_pk, sig_pk = b64u(kem.public_key), b64u(sig.public_key)

    ss_e, ct_e = xwing.encapsulate(kem.public_key)
    challenge_e = det("enroll challenge", 32)
    enroll_fields = dict(
        enroll_id="enr_" + b64u(det("enroll id", 16)),
        user_id="usr_" + b64u(det("user id", 16)),
        device_name="Aiko's laptop",
        kem_pk_b64u=kem_pk,
        sig_pk_b64u=sig_pk,
        challenge_b64u=b64u(challenge_e),
        xwing_ct_b64u=b64u(ct_e),
        directory_epoch=7,
        server_time="2026-11-26T12:00:00.000Z",
    )
    t_e = transcripts.enroll_transcript(**enroll_fields)
    k_ec = kdf.enroll_confirm_key(ss_e, challenge_e)

    ss_s, ct_s = xwing.encapsulate(kem.public_key)
    challenge_s = det("session challenge", 32)
    session_fields = dict(
        start_id="sst_" + b64u(det("start id", 16)),
        device_id="dev_" + b64u(det("device id", 16)),
        challenge_b64u=b64u(challenge_s),
        xwing_ct_b64u=b64u(ct_s),
        directory_epoch=8,
        server_time="2026-11-26T12:00:05.123Z",
    )
    t_s = transcripts.session_transcript(**session_fields)
    k_sc = kdf.session_confirm_key(ss_s, challenge_s)
    k_mac = kdf.session_mac_key(ss_s, challenge_s)
    return {
        "description": "spec/SUITE.md sections 3 and 5. Decapsulate xwing_ct with kem_seed to get ss, rebuild the "
        "transcript from the fields, derive keys, recompute key_confirm. Signatures are hedged: check that "
        "signature verifies with context QG/v1/<purpose> and that it fails with any other context.",
        "device": {"kem_seed": kem.seed.hex(), "sig_seed": sig.seed.hex(), "kem_pk_b64u": kem_pk, "sig_pk_b64u": sig_pk},
        "enroll": {
            "fields": {
                "enroll_id": enroll_fields["enroll_id"],
                "user_id": enroll_fields["user_id"],
                "device_name": enroll_fields["device_name"],
                "kem_pk": kem_pk,
                "sig_pk": sig_pk,
                "challenge": enroll_fields["challenge_b64u"],
                "xwing_ct": enroll_fields["xwing_ct_b64u"],
                "directory_epoch": 7,
                "server_time": enroll_fields["server_time"],
            },
            "ss": ss_e.hex(),
            "transcript_hex": t_e.hex(),
            "k_ec": k_ec.hex(),
            "confirmation_b64u": b64u(kdf.hmac384(k_ec, t_e)),
            "signature_b64u": b64u(sig.sign(t_e, "enroll")),
        },
        "session": {
            "fields": {
                "start_id": session_fields["start_id"],
                "device_id": session_fields["device_id"],
                "challenge": session_fields["challenge_b64u"],
                "xwing_ct": session_fields["xwing_ct_b64u"],
                "directory_epoch": 8,
                "server_time": session_fields["server_time"],
            },
            "ss": ss_s.hex(),
            "transcript_hex": t_s.hex(),
            "k_sc": k_sc.hex(),
            "k_mac": k_mac.hex(),
            "confirmation_b64u": b64u(kdf.hmac384(k_sc, t_s)),
            "signature_b64u": b64u(sig.sign(t_s, "session")),
        },
    }


def envelope() -> dict[str, Any]:
    dek = det("dek", 32)
    prefix = det("nonce prefix", 8)
    file_id = "fil_" + b64u(det("file id", 16))
    files = []
    for label, n in (("empty", 0), ("five", 5), ("one chunk exactly", 1_048_576), ("two chunks", 1_048_579)):
        data = plaintext_for("QG-1 plaintext/" + label, n)
        blobs = aead.encrypt_file(dek, file_id, 1, data, prefix)
        files.append(
            {
                "plaintext_label": "QG-1 plaintext/" + label,
                "plaintext_len": n,
                "chunk_count": len(blobs),
                "chunks": [
                    {
                        "index": i,
                        "aad_hex": aead.chunk_aad(file_id, 1, i, i == len(blobs) - 1).hex(),
                        "len": len(b),
                        "sha256": hashlib.sha256(b).hexdigest(),
                        "head_hex": b[:48].hex(),
                        "tail_hex": b[-48:].hex(),
                        **({"blob_hex": b.hex()} if len(b) <= 256 else {}),
                    }
                    for i, b in enumerate(blobs)
                ],
                "ciphertext_sha256_b64u": b64u(aead.ciphertext_sha256(blobs)),
            }
        )

    rcpt = xwing.XWingPrivateKey.from_seed(det("recipient kem", 32))
    dev_id = "dev_" + b64u(det("recipient id", 16))
    binding = aead.wrap_binding(file_id, 1, dev_id, 9)
    ss, ct = xwing.encapsulate(rcpt.public_key)
    nonce = det("wrap nonce", 12)
    wrapped = aead.wrap_dek_with_secret(ss, dek, binding, nonce)
    negatives = []
    for field, value in (("file_id", "fil_" + b64u(det("other file", 16))), ("version", 2), ("device_id", "recovery"), ("directory_epoch", 8)):
        bad = dict(binding)
        bad[field] = value
        negatives.append({"change": field, "binding": bad, "aad_hex": canon(bad).hex()})

    manifest_signer = MLDSAKey.from_seed(det("manifest signer", 32))
    manifest = {
        "chunk_count": files[3]["chunk_count"],
        "ciphertext_sha256": files[3]["ciphertext_sha256_b64u"],
        "classification": "restricted",
        "directory_epoch": 9,
        "file_id": file_id,
        "recipients": sorted([dev_id, "dev_" + b64u(det("second recipient", 16))]),
        "suite": SUITE,
        "version": 1,
    }
    share = {
        "directory_epoch": 9,
        "file_id": file_id,
        "recipients": ["dev_" + b64u(det("third recipient", 16))],
        "suite": SUITE,
        "version": 1,
    }
    return {
        "description": "spec/SUITE.md section 7. Plaintext for each file is SHAKE128(utf8(plaintext_label)) truncated "
        "to plaintext_len bytes. Encrypt with dek and nonce_prefix and compare every chunk; blob = nonce || ct || tag.",
        "dek": dek.hex(),
        "nonce_prefix": prefix.hex(),
        "file_id": file_id,
        "version": 1,
        "files": files,
        "wrap": {
            "recipient_kem_seed": rcpt.seed.hex(),
            "recipient_kem_pk_b64u": b64u(rcpt.public_key),
            "binding": binding,
            "aad_hex": canon(binding).hex(),
            "xwing_ct_b64u": b64u(ct),
            "ss": ss.hex(),
            "kek": kdf.wrap_key(ss).hex(),
            "nonce": nonce.hex(),
            "wrapped_dek_b64u": b64u(wrapped),
            "inner_wrap": {"xwing_ct": b64u(ct), "wrapped_dek": b64u(wrapped)},
            "must_fail_with_binding": negatives,
        },
        "manifest": {
            "signer_sig_seed": manifest_signer.seed.hex(),
            "signer_sig_pk_b64u": b64u(manifest_signer.public_key),
            "manifest": manifest,
            "canonical_hex": canon(manifest).hex(),
            "manifest_sig_b64u": b64u(manifest_signer.sign(canon(manifest), "manifest")),
        },
        "share": {
            "share": share,
            "canonical_hex": canon(share).hex(),
            "share_sig_b64u": b64u(manifest_signer.sign(canon(share), "share")),
        },
    }


def keystore_vectors() -> dict[str, Any]:
    seeds = keystore.DeviceSeeds(sig_seed=det("ks sig", 32), kem_seed=det("ks kem", 32))
    label = {
        "created_at": "2026-11-26T12:00:00.000Z",
        "device_id": None,
        "device_name": "Priya's workstation",
        "server": None,
        "user_id": None,
    }
    passphrase = "correct horse battery staple caf\u00e9"  # noqa: S105 - public test vector
    doc = keystore.seal_keystore(seeds, passphrase, label, salt=det("ks salt", 16), nonce=det("ks nonce", 12))
    key = keystore.derive_key(passphrase, doc["kdf"])
    tampered_label = json.loads(json.dumps(doc))
    tampered_label["label"]["device_name"] = "Mallory"
    heavy = json.loads(json.dumps(doc))
    heavy["kdf"]["m_kib"] = 4_194_304
    return {
        "description": "spec/SUITE.md section 15. Opening `keystore` with `passphrase` (or its NFD form) yields the "
        "seeds; every entry of must_fail must be rejected without revealing why.",
        "passphrase": passphrase,
        "passphrase_nfd": "correct horse battery staple cafe\u0301",
        "argon2_output": key.hex(),
        "aad_hex": canon({k: v for k, v in doc.items() if k != "ciphertext"}).hex(),
        "sig_seed": seeds.sig_seed.hex(),
        "kem_seed": seeds.kem_seed.hex(),
        "keystore": doc,
        "must_fail": [
            {"why": "wrong passphrase", "passphrase": "correct horse battery staple", "keystore": doc},
            {"why": "label changed", "passphrase": passphrase, "keystore": tampered_label},
            {"why": "memory parameter above bound", "passphrase": passphrase, "keystore": heavy},
        ],
    }


def merkle_vectors() -> dict[str, Any]:
    leaves = [f"leaf-{i}".encode() for i in range(9)]
    hashes = [merkle.leaf_hash(x) for x in leaves]
    roots = [{"tree_size": n, "root_b64u": b64u(merkle.root(hashes[:n]))} for n in range(0, 10)]
    inclusion = [
        {"leaf_index": i, "tree_size": n, "audit_path_b64u": [b64u(p) for p in merkle.inclusion_proof(i, hashes[:n])]}
        for n in range(1, 10)
        for i in range(n)
    ]
    consistency = [
        {"from": m, "to": n, "proof_b64u": [b64u(p) for p in merkle.consistency_proof(m, hashes[:n])]}
        for n in range(1, 10)
        for m in range(1, n + 1)
    ]
    receipt = {
        "action": "slot.release",
        "decision": "allow",
        "directory_epoch": 9,
        "id": "rcp_" + b64u(det("receipt id", 16)),
        "key_epoch": 1,
        "leaf_index": 0,
        "matched_rules": ["P-OPEN-RECIPIENT"],
        "policy_bundle_hash": b64u(det("bundle", 32)),
        "reason_code": "allowed",
        "request_hash": b64u(det("request", 32)),
        "resource": "fil_" + b64u(det("file id", 16)),
        "subject": {"device_id": "dev_" + b64u(det("device id", 16)), "session_id": "ses_" + b64u(det("session id", 16)), "user_id": "usr_" + b64u(det("user id", 16))},
        "suite": SUITE,
        "ts": "2026-11-26T12:00:06.000Z",
    }
    return {
        "description": "spec/SUITE.md section 9.1. leaf i is utf8('leaf-' + i); leaf hash = SHA-256(0x00 || leaf).",
        "leaves_hex": [x.hex() for x in leaves],
        "leaf_hashes_b64u": [b64u(h) for h in hashes],
        "roots": roots,
        "inclusion": inclusion,
        "consistency": consistency,
        "receipt_leaf": {
            "receipt": receipt,
            "leaf_hex": canon(receipt).hex(),
            "leaf_hash_b64u": b64u(merkle.leaf_hash(canon(receipt))),
        },
    }


def checkpoint_vectors() -> dict[str, Any]:
    signer = DualSigner(Ed25519Key.from_seed(det("server ed25519", 32)), MLDSAKey.from_seed(det("server mldsa", 32)))
    hashes = [merkle.leaf_hash(f"leaf-{i}".encode()) for i in range(9)]
    cp = signer.sign_object(
        {"root_hash": b64u(merkle.root(hashes)), "suite": SUITE, "tree_size": 9, "ts": "2026-11-26T12:00:07.000Z"},
        "checkpoint",
    )
    body = {k: v for k, v in cp.items() if k != "signatures"}
    other = DualSigner(Ed25519Key.from_seed(det("other ed25519", 32)), MLDSAKey.from_seed(det("other mldsa", 32)))
    wrong_purpose = signer.sign_object(body, "directory")
    foreign = other.sign_object(body, "checkpoint")

    def mutate(fn: Any) -> dict[str, Any]:
        c = json.loads(json.dumps(cp))
        fn(c)
        return c

    flipped_root = mutate(lambda c: c.__setitem__("root_hash", b64u(bytes([merkle.root(hashes)[0] ^ 1]) + merkle.root(hashes)[1:])))
    must_fail = [
        {"why": "root changed", "checkpoint": flipped_root},
        {"why": "tree size changed", "checkpoint": mutate(lambda c: c.__setitem__("tree_size", 8))},
        {"why": "mldsa missing", "checkpoint": mutate(lambda c: c["signatures"].pop("mldsa"))},
        {"why": "ed25519 missing", "checkpoint": mutate(lambda c: c["signatures"].pop("ed25519"))},
        {"why": "ed25519 from another key", "checkpoint": mutate(lambda c: c["signatures"].__setitem__("ed25519", foreign["signatures"]["ed25519"]))},
        {"why": "mldsa from another key", "checkpoint": mutate(lambda c: c["signatures"].__setitem__("mldsa", foreign["signatures"]["mldsa"]))},
        {"why": "signed for purpose directory", "checkpoint": wrong_purpose},
        {"why": "extra signature member", "checkpoint": mutate(lambda c: c["signatures"].__setitem__("slhdsa", "AA"))},
    ]
    return {
        "description": "spec/SUITE.md sections 4 and 9.3. Verify with the dual-signature rule and purpose checkpoint.",
        "server_keys": {"ed25519_seed": signer.ed.seed.hex(), "mldsa_seed": signer.pq.seed.hex(), **signer.public_keys},
        "ed25519_signing_input_hex": (b"QG/v1/checkpoint\x00" + canon(body)).hex(),
        "checkpoint": cp,
        "must_fail": must_fail,
    }


def main() -> None:
    write("canonical_json", {**canonical_json(), "b64u": b64u_vectors()})
    write("request_mac", request_mac())
    write("transcripts", transcripts_vectors())
    write("envelope", envelope())
    write("keystore", keystore_vectors())
    write("merkle", merkle_vectors())
    write("checkpoint", checkpoint_vectors())


if __name__ == "__main__":
    main()
