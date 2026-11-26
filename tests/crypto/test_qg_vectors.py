"""Replay QuantumGuard's own QG-1 vectors (the TypeScript client replays the same files)."""

import json
import unicodedata

import pytest

from qg.crypto import aead, kdf, keystore, transcripts, xwing
from qg.crypto.encoding import EncodingError, b64u, b64u_decode, canon, parse_strict
from qg.crypto.sign import MLDSAKey, mldsa_verify, verify_dual
from qg.crypto.suite import PURPOSES
from qg.log import merkle

from ._vectors import load

CJ = load("canonical_json")
MAC = load("request_mac")
TR = load("transcripts")
ENV = load("envelope")
KS = load("keystore")
MK = load("merkle")
CP = load("checkpoint")


@pytest.mark.parametrize("case", CJ["valid"], ids=range(len(CJ["valid"])))
def test_canonical_valid(case):
    assert canon(case["input"]).hex() == case["output_hex"]
    assert canon(parse_strict(case["output"])).hex() == case["output_hex"]


@pytest.mark.parametrize("case", CJ["invalid"], ids=lambda c: c["why"])
def test_canonical_invalid(case):
    with pytest.raises(EncodingError):
        canon(parse_strict(case["json"]))


@pytest.mark.parametrize("case", CJ["b64u"]["valid"], ids=lambda c: c["b64u"] or "empty")
def test_b64u_valid(case):
    assert b64u(bytes.fromhex(case["hex"])) == case["b64u"]
    assert b64u_decode(case["b64u"]).hex() == case["hex"]


@pytest.mark.parametrize("text", CJ["b64u"]["invalid"])
def test_b64u_invalid(text):
    with pytest.raises(EncodingError):
        b64u_decode(text)


@pytest.mark.parametrize("case", MAC["cases"], ids=lambda c: f"{c['method']} {c['seq']}")
def test_request_mac(case):
    k = bytes.fromhex(MAC["k_mac"])
    body = bytes.fromhex(case["body_hex"])
    assert transcripts.mac_input(case["method"], case["path"], case["seq"], body).hex() == case["mac_input_hex"]
    assert transcripts.request_mac(k, case["method"], case["path"], case["seq"], body) == case["mac_b64u"]
    assert transcripts.request_hash(case["method"], case["path"], case["seq"], body) == case["request_hash_b64u"]


def test_enroll_transcript():
    dev = TR["device"]
    kem = xwing.XWingPrivateKey.from_seed(bytes.fromhex(dev["kem_seed"]))
    sig = MLDSAKey.from_seed(bytes.fromhex(dev["sig_seed"]))
    assert b64u(kem.public_key) == dev["kem_pk_b64u"] and b64u(sig.public_key) == dev["sig_pk_b64u"]
    e = TR["enroll"]
    f = e["fields"]
    ss = kem.decapsulate(b64u_decode(f["xwing_ct"]))
    assert ss.hex() == e["ss"]
    t = transcripts.enroll_transcript(
        enroll_id=f["enroll_id"], user_id=f["user_id"], device_name=f["device_name"], kem_pk_b64u=f["kem_pk"],
        sig_pk_b64u=f["sig_pk"], challenge_b64u=f["challenge"], xwing_ct_b64u=f["xwing_ct"],
        directory_epoch=f["directory_epoch"], server_time=f["server_time"],
    )
    assert t.hex() == e["transcript_hex"]
    k_ec = kdf.enroll_confirm_key(ss, b64u_decode(f["challenge"]))
    assert k_ec.hex() == e["k_ec"]
    assert b64u(kdf.hmac384(k_ec, t)) == e["confirmation_b64u"]
    s = b64u_decode(e["signature_b64u"])
    assert mldsa_verify(sig.public_key, s, t, "enroll")
    for other in PURPOSES - {"enroll"}:
        assert not mldsa_verify(sig.public_key, s, t, other)


def test_session_transcript():
    dev = TR["device"]
    kem = xwing.XWingPrivateKey.from_seed(bytes.fromhex(dev["kem_seed"]))
    s_ = TR["session"]
    f = s_["fields"]
    ss = kem.decapsulate(b64u_decode(f["xwing_ct"]))
    assert ss.hex() == s_["ss"]
    t = transcripts.session_transcript(
        start_id=f["start_id"], device_id=f["device_id"], challenge_b64u=f["challenge"],
        xwing_ct_b64u=f["xwing_ct"], directory_epoch=f["directory_epoch"], server_time=f["server_time"],
    )
    assert t.hex() == s_["transcript_hex"]
    ch = b64u_decode(f["challenge"])
    assert kdf.session_confirm_key(ss, ch).hex() == s_["k_sc"]
    assert kdf.session_mac_key(ss, ch).hex() == s_["k_mac"]
    assert b64u(kdf.hmac384(kdf.session_confirm_key(ss, ch), t)) == s_["confirmation_b64u"]
    assert mldsa_verify(b64u_decode(dev["sig_pk_b64u"]), b64u_decode(s_["signature_b64u"]), t, "session")
    assert not mldsa_verify(b64u_decode(dev["sig_pk_b64u"]), b64u_decode(s_["signature_b64u"]), t, "enroll")


@pytest.mark.parametrize("f", ENV["files"], ids=lambda f: f["plaintext_label"])
def test_envelope_chunks(f):
    import hashlib

    dek, prefix = bytes.fromhex(ENV["dek"]), bytes.fromhex(ENV["nonce_prefix"])
    data = hashlib.shake_128(f["plaintext_label"].encode()).digest(f["plaintext_len"])
    blobs = aead.encrypt_file(dek, ENV["file_id"], ENV["version"], data, prefix)
    assert len(blobs) == f["chunk_count"]
    for b, c in zip(blobs, f["chunks"], strict=True):
        assert aead.chunk_aad(ENV["file_id"], ENV["version"], c["index"], c["index"] == f["chunk_count"] - 1).hex() == c["aad_hex"]
        assert len(b) == c["len"] and hashlib.sha256(b).hexdigest() == c["sha256"]
        assert b[:48].hex() == c["head_hex"] and b[-48:].hex() == c["tail_hex"]
        if "blob_hex" in c:
            assert b.hex() == c["blob_hex"]
    assert b64u(aead.ciphertext_sha256(blobs)) == f["ciphertext_sha256_b64u"]
    assert b"".join(aead.decrypt_chunks(dek, ENV["file_id"], ENV["version"], blobs, len(blobs))) == data


def test_envelope_wrap():
    w = ENV["wrap"]
    rcpt = xwing.XWingPrivateKey.from_seed(bytes.fromhex(w["recipient_kem_seed"]))
    assert b64u(rcpt.public_key) == w["recipient_kem_pk_b64u"]
    assert canon(w["binding"]).hex() == w["aad_hex"]
    ss = rcpt.decapsulate(b64u_decode(w["xwing_ct_b64u"]))
    assert ss.hex() == w["ss"] and kdf.wrap_key(ss).hex() == w["kek"]
    dek = bytes.fromhex(ENV["dek"])
    assert b64u(aead.wrap_dek_with_secret(ss, dek, w["binding"], bytes.fromhex(w["nonce"]))) == w["wrapped_dek_b64u"]
    assert aead.unwrap_dek(rcpt, w["inner_wrap"], w["binding"]) == dek
    for neg in w["must_fail_with_binding"]:
        with pytest.raises(aead.AeadError):
            aead.unwrap_dek(rcpt, w["inner_wrap"], neg["binding"])
    stranger = xwing.XWingPrivateKey.from_seed(b"\x01" * 32)
    with pytest.raises(aead.AeadError):
        aead.unwrap_dek(stranger, w["inner_wrap"], w["binding"])


def test_envelope_manifest_and_share():
    m = ENV["manifest"]
    pk = b64u_decode(m["signer_sig_pk_b64u"])
    assert canon(m["manifest"]).hex() == m["canonical_hex"]
    assert mldsa_verify(pk, b64u_decode(m["manifest_sig_b64u"]), canon(m["manifest"]), "manifest")
    assert not mldsa_verify(pk, b64u_decode(m["manifest_sig_b64u"]), canon(m["manifest"]), "share")
    s = ENV["share"]
    assert canon(s["share"]).hex() == s["canonical_hex"]
    assert mldsa_verify(pk, b64u_decode(s["share_sig_b64u"]), canon(s["share"]), "share")
    assert not mldsa_verify(pk, b64u_decode(s["share_sig_b64u"]), canon(s["share"]), "manifest")


def test_keystore_opens():
    doc = KS["keystore"]
    assert canon({k: v for k, v in doc.items() if k != "ciphertext"}).hex() == KS["aad_hex"]
    assert keystore.derive_key(KS["passphrase"], doc["kdf"]).hex() == KS["argon2_output"]
    for p in (KS["passphrase"], KS["passphrase_nfd"]):
        seeds = keystore.open_keystore(doc, p)
        assert seeds.sig_seed.hex() == KS["sig_seed"] and seeds.kem_seed.hex() == KS["kem_seed"]
    assert unicodedata.normalize("NFC", KS["passphrase_nfd"]) == KS["passphrase"]


@pytest.mark.parametrize("case", KS["must_fail"], ids=lambda c: c["why"])
def test_keystore_must_fail(case):
    with pytest.raises(keystore.KeystoreError):
        keystore.open_keystore(case["keystore"], case["passphrase"])


def test_keystore_roundtrip_new_salt():
    seeds = keystore.DeviceSeeds(b"\x02" * 32, b"\x03" * 32)
    label = {"created_at": "2026-11-26T12:00:00.000Z", "device_id": None, "device_name": "x", "server": None, "user_id": None}
    a = keystore.seal_keystore(seeds, "pass phrase one", label)
    b = keystore.seal_keystore(seeds, "pass phrase one", label)
    assert a["kdf"]["salt"] != b["kdf"]["salt"] and a["aead"]["nonce"] != b["aead"]["nonce"]
    assert keystore.open_keystore(json.loads(json.dumps(a)), "pass phrase one") == seeds


def test_merkle_vectors():
    hashes = [merkle.leaf_hash(bytes.fromhex(x)) for x in MK["leaves_hex"]]
    assert [b64u(h) for h in hashes] == MK["leaf_hashes_b64u"]
    roots = {}
    for r in MK["roots"]:
        assert b64u(merkle.root(hashes[: r["tree_size"]])) == r["root_b64u"]
        roots[r["tree_size"]] = b64u_decode(r["root_b64u"])
    for c in MK["inclusion"]:
        path = [b64u_decode(p) for p in c["audit_path_b64u"]]
        assert path == merkle.inclusion_proof(c["leaf_index"], hashes[: c["tree_size"]])
        assert merkle.verify_inclusion(c["leaf_index"], c["tree_size"], hashes[c["leaf_index"]], path, roots[c["tree_size"]])
        wrong = (c["leaf_index"] + 1) % c["tree_size"]
        if wrong != c["leaf_index"]:
            assert not merkle.verify_inclusion(c["leaf_index"], c["tree_size"], hashes[wrong], path, roots[c["tree_size"]])
    for c in MK["consistency"]:
        proof = [b64u_decode(p) for p in c["proof_b64u"]]
        assert proof == merkle.consistency_proof(c["from"], hashes[: c["to"]])
        assert merkle.verify_consistency(c["from"], c["to"], proof, roots[c["from"]], roots[c["to"]])
        if c["from"] < c["to"]:
            assert not merkle.verify_consistency(c["from"], c["to"], proof, roots[c["to"]], roots[c["to"]])
    rl = MK["receipt_leaf"]
    assert canon(rl["receipt"]).hex() == rl["leaf_hex"]
    assert b64u(merkle.leaf_hash(canon(rl["receipt"]))) == rl["leaf_hash_b64u"]


def test_checkpoint_vectors():
    keys = CP["server_keys"]
    ed, pq = b64u_decode(keys["ed25519_pk"]), b64u_decode(keys["mldsa_pk"])
    assert verify_dual(CP["checkpoint"], "checkpoint", ed, pq)
    body = {k: v for k, v in CP["checkpoint"].items() if k != "signatures"}
    assert (b"QG/v1/checkpoint\x00" + canon(body)).hex() == CP["ed25519_signing_input_hex"]
    for case in CP["must_fail"]:
        assert not verify_dual(case["checkpoint"], "checkpoint", ed, pq), case["why"]


def test_message_vectors():
    from qg.crypto.messages import digests_for, envelope_digest, statement

    mv = load("messages")
    pk = b64u_decode(mv["sender_sig_pk_b64u"])
    assert digests_for(mv["envelopes"]) == mv["envelope_digests"]
    st = statement(mv["to_user_id"], mv["envelope_digests"])
    assert st.hex() == mv["statement_hex"]
    assert mldsa_verify(pk, b64u_decode(mv["signature_b64u"]), st, "message")
    assert not mldsa_verify(pk, b64u_decode(mv["signature_b64u"]), st, "manifest")
    for dev, env in zip(mv["devices"], mv["envelopes"], strict=True):
        assert envelope_digest(env["device_id"], env["xwing_ct"], env["ciphertext"]) == dev["envelope_digest_b64u"]
        kem = xwing.XWingPrivateKey.from_seed(bytes.fromhex(dev["kem_seed"]))
        ss = kem.decapsulate(b64u_decode(env["xwing_ct"]))
        assert ss.hex() == dev["ss"] and kdf.message_key(ss).hex() == dev["aead_input"]
        raw = b64u_decode(env["ciphertext"])
        assert aead.gcm_decrypt(kdf.message_key(ss), raw[:12], raw[12:], bytes.fromhex(dev["aad_hex"])).hex() == \
            mv["plaintext_hex"]
    tampered = [dict(d) for d in mv["envelope_digests"]]
    tampered[0]["digest"] = tampered[1]["digest"]
    assert not mldsa_verify(pk, b64u_decode(mv["signature_b64u"]), statement(mv["to_user_id"], tampered), "message")
