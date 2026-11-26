"""Official known-answer tests: ML-KEM-768 (ACVP, CCTV), ML-DSA-65 (ACVP), X-Wing (draft-11)."""

import hashlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519

from qg.crypto import xwing

from ._vectors import load

MLKEM = load("mlkem768")
MLDSA = load("mldsa65")
XWING = load("xwing")


@pytest.mark.parametrize("v", MLKEM["keygen"], ids=lambda v: f"tc{v['tcId']}")
def test_mlkem768_keygen(v):
    sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(v["d"] + v["z"]))
    assert sk.public_key().public_bytes_raw().hex() == v["ek"]


@pytest.mark.parametrize("v", MLKEM["decaps"], ids=lambda v: f"tc{v['tcId']}")
def test_mlkem768_decaps_wycheproof(v):
    if v["result"] == "invalid":
        with pytest.raises(ValueError):
            sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(v["seed"]))
            sk.decapsulate(bytes.fromhex(v["c"]))
        return
    sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(v["seed"]))
    assert sk.public_key().public_bytes_raw().hex() == v["ek"]
    assert sk.decapsulate(bytes.fromhex(v["c"])).hex() == v["k"]


@pytest.mark.parametrize("v", load("xwing")["vectors"], ids=lambda v: v["seed"][:8])
def test_mlkem768_implicit_rejection(v):
    """FIPS 203 Algorithm 18: a modified ciphertext yields J(z || c') = SHAKE256(z || c', 32)."""
    expanded = hashlib.shake_256(bytes.fromhex(v["seed"])).digest(96)
    sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
    c = bytes.fromhex(v["ct"])[:1088]
    bad = bytes([c[0] ^ 1]) + c[1:]
    assert sk.decapsulate(bad) == hashlib.shake_256(expanded[32:64] + bad).digest(32)


@pytest.mark.parametrize("v", MLDSA["keygen"], ids=lambda v: f"tc{v['tcId']}")
def test_mldsa65_keygen(v):
    sk = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(v["seed"]))
    assert sk.public_key().public_bytes_raw().hex() == v["pk"]


@pytest.mark.parametrize("v", MLDSA["sigver"], ids=lambda v: f"tc{v['tcId']}")
def test_mldsa65_sigver_with_context(v):
    pk = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(v["pk"]))
    args = (bytes.fromhex(v["signature"]), bytes.fromhex(v["message"]), bytes.fromhex(v["context"]))
    if v["testPassed"]:
        pk.verify(*args)
    else:
        with pytest.raises((InvalidSignature, ValueError)):
            pk.verify(*args)


def test_mldsa65_sigver_has_both_outcomes():
    outcomes = {v["testPassed"] for v in MLDSA["sigver"]}
    assert outcomes == {True, False}


@pytest.mark.parametrize("v", XWING["vectors"], ids=lambda v: v["seed"][:8])
def test_xwing_draft11(v):
    sk = xwing.XWingPrivateKey.from_seed(bytes.fromhex(v["seed"]))
    assert sk.public_key.hex() == v["pk"]
    ct = bytes.fromhex(v["ct"])
    assert sk.decapsulate(ct).hex() == v["ss"]
    # X25519 half of the derandomized encapsulation (ML-KEM half needs EncapsDerand, see SUITE.md 1.1)
    eseed = bytes.fromhex(v["eseed"])
    ek_x = x25519.X25519PrivateKey.from_private_bytes(eseed[32:64])
    assert ek_x.public_key().public_bytes_raw() == ct[1088:]


def test_xwing_roundtrip_and_sizes():
    sk = xwing.XWingPrivateKey.generate()
    ss, ct = xwing.encapsulate(sk.public_key)
    assert (len(sk.public_key), len(ct), len(ss)) == (1216, 1120, 32)
    assert sk.decapsulate(ct) == ss
    other = xwing.XWingPrivateKey.generate()
    assert other.decapsulate(ct) != ss


def test_xwing_rejects_bad_lengths():
    sk = xwing.XWingPrivateKey.generate()
    with pytest.raises(xwing.XWingError):
        xwing.encapsulate(sk.public_key[:-1])
    with pytest.raises(xwing.XWingError):
        sk.decapsulate(b"\x00" * 1119)
    with pytest.raises(xwing.XWingError):
        xwing.XWingPrivateKey.from_seed(b"\x00" * 31)


def test_xwing_key_repr_redacted():
    assert "redacted" in repr(xwing.XWingPrivateKey.generate())
