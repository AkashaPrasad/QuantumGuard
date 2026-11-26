"""Property tests: round trip, single-bit flips fail, wrong AAD fails, nonces never repeat in a file."""

import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qg.crypto import aead, xwing
from qg.crypto.encoding import b64u, b64u_decode, canon, parse_strict

FILE_ID = "fil_" + "A" * 22
SMALL = 64  # small chunk size keeps properties fast; framing is identical


def enc(dek, data, version=1, prefix=None):
    prefix = prefix or os.urandom(8)
    parts = aead.split_plaintext(data, SMALL)
    n = len(parts)
    return [aead.encrypt_chunk(dek, prefix, FILE_ID, version, i, i == n - 1, p) for i, p in enumerate(parts)]


@settings(max_examples=50, deadline=None)
@given(st.binary(max_size=400))
def test_roundtrip(data):
    dek = os.urandom(32)
    blobs = enc(dek, data)
    assert b"".join(aead.decrypt_chunks(dek, FILE_ID, 1, blobs, len(blobs))) == data


@settings(max_examples=50, deadline=None)
@given(st.binary(min_size=1, max_size=300), st.data())
def test_any_single_bit_flip_fails(data, d):
    dek = os.urandom(32)
    blobs = enc(dek, data)
    ci = d.draw(st.integers(0, len(blobs) - 1))
    bit = d.draw(st.integers(0, len(blobs[ci]) * 8 - 1))
    b = bytearray(blobs[ci])
    b[bit // 8] ^= 1 << (bit % 8)
    blobs[ci] = bytes(b)
    with pytest.raises(aead.AeadError):
        list(aead.decrypt_chunks(dek, FILE_ID, 1, blobs, len(blobs)))


@settings(max_examples=30, deadline=None)
@given(st.binary(min_size=SMALL + 1, max_size=400))
def test_reorder_truncate_and_wrong_aad_fail(data):
    dek = os.urandom(32)
    blobs = enc(dek, data)
    with pytest.raises(aead.AeadError):
        list(aead.decrypt_chunks(dek, FILE_ID, 1, list(reversed(blobs)), len(blobs)))
    with pytest.raises(aead.AeadError):
        list(aead.decrypt_chunks(dek, FILE_ID, 1, blobs[:-1], len(blobs)))
    with pytest.raises(aead.AeadError):
        list(aead.decrypt_chunks(dek, FILE_ID, 1, blobs[:-1], len(blobs) - 1))  # last flag mismatch
    with pytest.raises(aead.AeadError):
        list(aead.decrypt_chunks(dek, FILE_ID, 2, blobs, len(blobs)))  # other version
    with pytest.raises(aead.AeadError):
        list(aead.decrypt_chunks(dek, "fil_" + "B" * 22, 1, blobs, len(blobs)))  # other file


def test_chunk_from_other_file_with_same_key_fails():
    dek = os.urandom(32)
    a = enc(dek, b"x" * 200)
    b = enc(dek, b"y" * 200)
    with pytest.raises(aead.AeadError):
        list(aead.decrypt_chunks(dek, FILE_ID, 1, [a[0], b[1], a[2], a[3]], 4))


@settings(max_examples=30, deadline=None)
@given(st.binary(max_size=2000))
def test_nonce_never_repeats_within_file(data):
    blobs = enc(os.urandom(32), data)
    nonces = [b[:12] for b in blobs]
    assert len(set(nonces)) == len(nonces)
    assert len({n[:8] for n in nonces}) == 1


def test_wrap_bound_to_device_file_version_epoch():
    sk = xwing.XWingPrivateKey.generate()
    dek = os.urandom(32)
    binding = aead.wrap_binding(FILE_ID, 3, "dev_" + "C" * 22, 5)
    w = aead.wrap_dek(sk.public_key, dek, binding)
    assert aead.unwrap_dek(sk, w, binding) == dek
    for k, v in (("version", 4), ("device_id", "dev_" + "D" * 22), ("directory_epoch", 6), ("file_id", "fil_" + "E" * 22)):
        with pytest.raises(aead.AeadError):
            aead.unwrap_dek(sk, w, {**binding, k: v})


def test_seal_bound_to_slot():
    master = os.urandom(32)
    inner = {"wrapped_dek": "AA", "xwing_ct": "BB"}
    aad = aead.seal_aad("slt_" + "A" * 22, FILE_ID, 1, "dev_" + "A" * 22, 1)
    s = aead.seal(master, 1, aad, inner)
    assert parse_strict(aead.unseal(master, 1, aad, s)) == inner
    with pytest.raises(aead.AeadError):
        aead.unseal(master, 1, aead.seal_aad("slt_" + "B" * 22, FILE_ID, 1, "dev_" + "A" * 22, 1), s)
    with pytest.raises(aead.AeadError):
        aead.unseal(master, 2, aad, s)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=100))
def test_b64u_roundtrip(data):
    assert b64u_decode(b64u(data)) == data


json_values = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**53 - 1), 2**53 - 1) | st.text(max_size=20),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(alphabet=st.characters(max_codepoint=127), max_size=8), children, max_size=4),
    max_leaves=12,
)


@settings(max_examples=100, deadline=None)
@given(json_values)
def test_canon_is_stable(value):
    try:
        out = canon(value)
    except ValueError:
        return  # lone surrogates from hypothesis text
    assert canon(parse_strict(out)) == out
