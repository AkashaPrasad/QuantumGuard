"""Independent check of the Merkle hashing against the RFC 6962 reference test data
(certificate-transparency project test leaves and roots)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qg.log import merkle

LEAVES = [
    b"",
    b"\x00",
    b"\x10",
    b"\x20\x21",
    b"\x30\x31",
    b"\x40\x41\x42\x43",
    b"\x50\x51\x52\x53\x54\x55\x56\x57",
    bytes(range(0x60, 0x70)),
]
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


@pytest.mark.parametrize("n", range(1, 9))
def test_reference_roots(n):
    hashes = [merkle.leaf_hash(x) for x in LEAVES[:n]]
    assert merkle.root(hashes).hex() == ROOTS[n - 1]


def test_empty_tree():
    assert merkle.root([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@settings(max_examples=60, deadline=None)
@given(st.integers(min_value=1, max_value=70), st.data())
def test_proofs_verify_for_random_sizes(n, data):
    hashes = [merkle.leaf_hash(i.to_bytes(4, "big")) for i in range(n)]
    r = merkle.root(hashes)
    i = data.draw(st.integers(min_value=0, max_value=n - 1))
    path = merkle.inclusion_proof(i, hashes)
    assert merkle.verify_inclusion(i, n, hashes[i], path, r)
    if path:
        bad = list(path)
        bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
        assert not merkle.verify_inclusion(i, n, hashes[i], bad, r)
    m = data.draw(st.integers(min_value=1, max_value=n))
    proof = merkle.consistency_proof(m, hashes)
    assert merkle.verify_consistency(m, n, proof, merkle.root(hashes[:m]), r)
