"""RFC 6962 Merkle tree hashing, inclusion and consistency proofs (spec/SUITE.md section 9).

Pure functions over leaf hashes so the offline verifier can reuse them without the server.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


EMPTY_ROOT = hashlib.sha256(b"").digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(hashes: Sequence[bytes]) -> bytes:
    n = len(hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(root(hashes[:k]), root(hashes[k:]))


def inclusion_proof(index: int, hashes: Sequence[bytes]) -> list[bytes]:
    n = len(hashes)
    if not 0 <= index < n:
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, hashes[:k]) + [root(hashes[k:])]
    return inclusion_proof(index - k, hashes[k:]) + [root(hashes[:k])]


def _subproof(m: int, hashes: Sequence[bytes], complete: bool) -> list[bytes]:
    n = len(hashes)
    if m == n:
        return [] if complete else [root(hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(m, hashes[:k], complete) + [root(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [root(hashes[:k])]


def consistency_proof(first: int, hashes: Sequence[bytes]) -> list[bytes]:
    n = len(hashes)
    if not 0 < first <= n:
        raise ValueError("bad sizes")
    if first == n:
        return []
    return _subproof(first, hashes, True)


def verify_inclusion(index: int, tree_size: int, leaf: bytes, path: Sequence[bytes], expected_root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2. `leaf` is the leaf hash."""
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def verify_consistency(first: int, second: int, proof: Sequence[bytes], first_root: bytes, second_root: bytes) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if first == second:
        return not proof and first_root == second_root
    if not 0 < first < second or not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # power of two
        path = [first_root] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root
