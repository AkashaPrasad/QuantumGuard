"""Random identifiers: prefix + 22 base64url characters from 16 random bytes."""

from __future__ import annotations

import os
import re

from qg.crypto.encoding import b64u

PREFIXES = frozenset(
    "usr dev fil slt ses inv rcp inc alr rsp chg svc key msg sig enr lse sst req".split()
)
_ID_RE = re.compile(r"^([a-z]{3})_[A-Za-z0-9_-]{22}$")


def new_id(prefix: str) -> str:
    if prefix not in PREFIXES:
        raise ValueError(prefix)
    return f"{prefix}_{b64u(os.urandom(16))}"


def is_id(value: object, prefix: str | None = None) -> bool:
    if not isinstance(value, str):
        return False
    m = _ID_RE.match(value)
    return bool(m) and (prefix is None or m.group(1) == prefix)
