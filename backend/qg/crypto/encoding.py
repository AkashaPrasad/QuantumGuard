"""base64url without padding and canonical JSON (spec/SUITE.md section 2)."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

_B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")
MAX_SAFE_INT = 2**53 - 1


class EncodingError(ValueError):
    """Raised for any value that is not a valid QG-1 encoding."""


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str, *, length: int | None = None) -> bytes:
    if not isinstance(text, str) or not _B64U_RE.match(text) or len(text) % 4 == 1:
        raise EncodingError("bad base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise EncodingError("bad base64url") from exc
    if b64u(raw) != text:
        raise EncodingError("non-canonical base64url")
    if length is not None and len(raw) != length:
        raise EncodingError("wrong length")
    return raw


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _encode_str(s: str, out: list[str]) -> None:
    out.append('"')
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise EncodingError("lone surrogate")
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')


def _encode(value: Any, out: list[str], depth: int) -> None:
    if depth > 64:
        raise EncodingError("too deep")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            raise EncodingError("integer out of range")
        out.append(str(value))
    elif isinstance(value, float):
        raise EncodingError("floats are not allowed")
    elif isinstance(value, str):
        _encode_str(value, out)
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _encode(item, out, depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        keys = list(value.keys())
        for k in keys:
            if not isinstance(k, str) or not k.isascii():
                raise EncodingError("object keys must be ASCII strings")
        out.append("{")
        for i, k in enumerate(sorted(keys)):
            if i:
                out.append(",")
            _encode_str(k, out)
            out.append(":")
            _encode(value[k], out, depth + 1)
        out.append("}")
    else:
        raise EncodingError(f"unsupported type {type(value).__name__}")


def canon(value: Any) -> bytes:
    """Canonical JSON bytes (RFC 8785 restricted to integers and ASCII keys)."""
    out: list[str] = []
    _encode(value, out, 0)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - surrogates are rejected above
        raise EncodingError("invalid string") from exc


def _reject_floats(text: str) -> None:
    raise EncodingError("floats are not allowed")


def _reject_constant(text: str) -> None:
    raise EncodingError("non-finite numbers are not allowed")


def _parse_int(text: str) -> int:
    if text == "-0" or text.startswith("-0") and len(text) > 2:
        raise EncodingError("negative zero is not allowed")
    value = int(text)
    if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
        raise EncodingError("integer out of range")
    return value


def parse_strict(data: bytes | str) -> Any:
    """Parse JSON for canonicalisation: floats, NaN and duplicate keys are rejected."""
    import json

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, v in items:
            if k in obj:
                raise EncodingError("duplicate key")
            obj[k] = v
        return obj

    try:
        return json.loads(
            data,
            parse_float=_reject_floats,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
            object_pairs_hook=pairs,
        )
    except json.JSONDecodeError as exc:
        raise EncodingError("invalid JSON") from exc
