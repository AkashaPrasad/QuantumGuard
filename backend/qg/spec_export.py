"""Export spec/openapi.yaml, spec/openapi.json and spec/schemas/ from the running application, and check them.

    python -m qg.spec_export --write     regenerate the committed files
    python -m qg.spec_export --check     fail if they differ from a fresh export, or if a route in spec/API.md
                                         is missing from the application (make spec-lint)
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "spec"
PUBLIC = {
    ("GET", "/healthz"), ("GET", "/api/v1/meta"), ("GET", "/api/v1/directory"), ("GET", "/api/v1/log/checkpoint"),
    ("GET", "/api/v1/keys"), ("GET", "/api/v1/bench/latest"), ("POST", "/api/v1/enroll/start"),
    ("POST", "/api/v1/enroll/finish"), ("POST", "/api/v1/session/start"), ("POST", "/api/v1/session/finish"),
}
ERROR_CODES = {
    "400": "QG_INVALID_INPUT, QG_BAD_SUITE, QG_BAD_SIGNATURE",
    "401": "QG_NO_SESSION, QG_BAD_MAC, QG_REPLAY",
    "403": "QG_DENY_REVOKED, QG_DENY_POLICY, QG_QUARANTINED, QG_LEASE_EXPIRED",
    "404": "QG_NOT_FOUND (also for objects the caller may not see)",
    "409": "QG_STALE_EPOCH, QG_CONFLICT",
    "429": "QG_RATE_LIMITED (Retry-After is set)",
    "503": "QG_UNAVAILABLE_FAIL_CLOSED (nothing was released)",
}
PUBLIC_ERRORS = ("400", "403", "404", "429", "503")

ID = {"type": "string", "pattern": "^[a-z]{3}_[A-Za-z0-9_-]{22}$"}
B64U = {"type": "string", "pattern": "^[A-Za-z0-9_-]*$", "description": "base64url without padding"}
TIME = {"type": "string", "format": "date-time", "pattern": r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$"}
SUITE = {"const": "QG-1"}
DUAL = {"type": "object", "additionalProperties": False, "required": ["ed25519", "mldsa"],
        "properties": {"ed25519": B64U, "mldsa": B64U}}


def _obj(props: dict[str, Any], required: list[str] | None = None, example: Any = None) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "object", "additionalProperties": False, "properties": props,
                           "required": required if required is not None else sorted(props)}
    if example is not None:
        out["examples"] = [example]
    return out


EX_ID = {p: f"{p}_AAAAAAAAAAAAAAAAAAAAAA" for p in "usr dev fil slt ses rcp alr rsp inc chg lse sig".split()}
EX_HASH = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
EX_SIG = {"ed25519": "c2lnbmF0dXJlLWV4YW1wbGU", "mldsa": "bWxkc2Etc2lnbmF0dXJlLWV4YW1wbGU"}
EX_TS = "2026-11-26T12:00:00.000Z"

SCHEMAS: dict[str, dict[str, Any]] = {
    "error": _obj({"error": _obj({"code": {"type": "string", "pattern": "^QG_[A-Z_]+$"}, "message": {"type": "string"},
                                  "reason": {"type": "string"}, "request_id": {"type": "string"},
                                  "receipt_id": {"type": ["string", "null"]}})},
                  example={"error": {"code": "QG_DENY_POLICY", "message": "Policy does not allow this action.",
                                     "reason": "self_approval", "request_id": "req_AAAAAAAAAAAAAAAAAAAAAA",
                                     "receipt_id": EX_ID["rcp"]}}),
    "receipt": _obj({
        "suite": SUITE, "id": ID, "ts": TIME, "request_hash": B64U,
        "subject": _obj({"user_id": {"type": ["string", "null"]}, "device_id": {"type": ["string", "null"]},
                         "session_id": {"type": ["string", "null"]}}),
        "action": {"type": "string"}, "resource": {"type": ["string", "null"]}, "policy_bundle_hash": B64U,
        "matched_rules": {"type": "array", "items": {"type": "string"}},
        "decision": {"enum": ["allow", "deny"]}, "reason_code": {"type": "string"},
        "key_epoch": {"type": "integer"}, "directory_epoch": {"type": "integer"}, "leaf_index": {"type": "integer"},
    }, example={"suite": "QG-1", "id": EX_ID["rcp"], "ts": EX_TS, "request_hash": EX_HASH,
                "subject": {"user_id": EX_ID["usr"], "device_id": EX_ID["dev"], "session_id": EX_ID["ses"]},
                "action": "slot.release", "resource": EX_ID["fil"], "policy_bundle_hash": EX_HASH,
                "matched_rules": ["P-FILE-HOLDER"], "decision": "allow", "reason_code": "released", "key_epoch": 1,
                "directory_epoch": 4, "leaf_index": 12}),
    "manifest": _obj({
        "chunk_count": {"type": "integer", "minimum": 1}, "ciphertext_sha256": B64U,
        "classification": {"enum": ["internal", "confidential", "restricted"]}, "directory_epoch": {"type": "integer"},
        "file_id": ID, "recipients": {"type": "array", "items": ID, "minItems": 1, "maxItems": 32},
        "suite": SUITE, "version": {"type": "integer", "minimum": 1},
    }, example={"chunk_count": 1, "ciphertext_sha256": EX_HASH, "classification": "restricted", "directory_epoch": 4,
                "file_id": EX_ID["fil"], "recipients": [EX_ID["dev"]], "suite": "QG-1", "version": 1}),
    "share": _obj({"directory_epoch": {"type": "integer"}, "file_id": ID,
                   "recipients": {"type": "array", "items": ID, "minItems": 1}, "suite": SUITE,
                   "version": {"type": "integer"}},
                  example={"directory_epoch": 5, "file_id": EX_ID["fil"], "recipients": [EX_ID["dev"]], "suite": "QG-1",
                           "version": 1}),
    "slot": _obj({
        "slot_id": ID, "file_id": ID, "version": {"type": "integer"}, "device_id": ID, "wrap_epoch": {"type": "integer"},
        "inner_wrap": _obj({"xwing_ct": B64U, "wrapped_dek": B64U}), "manifest": {"$ref": "manifest.schema.json"},
        "manifest_sig": B64U, "signer_device_id": ID, "lease": _obj({"lease_id": ID, "expires_at": TIME}),
        "receipt_id": ID,
    }, example={"slot_id": EX_ID["slt"], "file_id": EX_ID["fil"], "version": 1, "device_id": EX_ID["dev"],
                "wrap_epoch": 4, "inner_wrap": {"xwing_ct": "eHdpbmctY3Q", "wrapped_dek": "d3JhcHBlZA"},
                "manifest": {"chunk_count": 1, "ciphertext_sha256": EX_HASH, "classification": "restricted",
                             "directory_epoch": 4, "file_id": EX_ID["fil"], "recipients": [EX_ID["dev"]],
                             "suite": "QG-1", "version": 1},
                "manifest_sig": "c2ln", "signer_device_id": EX_ID["dev"],
                "lease": {"lease_id": EX_ID["lse"], "expires_at": EX_TS}, "receipt_id": EX_ID["rcp"]}),
    "certificate": _obj({
        "created_at": TIME, "device_id": ID, "directory_epoch": {"type": "integer"}, "expires_at": TIME, "kem_pk": B64U,
        "name": {"type": "string"}, "sig_pk": B64U, "suite": SUITE, "user_id": ID, "signatures": DUAL,
    }, example={"created_at": EX_TS, "device_id": EX_ID["dev"], "directory_epoch": 2, "expires_at": EX_TS,
                "kem_pk": "a2VtLXBr", "name": "Aiko's laptop", "sig_pk": "c2lnLXBr", "suite": "QG-1",
                "user_id": EX_ID["usr"], "signatures": EX_SIG}),
    "checkpoint": _obj({"root_hash": B64U, "suite": SUITE, "tree_size": {"type": "integer", "minimum": 0}, "ts": TIME,
                        "signatures": DUAL},
                       example={"root_hash": EX_HASH, "suite": "QG-1", "tree_size": 13, "ts": EX_TS,
                                "signatures": EX_SIG}),
    "directory": _obj({
        "suite": SUITE, "epoch": {"type": "integer", "minimum": 1}, "prev_hash": B64U, "issued_at": TIME,
        "users": {"type": "array", "items": _obj({"user_id": ID, "name": {"type": "string"},
                                                    "roles": {"type": "array", "items": {"type": "string"}},
                                                    "status": {"enum": ["active", "quarantined", "disabled"]}})},
        "devices": {"type": "array", "items": {"type": "object"}},
        "revoked": {"type": "array", "items": _obj({"device_id": ID, "revoked_at": TIME, "epoch": {"type": "integer"}})},
        "recovery_pk": B64U, "signatures": DUAL,
    }, example={"suite": "QG-1", "epoch": 1, "prev_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "issued_at": EX_TS, "users": [{"user_id": EX_ID["usr"], "name": "Aiko Tanaka", "roles": ["employee"],
                                               "status": "active"}],
                "devices": [], "revoked": [], "recovery_pk": "cmVjb3Zlcnk", "signatures": EX_SIG}),
    "alert": _obj({
        "id": ID, "ts": TIME, "rule_id": {"type": "string", "pattern": "^QG-R0[0-1][0-9]$"},
        "severity": {"enum": ["critical", "high", "medium"]}, "status": {"enum": ["open", "acknowledged"]},
        "subject": _obj({"user_id": {"type": ["string", "null"]}, "device_id": {"type": ["string", "null"]},
                         "session_id": {"type": ["string", "null"]}}),
        "summary": {"type": "string"},
        "explanation": _obj({"condition": {"type": "string"}, "receipt_ids": {"type": "array", "items": ID}}),
        "response": {"oneOf": [{"type": "null"}, _obj({
            "id": ID, "action": {"enum": ["deny", "end_session", "quarantine_device", "quarantine_identity", "throttle",
                                          "require_fresh_session", "hold_enrolment", "freeze_key_release", "none"]},
            "scope": _obj({"kind": {"enum": ["session", "device", "identity", "credential", "global"]},
                           "id": {"type": ["string", "null"]}}),
            "expires_at": {"type": ["string", "null"]}, "lifted_at": {"type": ["string", "null"]},
            "lifted_by": {"type": ["string", "null"]}})]},
        "incident_id": {"type": ["string", "null"]}, "acknowledged_by": {"type": ["string", "null"]},
    }, example={"id": EX_ID["alr"], "ts": EX_TS, "rule_id": "QG-R001", "severity": "critical", "status": "open",
                "subject": {"user_id": EX_ID["usr"], "device_id": EX_ID["dev"], "session_id": EX_ID["ses"]},
                "summary": "A revoked device tried to use QuantumGuard and was denied.",
                "explanation": {"condition": "A request or session attempt came from a device that is revoked.",
                                "receipt_ids": [EX_ID["rcp"]]},
                "response": {"id": EX_ID["rsp"], "action": "deny", "scope": {"kind": "device", "id": EX_ID["dev"]},
                             "expires_at": None, "lifted_at": None, "lifted_by": None},
                "incident_id": EX_ID["inc"], "acknowledged_by": None}),
    "signal": _obj({
        "iss": {"type": "string", "maxLength": 200}, "jti": {"type": "string", "maxLength": 128},
        "iat": {"type": "integer"}, "aud": {"const": "quantumguard"},
        "events": {"type": "object", "minProperties": 1, "maxProperties": 1},
    }, example={"iss": "sandbox-idp", "jti": "3f6c1d0e9b2a4c7d", "iat": 1795694400, "aud": "quantumguard",
                "events": {"https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
                    "subject": {"format": "opaque", "id": EX_ID["dev"]}, "event_timestamp": 1795694400}}}),
    "proof-bundle": _obj({
        "format": {"const": "qg-proof-bundle/1"}, "suite": SUITE, "incident_id": ID, "generated_at": TIME,
        "server_keys": _obj({"ed25519_pk": B64U, "mldsa_pk": B64U}), "checkpoint": {"$ref": "checkpoint.schema.json"},
        "revocation_checkpoint": {"oneOf": [{"type": "null"}, {"$ref": "checkpoint.schema.json"}]},
        "consistency": {"type": "array", "items": B64U}, "directory": {"$ref": "directory.schema.json"},
        "exposure": {"type": "object"},
        "entries": {"type": "array", "items": _obj({"leaf_index": {"type": "integer"}, "leaf_hash": B64U,
                                                      "receipt": {"$ref": "receipt.schema.json"},
                                                      "audit_path": {"type": "array", "items": B64U}})},
        "signatures": DUAL,
    }, example={"format": "qg-proof-bundle/1", "suite": "QG-1", "incident_id": EX_ID["inc"], "generated_at": EX_TS,
                "server_keys": {"ed25519_pk": "ZWQ", "mldsa_pk": "bWw"},
                "checkpoint": {"root_hash": EX_HASH, "suite": "QG-1", "tree_size": 13, "ts": EX_TS,
                               "signatures": EX_SIG},
                "revocation_checkpoint": None, "consistency": [], "directory": {}, "exposure": {}, "entries": [],
                "signatures": EX_SIG}),
    "keystore": _obj({
        "format": {"const": "qg-keystore/1"}, "suite": SUITE,
        "kdf": _obj({"alg": {"const": "argon2id"}, "version": {"const": 19},
                     "m_kib": {"type": "integer", "minimum": 19456, "maximum": 1048576},
                     "t": {"type": "integer", "minimum": 2, "maximum": 10},
                     "p": {"type": "integer", "minimum": 1, "maximum": 4}, "salt": B64U}),
        "aead": _obj({"alg": {"const": "AES-256-GCM"}, "nonce": B64U}),
        "label": {"type": "object"}, "ciphertext": B64U,
    }, example={"format": "qg-keystore/1", "suite": "QG-1",
                "kdf": {"alg": "argon2id", "version": 19, "m_kib": 19456, "t": 2, "p": 1,
                        "salt": "c2FsdHNhbHRzYWx0c2E"},
                "aead": {"alg": "AES-256-GCM", "nonce": "bm9uY2Vub25jZW4"},
                "label": {"created_at": EX_TS, "device_id": None, "device_name": "laptop", "server": None,
                          "user_id": None},
                "ciphertext": "Y2lwaGVydGV4dA"}),
}


def _build_app():  # noqa: ANN202
    from qg.app import create_app
    from qg.config import Settings
    from qg.core import Core

    tmp = tempfile.TemporaryDirectory(prefix="qg-spec-")
    core = Core(Settings(data_dir=Path(tmp.name) / "data", keys_dir=Path(tmp.name) / "keys", log_stdout=False),
                log_sink=lambda _l: None)
    return create_app(core), tmp


def _has_gateway(dependant: Any) -> bool:
    for d in dependant.dependencies:
        if getattr(d.call, "__qg_gateway__", False) or _has_gateway(d):
            return True
    return False


def _body_models(dependant: Any) -> list[Any]:
    out = []
    for d in dependant.dependencies:
        model = getattr(d.call, "__qg_body__", None)
        if model is not None:
            out.append(model)
        out.extend(_body_models(d))
    return out


def build_openapi() -> dict[str, Any]:
    from fastapi.openapi.utils import get_openapi
    from fastapi.routing import APIRoute

    app, tmp = _build_app()
    try:
        routes = [r for r in app.routes if isinstance(r, APIRoute) and r.include_in_schema]
        doc = get_openapi(title="QuantumGuard API", version="1", routes=routes,
                          description="Generated from the application by `python -m qg.spec_export`. "
                                      "Human contract: spec/API.md. Byte layouts: spec/SUITE.md.")
        components = doc.setdefault("components", {}).setdefault("schemas", {})
        components["Error"] = copy.deepcopy(SCHEMAS["error"])
        components["Error"].pop("examples", None)
        for r in routes:
            for model in _body_models(r.dependant):
                schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
                for name, sub in schema.pop("$defs", {}).items():
                    components[name] = sub
                components[model.__name__] = schema
            private = _has_gateway(r.dependant)
            for method in r.methods:
                op = doc["paths"][r.path_format][method.lower()]
                responses = op.setdefault("responses", {})
                responses.pop("422", None)
                for code, text in ERROR_CODES.items():
                    if private or code in PUBLIC_ERRORS:
                        responses[code] = {"description": text, "content": {"application/json": {
                            "schema": {"$ref": "#/components/schemas/Error"}}}}
                if private:
                    params = op.setdefault("parameters", [])
                    for name, desc in (("QG-Session", "Session id"), ("QG-Seq", "Strictly increasing sequence"),
                                       ("QG-MAC", "b64u HMAC-SHA-384 over method, path, sequence, body hash")):
                        params.append({"name": name, "in": "header", "required": True, "description": desc,
                                       "schema": {"type": "string"}})
                    op["x-qg-gateway"] = True
        for name in ("HTTPValidationError", "ValidationError"):
            components.pop(name, None)
        return json.loads(json.dumps(doc, sort_keys=True))
    finally:
        app.state.core.db.close()
        tmp.cleanup()


def rendered() -> dict[Path, str]:
    doc = build_openapi()
    files = {
        SPEC / "openapi.json": json.dumps(doc, indent=2, sort_keys=True) + "\n",
        SPEC / "openapi.yaml": yaml.safe_dump(doc, sort_keys=True, allow_unicode=True, width=120),
    }
    for name, schema in SCHEMAS.items():
        s = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": f"{name}.schema.json",
             "title": name, **schema}
        files[SPEC / "schemas" / f"{name}.schema.json"] = json.dumps(s, indent=2, sort_keys=True) + "\n"
    return files


ROUTE_RE = re.compile(r"`(GET|POST|PUT|PATCH|DELETE) (/[^`\s?]*)")


def contract_routes() -> set[tuple[str, str]]:
    out = set()
    for method, path in ROUTE_RE.findall((SPEC / "API.md").read_text(encoding="utf-8")):
        if not path.startswith("/api/") and path != "/healthz":
            path = "/api/v1" + path
        out.add((method, re.sub(r"\{[^}]+\}", "{}", path)))
    return out


def check() -> int:
    problems = []
    files = rendered()
    for path, text in files.items():
        if not path.exists():
            problems.append(f"missing {path.relative_to(ROOT)} (run make spec-export)")
        elif path.read_text(encoding="utf-8") != text:
            problems.append(f"{path.relative_to(ROOT)} differs from a fresh export (run make spec-export)")
    stale = sorted(p for p in (SPEC / "schemas").glob("*.json") if p not in files) if (SPEC / "schemas").exists() else []
    problems += [f"{p.relative_to(ROOT)} is not produced by the export" for p in stale]
    doc = json.loads(files[SPEC / "openapi.json"])
    app_routes = {(m.upper(), re.sub(r"\{[^}]+\}", "{}", p)) for p, ops in doc["paths"].items() for m in ops}
    for method, route in sorted(contract_routes() - app_routes):
        problems.append(f"spec/API.md route missing from the application: {method} {route}")
    for p, ops in doc["paths"].items():
        for m, op in ops.items():
            if not any(code in op.get("responses", {}) for code in ("400", "404")):
                problems.append(f"{m.upper()} {p} has no error table")
            private = (m.upper(), p) not in PUBLIC
            if private != bool(op.get("x-qg-gateway")):
                problems.append(f"{m.upper()} {p}: gateway dependency {'missing' if private else 'unexpected'}")
    for name, schema in SCHEMAS.items():
        if not schema.get("examples"):
            problems.append(f"schema {name} has no example")
    for line in problems:
        print("spec-lint:", line, file=sys.stderr)
    if not problems:
        print(f"spec-lint: ok ({len(app_routes)} operations, {len(SCHEMAS)} schemas)")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m qg.spec_export")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    args = p.parse_args(argv)
    if args.check:
        return check()
    for path, text in rendered().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print("wrote", path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
