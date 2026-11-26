"""Default-deny policy engine over the signed rules.yaml bundle. No ML: explicit rules only."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from qg.crypto.encoding import b64u, canon
from qg.crypto.kdf import sha256
from qg.crypto.sign import DualSigner, verify_dual
from qg.crypto.suite import SUITE

RULES_PATH = Path(__file__).parent / "rules.yaml"


class PolicyUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class Decision:
    allow: bool
    matched_rules: list[str]
    reason: str
    explanation: list[dict[str, Any]] = field(default_factory=list)


def load_document(path: Path = RULES_PATH) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = []
    for r in raw["rules"]:
        rules.append(
            {
                "id": str(r["id"]),
                "effect": str(r["effect"]),
                "description": str(r["description"]),
                "roles": [str(x) for x in r["roles"]],
                "actions": [str(x) for x in r["actions"]],
                "conditions": r.get("conditions") or {},
            }
        )
    doc = {"rules": rules, "suite": raw["suite"], "version": int(raw["version"])}
    canon(doc)  # rejects floats and other non-canonical values
    if doc["suite"] != SUITE:
        raise ValueError("policy suite")
    return doc


def bundle_hash(doc: dict[str, Any]) -> str:
    return b64u(sha256(canon(doc)))


class PolicyEngine:
    def __init__(self, doc: dict[str, Any], signed: dict[str, Any], ed_pk: bytes, pq_pk: bytes,
                 down_flag: Path | None = None) -> None:
        self.doc = doc
        self.signed = signed
        self.hash = bundle_hash(doc)
        self._intact = verify_dual({**doc, "signatures": signed.get("signatures")}, "policy", ed_pk, pq_pk)
        self._forced_down = False
        self._down_flag = down_flag
        self._lock = threading.Lock()

    @classmethod
    def sign_bundle(cls, doc: dict[str, Any], signer: DualSigner, signed_at: str) -> dict[str, Any]:
        """Signatures cover canon(doc) exactly (the bytes whose SHA-256 is the bundle hash)."""
        return {"signed_at": signed_at, "signatures": signer.sign_object(doc, "policy")["signatures"]}

    # ---- availability (testing switch and operational flag file) ----------------------------

    def set_available(self, available: bool) -> None:
        with self._lock:
            self._forced_down = not available

    def available(self) -> bool:
        if self._forced_down or not self._intact:
            return False
        return not (self._down_flag is not None and self._down_flag.exists())

    # ---- evaluation --------------------------------------------------------------------------

    @staticmethod
    def _cond_ok(conditions: dict[str, Any], facts: dict[str, Any]) -> bool:
        for key, expected in conditions.items():
            if key not in facts:
                return False
            actual = facts[key]
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def decide(self, roles: list[str], action: str, facts: dict[str, Any]) -> Decision:
        if not self.available():
            raise PolicyUnavailable("policy engine unavailable")
        allow: list[str] = []
        deny: list[str] = []
        for rule in self.doc["rules"]:
            if action not in rule["actions"] and "*" not in rule["actions"]:
                continue
            if "*" not in rule["roles"] and not set(rule["roles"]) & set(roles):
                continue
            if not self._cond_ok(rule["conditions"], facts):
                continue
            (deny if rule["effect"] == "deny" else allow).append(rule["id"])
        if deny:
            return Decision(False, deny, "denied_by_rule")
        if allow:
            return Decision(True, allow, "allowed")
        return Decision(False, [], "no_matching_rule")

    def explain(self, decision: Decision) -> list[dict[str, Any]]:
        by_id = {r["id"]: r for r in self.doc["rules"]}
        return [
            {"id": rid, "effect": by_id[rid]["effect"], "description": by_id[rid]["description"]}
            for rid in decision.matched_rules
        ]

    def public_view(self) -> dict[str, Any]:
        return {
            "bundle_hash": self.hash,
            "version": self.doc["version"],
            "signed_at": self.signed.get("signed_at"),
            "signatures": self.signed.get("signatures"),
            "document": b64u(canon(self.doc)),
            "rules": json.loads(json.dumps(self.doc["rules"])),
        }
