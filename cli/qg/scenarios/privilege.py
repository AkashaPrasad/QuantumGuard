"""Supporting workflow 3, unexpected privilege change: the identity source reports an admin role for an
employee with no signed change. QG-R005 quarantines that person for sensitive files only (QG-R007 draws the
new path to the crown jewels); the legitimate two-person path works and self-approval is refused; an operator
lifts the response."""

from __future__ import annotations

import os
import secrets
import time

from qg.client import ApiError, QGClient
from qg.scenarios.harness import Server, result


def _code(fn) -> str | None:  # noqa: ANN001
    try:
        fn()
        return None
    except ApiError as e:
        return e.code if e.reason in (None, e.code) else f"{e.code}/{e.reason}"


def run() -> int:
    srv = Server().start()
    try:
        client = QGClient(srv.url)
        mira = client.enroll(srv.code("Mira Okafor"), "Mira's laptop")
        tomas = client.enroll(srv.code("Tomas Lindqvist"), "Tomas's laptop")
        priya = client.enroll(srv.code("Priya Raman"), "Priya's workstation")
        daniel = client.enroll(srv.code("Daniel Mensah"), "Daniel's laptop")
        aiko = client.enroll(srv.code("Aiko Tanaka"), "Aiko's laptop")
        for d in (mira, tomas, priya, daniel, aiko):
            d.login()
        crown = aiko.protect("patent-draft.docx", os.urandom(40_000), "restricted", [daniel.device_id])["file"]["file_id"]
        conf = aiko.protect("q3-results.xlsx", os.urandom(20_000), "confidential", [daniel.device_id])["file"]["file_id"]
        memo = aiko.protect("canteen-menu.txt", b"soup", "internal", [daniel.device_id])["file"]["file_id"]
        before = _code(lambda: daniel.open(conf))

        # the identity source reports an admin role nobody approved
        now = int(time.time())
        priya.post("/api/v1/signals", {"iss": "sandbox-idp", "jti": secrets.token_hex(16), "iat": now,
                                       "aud": "quantumguard", "events": {"urn:qg:event-type:privilege-observed": {
                                           "subject": {"format": "opaque", "id": daniel.user_id},
                                           "event_timestamp": now, "role": "admin"}}})
        alerts = priya.get("/api/v1/alerts?limit=200")["items"]
        r005 = next((a for a in alerts if a["rule_id"] == "QG-R005" and a["subject"]["user_id"] == daniel.user_id), None)
        r007 = next((a for a in alerts if a["rule_id"] == "QG-R007"), None)
        path = priya.get(f"/api/v1/alerts/{r007['id']}").get("path", []) if r007 else []
        quarantined = _code(lambda: daniel.open(conf))
        crown_blocked = _code(lambda: daniel.open(crown))
        internal_ok = _code(lambda: daniel.open(memo)) is None
        others_ok = _code(lambda: aiko.open(conf)) is None

        # the legitimate path: signed request, self-approval refused, a second admin approves
        change = mira.request_change("role_grant", daniel.user_id, role="admin", reason="on-call cover")
        self_approval = _code(lambda: mira.approve_change(change))
        pending = tomas.get("/api/v1/changes?status=pending")["items"][0]
        applied = tomas.approve_change(pending)["status"]

        # an operator reviews and lifts the scoped response
        priya.post(f"/api/v1/responses/{r005['response']['id']}/lift", {"reason": "change approved by two admins"})
        daniel.login()
        after_lift = _code(lambda: daniel.open(conf))

        ok = (before is None and r005 is not None and r005["response"]["action"] == "quarantine_identity"
              and r005["response"]["scope"] == {"kind": "identity", "id": daniel.user_id}
              and quarantined == "QG_QUARANTINED/identity_quarantined" and crown_blocked is not None and internal_ok
              and others_ok and any(e["relation"] == "unlocks" for e in path)
              and self_approval == "QG_DENY_POLICY/self_approval" and applied == "applied" and after_lift is None)
        return result("privilege", ok, alert_rule=r005["rule_id"] if r005 else None,
                      response=(r005 or {}).get("response", {}).get("action"), path_rule=(r007 or {}).get("rule_id"),
                      path_edges=len(path), sensitive_denied=quarantined, internal_still_open=internal_ok,
                      other_people_unaffected=others_ok, self_approval_blocked=self_approval == "QG_DENY_POLICY/self_approval",
                      approved_change=applied, open_after_lift=after_lift is None,
                      receipt_id=(r005 or {}).get("explanation", {}).get("receipt_ids", [None])[0])
    finally:
        srv.close()
