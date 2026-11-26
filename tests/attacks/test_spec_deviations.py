"""Low-severity deviations from spec/SUITE.md and spec/API.md, each demonstrated on current main.

1. Leases are not bound to the session (SUITE 16: "bound to session, device, file and version").
2. A suite other than QG-1 inside a nested signed object (manifest, share statement) answers
   QG_INVALID_INPUT and raises no QG-R014 (SUITE 1, THREAT_MODEL C31).
3. A path integer above 2^63-1 reaches SQLite, raises OverflowError and answers 503 internal instead of 4xx.
4. A retired service key is refused only on GET /services; on every other route it is accepted silently and
   raises no QG-R010 (API 9: "A retired key presented to any route answers QG_DENY_POLICY / key_retired").
"""

from __future__ import annotations

import json
import os

from fastapi.testclient import TestClient

from qg.client.api import Device
from qgsec import commit_body, new_file, upload_chunks


def test_lease_is_bound_to_the_session_that_opened_the_slot(env):
    laptop = env.device("Aiko Tanaka")
    fid = laptop.protect("a.bin", os.urandom(500), "confidential")["file"]["file_id"]
    other_session = Device(laptop.http, laptop.state)
    other_session.login()
    lease = laptop.slot(fid)["lease"]["lease_id"]

    r = other_session.raw_request("GET", f"/api/v1/files/{fid}/chunks/0", headers={"QG-Lease": lease})

    assert r.status_code == 403, f"a lease issued to another session was honoured ({r.status_code})"
    assert r.json()["error"]["code"] == "QG_LEASE_EXPIRED"


def test_nested_object_with_other_suite_is_bad_suite_and_alerted(env):
    laptop = env.device("Aiko Tanaka")
    data = os.urandom(300)
    fid = new_file(laptop, "s.bin", data)
    dek, blobs = upload_chunks(laptop, fid, 1, data)
    body = commit_body(env, laptop, fid, 1, dek, blobs, "confidential", [laptop.device_id], suite="QG-0")

    r = laptop.raw_request("POST", f"/api/v1/files/{fid}/versions/1/commit", body=json.dumps(body).encode())

    assert r.status_code == 400
    assert r.json()["error"]["code"] == "QG_BAD_SUITE", r.json()["error"]
    assert env.alerts("QG-R014"), "no QG-R014 alert for a manifest naming another suite"


def test_huge_path_integer_is_refused_as_input_not_server_error(env):
    laptop = env.device("Aiko Tanaka")
    fid = laptop.protect("a.bin", os.urandom(100), "internal")["file"]["file_id"]
    dev = Device(TestClient(env.app, base_url="http://testserver", raise_server_exceptions=False), laptop.state)
    dev.session = laptop.session

    r = dev.raw_request("PUT", f"/api/v1/files/{fid}/versions/{2**64}/chunks/0", body=os.urandom(64),
                        content_type="application/octet-stream")

    assert r.status_code in (400, 404), (r.status_code, r.json()["error"])
    assert not any('"unhandled_error"' in line for line in env.logs)


def test_retired_service_key_is_refused_on_any_route(env):
    mira = env.device("Mira Okafor")
    svc = mira.post("/api/v1/services", {"name": "ci-signer"})
    old_key = svc["keys"][0]["key_id"]
    mira.post(f"/api/v1/services/{svc['service_id']}/rotate", {"reason": "key leaked", "emergency": True})
    assert mira.raw_request("GET", "/api/v1/services", headers={"QG-Service-Key": old_key}).status_code == 403

    r = mira.raw_request("GET", "/api/v1/files", headers={"QG-Service-Key": old_key})

    assert r.status_code == 403 and r.json()["error"]["reason"] == "key_retired", r.status_code
