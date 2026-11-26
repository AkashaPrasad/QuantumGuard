"""Finding: a recipient (any device holding a slot) can commit a 're-key' version that names only itself,
removing the owner and every other recipient and replacing the content. The commit deletes the old slots,
the old recovery slot and the old ciphertext, so the owner cannot get the file back. Unshare is owner-only
(P-FILE-OWNER), but a re-key commit by a holder achieves the same removal without that check, and nothing
requires a re-key to be pending or the new recipients to match the remaining holders."""

from __future__ import annotations

import json

from qgsec import commit_body, upload_chunks


def _rekey_as(env, dev, fid, data, recipients):
    r = dev.raw_request("POST", f"/api/v1/files/{fid}/versions",
                        body=json.dumps({"reason": "rekey", "size_bytes": len(data), "chunk_count": 1}).encode())
    if r.status_code != 200:
        return r
    version = r.json()["version"]
    dek, blobs = upload_chunks(dev, fid, version, data)
    body = commit_body(env, dev, fid, version, dek, blobs, "confidential", recipients)
    return dev.raw_request("POST", f"/api/v1/files/{fid}/versions/{version}/commit",
                           body=json.dumps(body).encode())


def test_recipient_cannot_rekey_owner_out_of_file(env):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    fid = aiko.protect("plan.txt", b"owner content", "confidential", [dan.device_id])["file"]["file_id"]
    assert dan.rekey_pending()["rekeys"] == []  # nothing was revoked or unshared: no re-key is due

    r = _rekey_as(env, dan, fid, b"replaced by a recipient", [dan.device_id])

    assert r.status_code == 403, f"holder re-key that drops the owner was accepted ({r.status_code})"
    assert r.json()["error"]["code"] == "QG_DENY_POLICY"
    assert aiko.open(fid) == b"owner content"


def test_pending_rekey_must_keep_the_remaining_recipients(env):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    tomas = env.device("Tomas Lindqvist")
    fid = aiko.protect("plan.txt", b"owner content", "confidential",
                       [dan.device_id, tomas.device_id])["file"]["file_id"]
    aiko.post(f"/api/v1/files/{fid}/unshare", {"user_id": tomas.user_id})  # queues a re-key
    item = next(i for i in dan.rekey_pending()["rekeys"] if i["file_id"] == fid)
    assert sorted(item["recipients"]) == sorted([aiko.device_id, dan.device_id])

    r = _rekey_as(env, dan, fid, b"owner content", [dan.device_id])  # commits for fewer than the listed recipients

    assert r.status_code == 403, f"re-key for a subset of the remaining recipients was accepted ({r.status_code})"
    assert aiko.open(fid) == b"owner content"
