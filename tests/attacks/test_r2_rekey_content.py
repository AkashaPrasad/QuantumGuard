"""Review r2, H1 follow-up: the fix pins a holder's re-key to the pending recipient set, but nothing pins the
content. A holder who is not the owner may never create an `update` version (owner-only), yet a re-key version
carries whatever ciphertext the holder uploads. Once any re-key job is pending, the holder commits a "re-key"
with new content for exactly the listed recipients, and the owner's next open silently returns the holder's
content. The holder can create the pending job themselves by reporting one of their own devices lost."""

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


def _owner_reads(owner, fid):
    try:
        return owner.open(fid)
    except Exception:  # noqa: BLE001  a client that detects the substitution and refuses is an acceptable fix
        return None


def test_holder_rekey_cannot_replace_content_after_owner_unshare(env):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    tomas = env.device("Tomas Lindqvist")
    fid = aiko.protect("plan.txt", b"owner content", "confidential",
                       [dan.device_id, tomas.device_id])["file"]["file_id"]
    aiko.post(f"/api/v1/files/{fid}/unshare", {"user_id": tomas.user_id})  # owner's action queues a re-key
    item = next(i for i in dan.rekey_pending()["rekeys"] if i["file_id"] == fid)

    r = _rekey_as(env, dan, fid, b"written by a read-only recipient", item["recipients"])

    got = _owner_reads(aiko, fid)
    assert got in (b"owner content", None), (
        f"holder's re-key (HTTP {r.status_code}) replaced the owner's content; owner now reads {got!r}")


def test_holder_can_not_self_queue_a_rekey_and_replace_content(env):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    dan_phone = env.second_device("Daniel Mensah", "Dan's phone")
    fid = aiko.protect("plan.txt", b"owner content", "confidential",
                       [dan.device_id, dan_phone.device_id])["file"]["file_id"]
    assert dan.rekey_pending()["rekeys"] == []
    dan_phone.open(fid)  # a released slot makes the file "held", so the report queues a re-key
    dan.post(f"/api/v1/devices/{dan_phone.device_id}/report-lost", {"lost_at": env.clock.iso()})  # self-caused job
    item = next(i for i in dan.rekey_pending()["rekeys"] if i["file_id"] == fid)
    assert sorted(item["recipients"]) == sorted([aiko.device_id, dan.device_id])

    r = _rekey_as(env, dan, fid, b"written by a read-only recipient", item["recipients"])

    got = _owner_reads(aiko, fid)
    assert got in (b"owner content", None), (
        f"holder's self-queued re-key (HTTP {r.status_code}) replaced the owner's content; owner reads {got!r}")


def test_holder_rekey_cannot_add_back_the_unshared_person(env):
    """Regression (passes): the pending set is exact, so a holder cannot re-add someone the owner removed."""
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    tomas = env.device("Tomas Lindqvist")
    fid = aiko.protect("plan.txt", b"owner content", "confidential",
                       [dan.device_id, tomas.device_id])["file"]["file_id"]
    aiko.post(f"/api/v1/files/{fid}/unshare", {"user_id": tomas.user_id})
    item = next(i for i in dan.rekey_pending()["rekeys"] if i["file_id"] == fid)

    r = _rekey_as(env, dan, fid, b"owner content", sorted(item["recipients"] + [tomas.device_id]))

    assert r.status_code == 403 and r.json()["error"]["reason"] == "recipient_not_allowed"
    assert [x["device_id"] for x in aiko.get(f"/api/v1/files/{fid}")["recipients"]] == sorted(item["recipients"])
