"""QG-R013: evidence log mismatch."""

from __future__ import annotations

from .conftest import check_explanation, check_response, err_of, only_alert, protect_file


def test_tampered_receipt_freezes_key_release(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    fid = protect_file(aiko)
    aiko.open(fid)
    assert not env.alerts()

    idx, leaf = env.core.db.one("SELECT leaf_index, leaf FROM receipts ORDER BY leaf_index LIMIT 1")
    flipped = (leaf[:-1] + ("A" if leaf[-1] != "A" else "B")) if isinstance(leaf, str) \
        else leaf[:-1] + bytes([leaf[-1] ^ 1])
    with env.core.db.tx() as conn:
        conn.execute("UPDATE receipts SET leaf = ? WHERE leaf_index = ?", (flipped, idx))
    env.core.self_audit()

    alert = only_alert(env, "QG-R013")
    assert alert["severity"] == "critical"
    check_explanation(alert, receipts=False)
    check_response(alert, "freeze_key_release", "global", None)

    e = err_of(aiko.slot, fid)
    assert e.status == 503 and e.code == "QG_UNAVAILABLE_FAIL_CLOSED" and e.reason == "key_release_frozen"

    priya.post(f"/api/v1/alerts/{alert['id']}/ack", {})
    fresh = next(a for a in env.alerts("QG-R013"))
    assert fresh["response"]["lifted_at"] is not None
    # The store itself is still tampered; only the freeze was lifted.
