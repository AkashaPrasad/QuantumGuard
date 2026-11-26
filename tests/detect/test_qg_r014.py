"""QG-R014: unknown or weaker suite requested."""

from __future__ import annotations

from .conftest import check_explanation, only_alert


def test_unknown_suite_is_refused_and_alerted(env):
    code = env.people["Aiko Tanaka"]["code"]
    r = env.http.post("/api/v1/enroll/start", json={"suite": "QG-0", "code": code, "device_name": "x",
                                                    "kem_pk": "AAAA", "sig_pk": "AAAA"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "QG_BAD_SUITE"

    alert = only_alert(env, "QG-R014")
    assert alert["severity"] == "medium"
    assert alert["response"] is None
    check_explanation(alert, receipts=False)

    # Nothing was throttled: the same code still enrols a device.
    assert env.enroll("Aiko Tanaka").device_id
