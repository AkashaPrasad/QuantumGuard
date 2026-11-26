"""One alert reaches the API, the structured log and SECURITY_EVENTS.jsonl with the same id."""

from __future__ import annotations

import json


def test_alert_appears_on_every_channel(env):
    aiko = env.device("Aiko Tanaka")
    priya = env.device("Priya Raman")
    aiko.raw_request("GET", "/api/v1/devices", seq=7)
    aiko.raw_request("GET", "/api/v1/devices", seq=7)

    api = priya.get("/api/v1/alerts")
    items = api["items"] if isinstance(api, dict) else api
    ids = [a["id"] for a in items]
    assert len(ids) == 1
    alert_id = ids[0]

    logged = [e for e in env.json_logs() if e.get("event") == "alert"]
    assert [e["id"] for e in logged] == [alert_id]
    assert logged[0]["rule_id"] == "QG-R002"

    path = env.core.settings.data_dir / "SECURITY_EVENTS.jsonl"
    lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert [x["id"] for x in lines] == [alert_id]
    assert lines[0]["rule_id"] == "QG-R002"
