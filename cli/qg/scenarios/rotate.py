"""Supporting workflow 2, service key rotation: an admin creates a service identity, rotates its key (old key
retiring, still accepted), then an operator performs an emergency rotation. The signed key set verifies with
the server's public keys at every epoch, and a retired key is denied with QG-R010."""

from __future__ import annotations

import httpx

from qg.client import QGClient
from qg.crypto.encoding import b64u_decode
from qg.crypto.sign import verify_dual
from qg.scenarios.harness import Server, result


def run() -> int:
    srv = Server().start()
    try:
        client = QGClient(srv.url)
        meta = client.meta()
        ed, pq = b64u_decode(meta["server_keys"]["ed25519_pk"]), b64u_decode(meta["server_keys"]["mldsa_pk"])
        public = httpx.Client(base_url=srv.url, timeout=10)

        def keyset() -> dict:
            ks = public.get("/api/v1/keys").json()
            if not verify_dual(ks, "keyset", ed, pq):
                raise RuntimeError("key set signature")
            return ks

        mira = client.enroll(srv.code("Mira Okafor"), "Mira's laptop")
        priya = client.enroll(srv.code("Priya Raman"), "Priya's workstation")
        mira.login()
        priya.login()
        epoch0 = keyset()["epoch"]
        svc = mira.post("/api/v1/services", {"name": "lims-export"})
        first = svc["keys"][0]["key_id"]

        def use(dev, key_id: str) -> tuple[int, str | None]:  # noqa: ANN001
            r = dev.raw_request("GET", "/api/v1/services", headers={"QG-Service-Key": key_id})
            return r.status_code, (r.json().get("error") or {}).get("reason") if r.status_code >= 400 else None

        planned = mira.post(f"/api/v1/services/{svc['service_id']}/rotate", {"reason": "quarterly", "emergency": False})
        second = next(k["key_id"] for k in planned["keys"] if k["status"] == "active")
        retiring_status = next(k["status"] for k in planned["keys"] if k["key_id"] == first)
        retiring_ok = use(mira, first)[0] == 200
        operator_plain = priya.raw_request("POST", f"/api/v1/services/{svc['service_id']}/rotate",
                                           body=b'{"reason":"x","emergency":false}').status_code
        emergency = priya.post(f"/api/v1/services/{svc['service_id']}/rotate",
                               {"reason": "key exposed in a build log", "emergency": True})
        statuses = {k["key_id"]: k["status"] for k in emergency["keys"]}
        denied = use(mira, second)
        alerts = priya.get("/api/v1/alerts?rule_id=QG-R010")["items"]
        ks = keyset()
        published = {k["key_id"]: k["status"] for k in ks["keys"]}
        ok = (retiring_status == "retiring" and retiring_ok and operator_plain == 403
              and statuses[first] == "retired" and statuses[second] == "retired"
              and list(statuses.values()).count("active") == 1 and denied == (403, "key_retired") and alerts
              and alerts[0]["response"]["scope"] == {"kind": "credential", "id": second}
              and published.get(second) == "retired" and ks["epoch"] >= epoch0 + 3)
        return result("rotate", bool(ok), service_id=svc["service_id"], keyset_epoch_before=epoch0,
                      keyset_epoch_after=ks["epoch"], keyset_verified=True, retiring_key_accepted=retiring_ok,
                      operator_needs_emergency=operator_plain == 403, retired_key_denied=denied == (403, "key_retired"),
                      alert_rule=alerts[0]["rule_id"] if alerts else None,
                      receipt_id=alerts[0]["explanation"]["receipt_ids"][0] if alerts else None)
    finally:
        srv.close()
