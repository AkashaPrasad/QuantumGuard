"""Off-camera attacker for the demo recording (scripts/demo-video.sh). Runs inside the demo container:

    docker compose ... exec -T quantumguard python - CODE DECOY_FILE_ID < scripts/demo-attacks.py

With a device enrolled for Daniel Mensah it sweeps invented file ids (QG-R009), replays a signed request
(QG-R002) and opens a planted decoy file (QG-R004). Every attempt is refused by the server, recorded and alerted
with a scoped response; the operator sees the alerts in the console. Prints one JSON line with what happened.
"""

from __future__ import annotations

import base64
import json
import os
import sys

from qg.client.api import ApiError, QGClient

code, decoy = sys.argv[1], sys.argv[2]
client = QGClient("http://127.0.0.1:8080")
dev = client.enroll(code, "Daniel's laptop")
dev.login()
out: dict[str, object] = {}

# 1. enumeration: invented file ids, one a second in server time terms
statuses = []
for _ in range(22):
    fid = "fil_" + base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    statuses.append(dev.raw_request("GET", f"/api/v1/files/{fid}/slot").status_code)
out["enumeration"] = {"refused": sum(s >= 400 for s in statuses), "sent": len(statuses)}

# 2. replay: the same signed request twice with the same sequence number
dev.login()
seq = dev.session.seq + 1
dev.raw_request("GET", "/api/v1/devices", seq=seq)
replayed = dev.raw_request("GET", "/api/v1/devices", seq=seq)
out["replay"] = {"status": replayed.status_code, "code": replayed.json().get("error", {}).get("code")}

# 3. a planted decoy file: nobody legitimate ever opens it
dev.login()
try:
    dev.slot(decoy)
    out["decoy"] = {"status": 200}
except ApiError as e:
    out["decoy"] = {"status": e.status, "code": e.code}

print(json.dumps(out))
