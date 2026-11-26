"""Device key material and the passphrase keystore file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from qg.crypto import keystore
from qg.crypto.encoding import b64u
from qg.crypto.sign import MLDSAKey
from qg.crypto.xwing import XWingPrivateKey


@dataclass
class DeviceKeys:
    sig: MLDSAKey
    kem: XWingPrivateKey

    @classmethod
    def generate(cls) -> DeviceKeys:
        return cls(MLDSAKey.generate(), XWingPrivateKey.generate())

    @classmethod
    def from_seeds(cls, seeds: keystore.DeviceSeeds) -> DeviceKeys:
        return cls(MLDSAKey.from_seed(seeds.sig_seed), XWingPrivateKey.from_seed(seeds.kem_seed))

    @property
    def seeds(self) -> keystore.DeviceSeeds:
        return keystore.DeviceSeeds(sig_seed=self.sig.seed, kem_seed=self.kem.seed)

    @property
    def sig_pk_b64u(self) -> str:
        return b64u(self.sig.public_key)

    @property
    def kem_pk_b64u(self) -> str:
        return b64u(self.kem.public_key)

    def __repr__(self) -> str:
        return "DeviceKeys(<redacted>)"


@dataclass
class DeviceState:
    """Everything a client remembers about its enrolment (public data plus the keys)."""

    keys: DeviceKeys
    device_name: str
    device_id: str | None = None
    user_id: str | None = None
    server: str | None = None
    created_at: str = ""
    server_keys: dict[str, str] = field(default_factory=dict)  # pinned at enrolment (TOFU)
    highest_epoch: int = 0

    def label(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "server": self.server,
            "user_id": self.user_id,
        }

    def save(self, path: str, passphrase: str) -> None:
        doc = keystore.seal_keystore(self.keys.seeds, passphrase, self.label())
        keystore.save_file(path, doc)
        side = path + ".public.json"
        import json

        with open(side, "w", encoding="utf-8") as fh:
            json.dump({"server_keys": self.server_keys, "highest_epoch": self.highest_epoch}, fh, indent=2)

    @classmethod
    def load(cls, path: str, passphrase: str) -> DeviceState:
        import json

        doc = keystore.load_file(path)
        seeds = keystore.open_keystore(doc, passphrase)
        label = doc["label"]
        st = cls(DeviceKeys.from_seeds(seeds), label["device_name"], label["device_id"], label["user_id"],
                 label["server"], label["created_at"])
        side = path + ".public.json"
        if os.path.exists(side):
            with open(side, encoding="utf-8") as fh:
                pub = json.load(fh)
            st.server_keys = pub.get("server_keys", {})
            st.highest_epoch = int(pub.get("highest_epoch", 0))
        return st
