"""Ciphertext chunk store on disk: <data>/blobs/<file_id>/<version>/<index>. Writes are atomic."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from qg.ids import is_id


class BlobStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def _dir(self, file_id: str, version: int) -> Path:
        if not is_id(file_id, "fil") or not isinstance(version, int) or version < 1:
            raise ValueError("bad blob address")
        return self.root / file_id / str(version)

    def put(self, file_id: str, version: int, index: int, data: bytes) -> None:
        d = self._dir(file_id, version)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".{index}.tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, d / str(index))

    def get(self, file_id: str, version: int, index: int) -> bytes | None:
        p = self._dir(file_id, version) / str(index)
        try:
            return p.read_bytes()
        except FileNotFoundError:
            return None

    def count(self, file_id: str, version: int) -> int:
        d = self._dir(file_id, version)
        if not d.exists():
            return 0
        return sum(1 for p in d.iterdir() if p.name.isdigit())

    def delete_version(self, file_id: str, version: int) -> None:
        shutil.rmtree(self._dir(file_id, version), ignore_errors=True)

    def delete_file(self, file_id: str) -> None:
        if is_id(file_id, "fil"):
            shutil.rmtree(self.root / file_id, ignore_errors=True)
