"""QuantumGuard `qg` client: device keys, enrolment, sessions with signed requests, protect/open/share,
re-key and offline verification. Importable as a library (tests and scenarios drive real devices)."""

from .api import ApiError, Device, QGClient

__all__ = ["ApiError", "Device", "QGClient"]
