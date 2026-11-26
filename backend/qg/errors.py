"""Stable error codes (spec/API.md section 1.2). Messages never carry internal detail."""

from __future__ import annotations

STATUS = {
    "QG_INVALID_INPUT": 400,
    "QG_BAD_SUITE": 400,
    "QG_BAD_SIGNATURE": 400,
    "QG_NO_SESSION": 401,
    "QG_BAD_MAC": 401,
    "QG_REPLAY": 401,
    "QG_DENY_REVOKED": 403,
    "QG_DENY_POLICY": 403,
    "QG_QUARANTINED": 403,
    "QG_STALE_EPOCH": 409,
    "QG_LEASE_EXPIRED": 403,
    "QG_NOT_FOUND": 404,
    "QG_CONFLICT": 409,
    "QG_RATE_LIMITED": 429,
    "QG_UNAVAILABLE_FAIL_CLOSED": 503,
}

MESSAGES = {
    "QG_INVALID_INPUT": "The request was not valid. Check the fields and try again.",
    "QG_BAD_SUITE": "Only suite QG-1 is supported.",
    "QG_BAD_SIGNATURE": "A signature or key confirmation did not verify.",
    "QG_NO_SESSION": "No valid session. Sign in again.",
    "QG_BAD_MAC": "The request signature did not verify. Sign in again.",
    "QG_REPLAY": "This request was already used. The session has ended; sign in again.",
    "QG_DENY_REVOKED": "This device has been revoked and can no longer be used.",
    "QG_DENY_POLICY": "Policy does not allow this action.",
    "QG_QUARANTINED": "Access is on hold by an automatic security response. An operator can lift it.",
    "QG_STALE_EPOCH": "The request was built on an old directory. Refresh and try again.",
    "QG_LEASE_EXPIRED": "The download lease has expired or was cancelled. Open the file again.",
    "QG_NOT_FOUND": "Not found.",
    "QG_CONFLICT": "The current state does not allow this.",
    "QG_RATE_LIMITED": "Too many requests. Wait and try again.",
    "QG_UNAVAILABLE_FAIL_CLOSED": "A required service is unavailable, so nothing was released. Try again shortly.",
}


class QGError(Exception):
    def __init__(
        self,
        code: str,
        reason: str | None = None,
        *,
        receipt_id: str | None = None,
        retry_after: int | None = None,
        message: str | None = None,
    ) -> None:
        if code not in STATUS:
            raise ValueError(code)
        super().__init__(code)
        self.code = code
        self.reason = reason or code.removeprefix("QG_").lower()
        self.receipt_id = receipt_id
        self.retry_after = retry_after
        self.message = message or MESSAGES[code]

    @property
    def status(self) -> int:
        return STATUS[self.code]

    def body(self, request_id: str) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "reason": self.reason,
                "request_id": request_id,
                "receipt_id": self.receipt_id,
            }
        }
