"""`python -m qg.server`: run the API (and the built site when QG_WEB_DIST is set)."""

from __future__ import annotations

import os
import signal
import sys

import uvicorn

from qg.app import create_app
from qg.config import Settings
from qg.core import Core


def main() -> int:
    settings = Settings.from_env()
    core = Core(settings)
    core.log_event("server_start", port=settings.port, demo=settings.demo, policy_bundle_hash=core.policy.hash)
    core.start_background()
    app = create_app(core)
    host = os.environ.get("QG_HOST", "127.0.0.1")
    # Behind a reverse proxy, set QG_TRUSTED_PROXIES to the proxy's address(es) so the client address used for
    # rate limits and QG-R012 source responses comes from X-Forwarded-For; otherwise every client looks alike.
    trusted = os.environ.get("QG_TRUSTED_PROXIES", "127.0.0.1")
    config = uvicorn.Config(app, host=host, port=settings.port, access_log=False, log_level="warning",
                            proxy_headers=True, forwarded_allow_ips=trusted,
                            server_header=False, date_header=True, timeout_keep_alive=5,
                            limit_concurrency=512, timeout_graceful_shutdown=5)
    server = uvicorn.Server(config)

    def stop(*_: object) -> None:
        server.should_exit = True

    signal.signal(signal.SIGTERM, stop)
    try:
        server.run()
    finally:
        core.stop()
        core.log_event("server_stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
