"""Start the server without a shell in the runtime image."""

import os
import sys

from qg.server import main

if __name__ == "__main__":
    # Bind inside the container; Compose publishes the port on host loopback only.
    os.environ.setdefault("QG_HOST", "0.0.0.0")  # nosec B104
    # qg.server reads QG_TRUSTED_PROXIES so the client address comes from the proxy's X-Forwarded-For.
    sys.exit(main())
