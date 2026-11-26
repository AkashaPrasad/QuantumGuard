"""Start the ASGI application without a shell in the runtime image."""

import os

import uvicorn


if __name__ == "__main__":
    # Bind inside the container; Compose publishes the port on host loopback only.
    uvicorn.run("qg.app:app", host="0.0.0.0", port=int(os.environ.get("QG_PORT", "8080")))  # nosec B104
