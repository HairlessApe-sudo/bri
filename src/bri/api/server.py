from __future__ import annotations

import os
from collections.abc import Mapping

import uvicorn


def resolve_server_bind(env: Mapping[str, str]) -> tuple[str, int]:
    environment = env.get("BRI_ENVIRONMENT", "").strip().lower()
    if environment == "development":
        host = "127.0.0.1"
    elif environment == "hosted-development":
        host = "0.0.0.0"
    else:
        raise ValueError("BRI_ENVIRONMENT must be development or hosted-development")

    port_text = env.get("PORT", "8000")
    if not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("PORT must be an integer from 1 to 65535")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be an integer from 1 to 65535")
    return host, port


def main() -> None:
    host, port = resolve_server_bind(os.environ)
    uvicorn.run(
        "bri.api.main:app",
        host=host,
        port=port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
