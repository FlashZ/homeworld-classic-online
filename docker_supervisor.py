#!/usr/bin/env python3
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from typing import Optional


def _terminate(proc: Optional[subprocess.Popen[str]]) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    app_dir = os.environ["APP_DIR"]
    db_path = os.environ["DB_PATH"]
    keys_dir = os.environ["KEYS_DIR"]

    backend_cmd = [
        sys.executable,
        os.path.join(app_dir, "won_server.py"),
        "--host",
        os.environ["BACKEND_HOST"],
        "--port",
        os.environ["BACKEND_PORT"],
        "--db-path",
        db_path,
    ]
    gateway_cmd = [
        sys.executable,
        os.path.join(app_dir, "titan_binary_gateway.py"),
        "--host",
        os.environ["GATEWAY_HOST"],
        "--port",
        os.environ["GATEWAY_PORT"],
        "--backend-host",
        os.environ["BACKEND_HOST"],
        "--backend-port",
        os.environ["BACKEND_PORT"],
        "--public-host",
        os.environ["PUBLIC_HOST"],
        "--routing-port",
        os.environ["ROUTING_PORT"],
        "--routing-max-port",
        os.environ["ROUTING_MAX_PORT"],
        "--firewall-port",
        os.environ["FIREWALL_PORT"],
        "--admin-host",
        os.environ["ADMIN_HOST"],
        "--admin-port",
        os.environ["ADMIN_PORT"],
        "--keys-dir",
        keys_dir,
        "--log",
        os.environ["LOG_LEVEL"],
    ]

    backend = subprocess.Popen(backend_cmd)
    gateway: Optional[subprocess.Popen[str]] = None

    def handle_signal(signum: int, _frame: object) -> None:
        _terminate(gateway)
        _terminate(backend)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        for _ in range(20):
            if backend.poll() is not None:
                return int(backend.returncode or 1)
            time.sleep(0.1)

        gateway = subprocess.Popen(gateway_cmd)

        while True:
            backend_rc = backend.poll()
            gateway_rc = gateway.poll()
            if backend_rc is not None:
                _terminate(gateway)
                return int(backend_rc)
            if gateway_rc is not None:
                _terminate(backend)
                return int(gateway_rc)
            time.sleep(0.5)
    finally:
        _terminate(gateway)
        _terminate(backend)


if __name__ == "__main__":
    raise SystemExit(main())
