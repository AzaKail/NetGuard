from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import psutil
import uvicorn


HOST = "127.0.0.1"
PORT = 8000
BASE_URL = f"http://{HOST}:{PORT}"


def runtime_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def configure_environment() -> None:
    data_dir = runtime_dir() / "netguard_data"
    data_dir.mkdir(exist_ok=True)
    os.environ.setdefault("NETGUARD_DB_URL", f"sqlite:///{(data_dir / 'netguard.db').as_posix()}")


def pick_iface() -> str:
    pernic = psutil.net_io_counters(pernic=True)
    best = None
    best_val = -1
    for name, counters in pernic.items():
        value = counters.bytes_sent + counters.bytes_recv
        if value > best_val:
            best = name
            best_val = value
    return best or "unknown"


def read_iface(name: str):
    pernic = psutil.net_io_counters(pernic=True)
    if name not in pernic:
        raise RuntimeError(f"Network interface '{name}' was not found. Available: {list(pernic.keys())}")
    return pernic[name]


def post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def get_status() -> bool:
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/status", timeout=1) as response:
            response.read()
        return True
    except Exception:
        return False


def server_thread() -> None:
    from server.app.main import app

    config = uvicorn.Config(
        app,
        host=HOST,
        port=PORT,
        log_level="warning",
    )
    uvicorn.Server(config).run()


def local_agent_thread(interval: float = 5.0) -> None:
    iface = pick_iface()
    host = socket.gethostname()
    url = f"{BASE_URL}/ingest"

    print(f"[agent] real metrics enabled: host={host} iface={iface} interval={interval}s")
    prev = read_iface(iface)
    prev_t = time.time()

    while True:
        time.sleep(interval)
        cur = read_iface(iface)
        cur_t = time.time()
        dt = max(cur_t - prev_t, 0.001)

        payload = {
            "host": host,
            "iface": iface,
            "ts": datetime.now(timezone.utc).isoformat(),
            "interval_s": interval,
            "manual_anomaly": False,
            "bps_in": max(0.0, (cur.bytes_recv - prev.bytes_recv) / dt),
            "bps_out": max(0.0, (cur.bytes_sent - prev.bytes_sent) / dt),
            "pps_in": max(0.0, (cur.packets_recv - prev.packets_recv) / dt),
            "pps_out": max(0.0, (cur.packets_sent - prev.packets_sent) / dt),
            "err_in": max(0.0, (cur.errin - prev.errin) / dt),
            "err_out": max(0.0, (cur.errout - prev.errout) / dt),
            "drop_in": max(0.0, (cur.dropin - prev.dropin) / dt),
            "drop_out": max(0.0, (cur.dropout - prev.dropout) / dt),
        }

        try:
            result = post_json(url, payload)
            status = "ANOMALY" if result.get("is_anomaly") else "ok"
            model = "ready" if result.get("model_ready") else "training"
            print(f"[agent] sent: {status}, model={model}, score={result.get('anomaly_score'):.4f}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"[agent] send error: {exc}")

        prev = cur
        prev_t = cur_t


def main() -> None:
    configure_environment()

    print("NetGuard.AI")
    print("Starting local server and real local agent...")
    print(f"Data folder: {runtime_dir() / 'netguard_data'}")

    threading.Thread(target=server_thread, daemon=True).start()

    for _ in range(30):
        if get_status():
            break
        time.sleep(0.5)
    else:
        print("Server did not start. Check that port 8000 is free.")
        input("Press Enter to exit...")
        return

    print(f"Web panel: {BASE_URL}")
    webbrowser.open(BASE_URL)

    threading.Thread(target=local_agent_thread, daemon=True).start()

    print("Running. Close this window or press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
