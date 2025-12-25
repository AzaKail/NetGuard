from __future__ import annotations
import argparse
import socket
import time
from datetime import datetime, timezone
from typing import Dict

import psutil
import requests

def pick_iface() -> str:
    pernic = psutil.net_io_counters(pernic=True)
    best = None
    best_val = -1
    for name, c in pernic.items():
        val = (c.bytes_sent + c.bytes_recv)
        if val > best_val:
            best, best_val = name, val
    return best or "unknown"

def read_iface(name: str):
    pernic = psutil.net_io_counters(pernic=True)
    if name not in pernic:
        raise SystemExit(f"Интерфейс '{name}' не найден. Доступные: {list(pernic.keys())}")
    return pernic[name]

def to_rates(prev, cur, dt: float, simulate: bool, tick: int) -> Dict[str, float]:
    dt = max(dt, 0.001)

    bps_in = (cur.bytes_recv - prev.bytes_recv) / dt
    bps_out = (cur.bytes_sent - prev.bytes_sent) / dt
    pps_in = (cur.packets_recv - prev.packets_recv) / dt
    pps_out = (cur.packets_sent - prev.packets_sent) / dt

    err_in = (cur.errin - prev.errin) / dt
    err_out = (cur.errout - prev.errout) / dt
    drop_in = (cur.dropin - prev.dropin) / dt
    drop_out = (cur.dropout - prev.dropout) / dt

    # Демо-режим: периодически "спайк", чтобы модель увидела аномалии
    if simulate and tick % 25 == 0 and tick > 0:
        mult = 50.0
        bps_in *= mult
        bps_out *= mult
        pps_in *= mult
        pps_out *= mult

    return {
        "bps_in": float(max(0.0, bps_in)),
        "bps_out": float(max(0.0, bps_out)),
        "pps_in": float(max(0.0, pps_in)),
        "pps_out": float(max(0.0, pps_out)),
        "err_in": float(max(0.0, err_in)),
        "err_out": float(max(0.0, err_out)),
        "drop_in": float(max(0.0, drop_in)),
        "drop_out": float(max(0.0, drop_out)),
    }

def main():
    ap = argparse.ArgumentParser(description="NetGuard.AI MVP agent (aggregated network metrics)")
    ap.add_argument("--server", required=True, help="Server URL, e.g. http://127.0.0.1:8000")
    ap.add_argument("--interval", type=float, default=5.0, help="Seconds between sends (default 5)")
    ap.add_argument("--iface", default=None, help="Network interface name (default: auto-pick)")
    ap.add_argument("--host", default=None, help="Host label (default: hostname)")
    ap.add_argument("--simulate", action="store_true", help="Generate synthetic spikes to see anomalies")
    ap.add_argument("--force-anomaly", action="store_true", help="Force manual anomaly flag for demo")
    args = ap.parse_args()

    iface = args.iface or pick_iface()
    host = args.host or socket.gethostname()
    url = args.server.rstrip("/") + "/ingest"

    print(
        f"[agent] host={host} iface={iface} interval={args.interval}s server={url} "
        f"simulate={args.simulate} manual_anomaly={args.force_anomaly}"
    )

    prev = read_iface(iface)
    prev_t = time.time()
    tick = 0

    while True:
        time.sleep(args.interval)
        cur = read_iface(iface)
        cur_t = time.time()
        dt = cur_t - prev_t

        rates = to_rates(prev, cur, dt, args.simulate, tick)
        payload = {
            "host": host,
            "iface": iface,
            "ts": datetime.now(timezone.utc).isoformat(),
            "interval_s": float(args.interval),
            "manual_anomaly": bool(args.force_anomaly),
            **rates
        }

        try:
            r = requests.post(url, json=payload, timeout=5)
            if r.ok:
                data = r.json()
                status = "ANOM" if data.get("is_anomaly") else "ok"
                ready = "ready" if data.get("model_ready") else "warmup"
                print(f"[agent] {status} {ready} score={data.get('anomaly_score'):.4f} thr={data.get('threshold'):.4f}")
            else:
                print(f"[agent] HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            print(f"[agent] send error: {e}")

        prev, prev_t = cur, cur_t
        tick += 1

if __name__ == "__main__":
    main()
