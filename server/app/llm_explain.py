"""Alert explanation with a local LLM served by Ollama (https://ollama.com).

The detector (Isolation Forest) decides whether a point is anomalous. The LLM
only turns the numbers around an alert into a short report for the operator.
Nothing leaves the local network: Ollama runs on the admin PC.

Settings (environment variables):
  NETGUARD_OLLAMA_URL    default http://127.0.0.1:11434
  NETGUARD_OLLAMA_MODEL  default qwen2.5:3b   (also: llama3.2:3b, gemma2:2b, qwen2.5:7b)
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from statistics import mean, pstdev

OLLAMA_URL = os.getenv("NETGUARD_OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("NETGUARD_OLLAMA_MODEL", "qwen2.5:3b")

FEATURES = ["bps_in", "bps_out", "pps_in", "pps_out", "err_in", "err_out", "drop_in", "drop_out"]

SYSTEM = (
    "Ты помощник администратора сети в системе NetGuard. Система не анализирует "
    "содержимое пакетов, только счётчики сетевого интерфейса хоста. Аномалию уже "
    "обнаружил алгоритм Isolation Forest, твоя задача объяснить её. Отвечай по-русски, "
    "кратко, по шаблону:\n"
    "1. Что произошло (1-2 предложения, с конкретными числами из данных).\n"
    "2. На что похоже: выбери из [объёмная атака/флуд, сканирование, утечка данных "
    "(исходящий всплеск), проблема канала или драйвера (ошибки/сбросы), легитимная "
    "нагрузка (обновление, бэкап), недостаточно данных] и объясни почему.\n"
    "3. Что проверить администратору (2-4 пункта).\n"
    "Используй только числа из данных. Если данных мало, так и скажи. Не придумывай "
    "IP-адреса, процессы и порты, которых нет в данных."
)


def build_context(alert, window: list, baseline: list) -> dict:
    """alert: Alert row; window: Metric rows around the alert (oldest first);
    baseline: Metric rows of the same host before the window."""
    def stats(rows, f):
        vals = [getattr(r, f) for r in rows]
        return (mean(vals), pstdev(vals)) if vals else (0.0, 0.0)

    base = {f: stats(baseline, f) for f in FEATURES}
    at = min(window, key=lambda r: abs((r.ts - alert.ts).total_seconds())) if window else None
    return {
        "host": alert.host,
        "iface": alert.iface,
        "time": alert.ts.isoformat(),
        "anomaly_score": round(alert.score, 4),
        "threshold": round(alert.threshold, 4),
        "detector_reason": alert.reason,
        "baseline_mean_std": {f: [round(m, 1), round(s, 1)] for f, (m, s) in base.items()},
        "value_at_alert": {f: round(getattr(at, f), 1) for f in FEATURES} if at else {},
        "series": [
            {"t": r.ts.strftime("%H:%M:%S"), **{f: round(getattr(r, f), 1) for f in FEATURES},
             "anomaly": bool(r.is_anomaly)}
            for r in window
        ],
    }


def make_prompt(ctx: dict) -> str:
    return "Данные алерта (JSON):\n" + json.dumps(ctx, ensure_ascii=False, indent=1)


def ask_ollama(prompt: str, model: str | None = None, timeout: float = 120.0) -> tuple[str, float]:
    model = model or OLLAMA_MODEL
    body = json.dumps({
        "model": model,
        "stream": False,
        "options": {"temperature": 0.2},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    t = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Ollama недоступна по адресу {OLLAMA_URL} ({e}). Запустите `ollama serve` "
            f"и скачайте модель: `ollama pull {model}`") from e
    return data["message"]["content"].strip(), time.perf_counter() - t
