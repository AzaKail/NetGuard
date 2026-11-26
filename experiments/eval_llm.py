"""Evaluate local LLM alert explanations (Ollama) on labelled synthetic alerts.

Each case is built so that its true class is known:
  flood    - inbound packets/bytes jump, outbound unchanged
  scan     - many small packets both ways, volume almost unchanged
  exfil    - outbound bytes/packets jump
  channel  - NIC errors/drops appear, traffic unchanged or lower
  benign   - small deviations (z < 2)
Metrics per model:
  class_acc     - the class named in section 2 equals the true class
  fabricated    - share of answers with a number that is not in the input
                  (tolerance 5%, small numbers < 3 and list numbering ignored)
  latency_s     - median answer time

Usage (on the PC with Ollama running):
  python experiments/eval_llm.py --models gemma4:e2b netguard-analyst --n 8
Result: experiments/results/llm_eval_<model>.jsonl and a summary table.
"""
import argparse, json, os, re, statistics, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server", "app"))
import llm_explain as L  # noqa: E402

F = L.FEATURES
CLASSES = {
    "flood": ["флуд", "объёмн", "объемн"],
    "scan": ["сканир"],
    "exfil": ["утечк", "исходящий всплеск"],
    "channel": ["канал", "драйвер"],
    "benign": ["легитимн", "недостаточно данных"],
}


def make_case(cls, rng):
    import random
    r = random.Random(rng)
    base = {"bps_in": [r.uniform(5e3, 5e4), 0], "bps_out": [r.uniform(4e3, 4e4), 0],
            "pps_in": [r.uniform(10, 80), 0], "pps_out": [r.uniform(8, 60), 0],
            "err_in": [0.0, 0.1], "err_out": [0.0, 0.1], "drop_in": [0.0, 0.1], "drop_out": [0.0, 0.1]}
    for f in ["bps_in", "bps_out", "pps_in", "pps_out"]:
        base[f][1] = base[f][0] * r.uniform(0.2, 0.4)
    at = {f: base[f][0] * r.uniform(0.9, 1.1) for f in F[:4]}
    at.update({f: 0.0 for f in F[4:]})
    k = r.uniform(20, 300)
    if cls == "flood":
        at["pps_in"] *= k; at["bps_in"] *= k
    elif cls == "scan":
        at["pps_in"] *= k / 10; at["pps_out"] *= k / 10; at["bps_in"] *= 1.6; at["bps_out"] *= 1.6
    elif cls == "exfil":
        at["bps_out"] *= k; at["pps_out"] *= k / 3
    elif cls == "channel":
        at["err_in"] = r.uniform(5, 80); at["drop_in"] = r.uniform(5, 80)
        at["bps_in"] *= 0.8; at["pps_in"] *= 0.8
    elif cls == "benign":
        at["pps_in"] = base["pps_in"][0] + 1.5 * base["pps_in"][1]
        at["bps_out"] = base["bps_out"][0] + 1.2 * base["bps_out"][1]
    z = {f: (at[f] - base[f][0]) / max(base[f][1], 1e-9) for f in F}
    top = sorted(F, key=lambda f: -abs(z[f]))[:2]
    reason = "аномалия: " + ", ".join(f"{f} (z={abs(z[f]):.1f})" for f in top)
    rnd = lambda d: {f: round(v, 1) for f, v in d.items()}
    normal_row = {"t": "12:00:00", **rnd({f: base[f][0] for f in F}), "anomaly": False}
    ctx = {"host": "pc-test", "iface": "Ethernet", "anomaly_score": 0.2, "threshold": 0.12,
           "detector_reason": reason,
           "baseline_mean_std": {f: [round(m, 1), round(s, 1)] for f, (m, s) in base.items()},
           "value_at_alert": rnd(at),
           "series": [normal_row, {"t": "12:00:01", **rnd(at), "anomaly": True}]}
    return ctx


def predicted_class(text):
    """Class named first in section 2 (the model may list an alternative after it)."""
    m = re.search(r"2\.(.*?)(?:\n\s*3\.|$)", text, re.S)
    part = (m.group(1) if m else text).lower()
    pos = {c: min((part.find(k) for k in kws if k in part), default=-1) for c, kws in CLASSES.items()}
    pos = {c: p for c, p in pos.items() if p >= 0}
    return min(pos, key=pos.get) if pos else "none"


def numbers(s):
    out = []
    for m in re.finditer(r"(?<![\w.])(\d+(?:[  ]\d{3})*(?:[.,]\d+)?)\s*(к|м|г)?", s, re.I):
        v = float(m.group(1).replace(" ", "").replace(" ", "").replace(",", "."))
        mult = {"к": 1e3, "м": 1e6, "г": 1e9}.get((m.group(2) or "").lower(), 1)
        out.append((v, v * mult))
    return out


def fabricated(text, ctx):
    src = [abs(v) for _, v in numbers(json.dumps(ctx, ensure_ascii=False))]
    src += [s / 1e3 for s in src] + [s / 1e6 for s in src]  # КБ/МБ conversions
    body = re.sub(r"^\s*\d+\.\s", "", text, flags=re.M)  # list numbering
    for raw, val in numbers(body):
        if raw < 3:
            continue
        ok = any(abs(c - x) <= 0.05 * max(abs(x), 1) for x in src for c in (raw, val))
        # ratios like "в 12 раз" are derived, allow them
        if not ok and not re.search(re.escape(str(int(raw))) + r"\s*раз", body):
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=[L.OLLAMA_MODEL])
    ap.add_argument("--n", type=int, default=8, help="cases per class")
    a = ap.parse_args()
    out_dir = os.path.join(os.path.dirname(__file__), "results"); os.makedirs(out_dir, exist_ok=True)
    cases = [(c, make_case(c, 1000 * i + j)) for i, c in enumerate(CLASSES) for j in range(a.n)]
    summary = []
    for model in a.models:
        rows = []
        path = os.path.join(out_dir, f"llm_eval_{model.replace(':', '_').replace('/', '_')}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for cls, ctx in cases:
                try:
                    text, lat = L.ask_ollama(L.make_prompt(ctx), model, timeout=300)
                except RuntimeError as e:
                    print(e); return
                r = dict(model=model, true=cls, pred=predicted_class(text), fabricated=fabricated(text, ctx),
                         latency_s=lat, text=text)
                rows.append(r); f.write(json.dumps(r, ensure_ascii=False) + "\n"); f.flush()
                print(model, cls, "->", r["pred"], "fab" if r["fabricated"] else "", f"{lat:.1f}s", flush=True)
        acc = sum(r["true"] == r["pred"] for r in rows) / len(rows)
        per = {c: sum(r["true"] == r["pred"] for r in rows if r["true"] == c) / a.n for c in CLASSES}
        summary.append(dict(model=model, class_acc=round(acc, 3), fabricated=round(sum(r["fabricated"] for r in rows) / len(rows), 3),
                            latency_med_s=round(statistics.median(r["latency_s"] for r in rows), 1), **{f"acc_{c}": round(v, 2) for c, v in per.items()}))
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    json.dump(summary, open(os.path.join(out_dir, "llm_eval_summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
