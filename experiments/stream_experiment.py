"""Online NetGuard detector replayed on injected UNSW-NB15 host traces.

Reproduces server/app/detector.py: ring buffer N=1500, first fit after
min_train=120 points, refit every retrain_every=60 points, IsolationForest
(200 trees), threshold = 0.99-quantile of training scores.

Variants
  orig      : as in detector.py, raw features, every point is appended to the
              buffer before it is scored (attacks can poison the model)
  log       : log1p features, otherwise as orig
  log+filter: log1p features, points flagged as anomalous are NOT appended
              (the behaviour described in the paper)
  log+filter+guard: as log+filter, but if >=10% of the last 300 points raised
              alarms, points are appended anyway (prevents the model from
              freezing when normal traffic drifts)
Because the model only changes at refits, points between two refits are scored
in one batch; this gives the same result as scoring them one by one.
"""
import json, sys, time
from collections import deque
from multiprocessing import Pool
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from run_experiment import load, inject, HOSTS  # noqa: E402

F4 = [0, 1, 2, 3]


def run_stream(x, log, filt, N=1500, min_train=120, every=60, q=0.99, seed=42, guard=None, guard_win=300):
    X = x[:, F4].astype(np.float64)
    if log:
        X = np.log1p(X)
    n = len(X)
    score = np.zeros(n); alarm = np.zeros(n, bool)
    buf = deque(maxlen=N)
    st = dict(model=None, scaler=None, thr=np.inf, fits=0)
    pending = []
    recent = deque(maxlen=guard_win)  # recent alarm flags for the drift guard

    def refit():
        st["model"], st["scaler"], st["thr"] = fit(buf, q, seed); st["fits"] += 1

    def flush():
        # score all pending points with the current (unchanged) model
        if pending:
            idx = np.array(pending)
            s = -st["model"].decision_function(st["scaler"].transform(X[idx]))
            score[idx] = s; alarm[idx] = s > st["thr"]
            if filt:
                for k in idx:
                    # guard: if alarms are frequent, the "anomaly" is more likely drift
                    # of normal traffic, so the point is admitted to the buffer anyway
                    drift = guard is not None and len(recent) == recent.maxlen and np.mean(recent) >= guard
                    if not alarm[k] or drift:
                        buf.append(X[k])
                    recent.append(alarm[k])
            pending.clear()

    for k in range(n):
        seen = k + 1
        if st["model"] is None:
            buf.append(X[k])
            if len(buf) >= min_train:
                refit()
                if not filt:
                    pending.append(k)
            continue
        if filt:
            # score with the current model, keep only normal points, then refit if due
            pending.append(k)
            if seen % every == 0:
                flush(); refit()
        else:
            # detector.py: append first, refit if due, then score with the newest model
            if seen % every == 0:
                flush(); buf.append(X[k]); refit(); pending.append(k)
            else:
                buf.append(X[k]); pending.append(k)
    flush()
    return score, alarm, st["fits"]


def fit(buf, q, seed):
    A = np.vstack(buf)
    sc = StandardScaler().fit(A)
    m = IsolationForest(n_estimators=200, contamination=0.01, random_state=seed, n_jobs=1).fit(sc.transform(A))
    thr = float(np.quantile(-m.decision_function(sc.transform(A)), q))
    return m, sc, thr


def job(args):
    traces, regime, h, hi, seed, rate, variant = args
    normal, segs = load(traces)
    rng = np.random.default_rng(seed * 100 + hi)
    x, y, events = inject(normal[f"normal|{h}|feb"], segs["feb"], rate, rng)
    log = variant != "orig"; filt = variant.startswith("log+filter")
    guard = 0.1 if variant == "log+filter+guard" else None
    t = time.perf_counter()
    s, a, fits = run_stream(x, log, filt, guard=guard)
    el = time.perf_counter() - t
    w = np.arange(len(x)) >= 120  # ignore warm-up
    yy, aa, ss = y[w], a[w], s[w]
    tp = (aa & yy).sum(); fp = (aa & ~yy).sum(); fn = (~aa & yy).sum()
    det = []; delay = []
    for cat, p, q, act in events:
        if p < 120:
            continue
        hit = a[p:q].any(); det.append(hit)
        if hit:
            delay.append(int(np.flatnonzero(a[p:q])[0]))
    return dict(regime=regime, host=h, seed=seed, rate=rate, variant=variant,
                tpr=tp / max(tp + fn, 1), fpr=fp / max((~yy).sum(), 1), f1=2 * tp / max(2 * tp + fp + fn, 1),
                pr_auc=average_precision_score(yy, ss), roc_auc=roc_auc_score(yy, ss),
                event_det=float(np.mean(det)), delay_med=float(np.median(delay)) if delay else None,
                fits=fits, sec=el)


if __name__ == "__main__":
    traces, out = sys.argv[1], sys.argv[2]
    cfg = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    regimes = cfg.get("regimes", ["quiet", "busy"]); rates = cfg.get("rates", [0.03, 0.10])
    seeds = cfg.get("seeds", [0]); variants = cfg.get("variants", ["orig", "log", "log+filter"])
    jobs = [(traces, r, h, hi, s, rate, v) for r in regimes for hi, h in enumerate(HOSTS[r])
            for s in seeds for rate in rates for v in variants]
    done = set()
    for f in cfg.get("skip_logs", []):  # resume: skip jobs already in earlier logs
        for line in open(f):
            if line.startswith("{"):
                r = json.loads(line); done.add((r["regime"], r["host"], r["seed"], r["rate"], r["variant"]))
    jobs = [j for j in jobs if (j[1], j[2], j[4], j[5], j[6]) not in done]
    print("jobs to run:", len(jobs), flush=True)
    with Pool(cfg.get("procs", 4)) as p:
        res = []
        for r in p.imap_unordered(job, jobs):
            res.append(r); print(json.dumps(r), flush=True)
    json.dump(res, open(out, "w"))
