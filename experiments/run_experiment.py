"""NetGuard evaluation on UNSW-NB15 host traces (see build_traces.py).

Protocol (split="feb_half", main setting)
  train: first half of the 18 Feb normal trace of host h (+ optional contamination
         with 22 Jan attack segments); test: second half of the same trace with
         18 Feb attack segments injected so that `rate` of seconds are attack seconds.
  split="jan_feb": train on 22 Jan, test on 18 Feb (shows the effect of drift:
         quiet hosts carry almost no normal traffic on 22 Jan).
  label: a second is an attack second if injected attack traffic is non-zero.
  event: an injected segment is detected if >=1 alarm falls inside it.
Methods: Isolation Forest, LOF (novelty), One-Class SVM, max-|z| baseline.
Threshold: q-quantile (0.99) of training scores, as in NetGuard.
"""
import json, sys, time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

FEATS = ["bytes_in", "bytes_out", "pkts_in", "pkts_out", "new_flows", "uniq_remote"]
FSETS = {"F4": [0, 1, 2, 3], "F6": [0, 1, 2, 3, 4, 5]}
HOSTS = {"busy": [f"149.171.126.{i}" for i in range(10)],
         "quiet": [f"149.171.126.{i}" for i in range(10, 20)]}


def load(path):
    z = np.load(path)
    normal = {k: z[k] for k in z.files if k.startswith("normal")}
    segs = {"jan": [], "feb": []}
    for k in z.files:
        if k.startswith("attack"):
            _, day, _, cat, host = k.split("|")
            segs[day].append((cat, z[k]))
    return normal, segs


def inject(base, segs, rate, rng):
    """Add randomly chosen attack segments at random non-overlapping places
    until `rate` of seconds are attack seconds."""
    x = base.copy()
    y = np.zeros(len(x), dtype=bool)
    busy = np.zeros(len(x), dtype=bool)
    events = []
    target = rate * len(x)
    tries = 0
    while y.sum() < target and tries < 100_000:
        tries += 1
        cat, s = segs[rng.integers(len(segs))]
        L = len(s)
        p = int(rng.integers(0, len(x) - L))
        if busy[max(0, p - 10):p + L + 10].any():
            continue
        busy[p:p + L] = True
        x[p:p + L] += s
        act = (s[:, 2] + s[:, 3]) > 0
        y[p:p + L] |= act
        events.append((cat, p, p + L, act))
    return x, y, events


def prep(x, fs, log=True):
    x = x[:, FSETS[fs]]
    return np.log1p(x) if log else x


class ZScore:
    def fit(self, X):
        self.m, self.s = X.mean(0), X.std(0) + 1e-9
        return self

    def score(self, X):
        return np.abs((X - self.m) / self.s).max(1)


def make(name, seed):
    if name == "IF":
        return IsolationForest(n_estimators=200, random_state=seed, n_jobs=1)
    if name == "LOF":
        return LocalOutlierFactor(n_neighbors=20, novelty=True)
    if name == "OCSVM":
        return OneClassSVM(kernel="rbf", nu=0.01, gamma="scale")
    if name == "Z":
        return ZScore()


def fit_score(name, Xtr, Xte, seed, max_train=None):
    rng = np.random.default_rng(seed)
    sc = StandardScaler().fit(Xtr)
    A, B = sc.transform(Xtr), sc.transform(Xte)
    if max_train and len(A) > max_train:
        A = A[rng.choice(len(A), max_train, replace=False)]
    m = make(name, seed)
    t = time.perf_counter(); m.fit(A); fit_s = time.perf_counter() - t
    sfun = m.score if name == "Z" else (lambda X: -m.decision_function(X))
    tr = sfun(A)
    t = time.perf_counter(); te = sfun(B); batch_us = (time.perf_counter() - t) / len(B) * 1e6
    # single-vector latency, as in the online agent
    one = B[:1]
    t = time.perf_counter()
    for _ in range(50):
        sfun(one)
    single_ms = (time.perf_counter() - t) / 50 * 1e3
    return tr, te, dict(fit_s=fit_s, batch_us=batch_us, single_ms=single_ms)


def metrics(tr, te, y, events, q=0.99):
    thr = np.quantile(tr, q)
    alarm = te > thr
    tp = (alarm & y).sum(); fp = (alarm & ~y).sum(); fn = (~alarm & y).sum()
    fpr_c, tpr_c, _ = roc_curve(y, te)
    tpr_at1 = float(np.interp(0.01, fpr_c, tpr_c))
    ev = {}
    for cat, a, b, act in events:
        hit = alarm[a:b].any()
        first = np.flatnonzero(alarm[a:b])
        delay = int(first[0]) if hit else None
        ev.setdefault(cat, []).append((bool(hit), delay))
    return dict(
        roc_auc=roc_auc_score(y, te), pr_auc=average_precision_score(y, te),
        tpr=tp / max(tp + fn, 1), fpr=fp / max((~y).sum(), 1),
        prec=tp / max(tp + fp, 1), f1=2 * tp / max(2 * tp + fp + fn, 1),
        tpr_at_fpr1=tpr_at1,
        event=ev,
    )


def main(traces, out, regime="busy", split="feb_half", seeds=(0, 1, 2), rate=0.03, contam=0.0, log=True, methods=("IF", "LOF", "OCSVM", "Z"), fsets=("F4", "F6")):
    normal, segs = load(traces)
    rows = []
    for seed in seeds:
        for hi, h in enumerate(HOSTS[regime]):
            rng = np.random.default_rng(seed * 100 + hi)
            if split == "jan_feb":   # train on 22 Jan, test on 18 Feb
                tr_x, te_base = normal[f"normal|{h}|jan"], normal[f"normal|{h}|feb"]
            else:                    # train on first half of 18 Feb, test on second half
                f = normal[f"normal|{h}|feb"]; half = len(f) // 2
                tr_x, te_base = f[:half], f[half:]
            if contam > 0:
                tr_x, _, _ = inject(tr_x, segs["jan"], contam, rng)
            te_x, y, events = inject(te_base, segs["feb"], rate, rng)
            for fs in fsets:
                Xtr, Xte = prep(tr_x, fs, log), prep(te_x, fs, log)
                for m in methods:
                    mt = 10_000 if m in ("OCSVM", "LOF") else None
                    tr, te, tm = fit_score(m, Xtr, Xte, seed, mt)
                    r = metrics(tr, te, y, events)
                    r.update(tm, seed=seed, host=h, fs=fs, method=m, regime=regime, split=split, contam=contam)
                    rows.append(r)
                    print(seed, h, fs, m, f"auc={r['roc_auc']:.3f} pr={r['pr_auc']:.3f} tpr={r['tpr']:.3f} fpr={r['fpr']:.4f}", flush=True)
    with open(out, "w") as f:
        json.dump(dict(config=dict(regime=regime, split=split, seeds=list(seeds), rate=rate, contam=contam, log=log), rows=rows), f)


if __name__ == "__main__":
    a = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    main(sys.argv[1], sys.argv[2], **a)
