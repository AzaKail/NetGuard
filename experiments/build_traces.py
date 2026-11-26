"""Build host-level per-second traffic traces from UNSW-NB15 flow records.

Why: NetGuard observes aggregate NIC counters of one host (bytes/packets per
second), while UNSW-NB15 is a flow dataset. We convert flows into the per-second
counters a host agent would see.

Problem with the raw data: in UNSW-NB15 the victim hosts 149.171.126.10-19 receive
almost only attack traffic (about 93% of their active seconds contain an attack),
while hosts 149.171.126.0-9 receive only normal traffic. Anomaly detection assumes
attacks are rare, so we use trace-driven injection:
  * normal traces  = per-second counters of hosts .0-.9 (normal flows only);
  * attack segments = per-second counters produced by attack flows on victims .10-.19;
  * test/train traces = normal trace + attack segments added at a controlled rate
    (counters are additive, as on a real NIC).
Attack segments from 22 Jan 2015 are used only for training, those from
18 Feb 2015 only for testing, so no attack instance appears in both.

Two background regimes, both from real UNSW-NB15 normal flows:
  busy  = hosts .0-.9 (about 100 packets/s), quiet = normal flows of hosts .10-.19.

Output: traces.npz with normal traces per (host, day) and attack segments per day.
"""
import sys
import numpy as np
import pandas as pd

FEATS = ["bytes_in", "bytes_out", "pkts_in", "pkts_out", "new_flows", "uniq_remote"]
DAY_SPLIT = 1_423_000_000  # epoch between 23 Jan and 18 Feb 2015


def host_series(fl: pd.DataFrame, host: str, t0: int, t1: int) -> np.ndarray:
    """Per-second counters for `host` over [t0, t1). Flow volume is spread
    uniformly over its duration [stime, ltime]."""
    n = t1 - t0
    out = np.zeros((n, len(FEATS)), dtype=np.float64)
    is_dst = (fl.dstip == host).values
    b_in = np.where(is_dst, fl.sbytes, fl.dbytes).astype(float)
    b_out = np.where(is_dst, fl.dbytes, fl.sbytes).astype(float)
    p_in = np.where(is_dst, fl.spkts, fl.dpkts).astype(float)
    p_out = np.where(is_dst, fl.dpkts, fl.spkts).astype(float)
    s = np.clip(fl.stime.values - t0, 0, n - 1)
    e = np.clip(fl.ltime.values - t0, 0, n - 1)
    dur = (e - s + 1).astype(float)
    # difference arrays for uniform spreading
    for k, v in enumerate([b_in, b_out, p_in, p_out]):
        d = np.zeros(n + 1)
        np.add.at(d, s, v / dur)
        np.add.at(d, e + 1, -v / dur)
        out[:, k] = np.cumsum(d)[:n]
    np.add.at(out[:, 4], s, 1.0)
    remote = np.where(is_dst, fl.srcip, fl.dstip)
    u = pd.DataFrame({"s": s, "r": remote}).drop_duplicates()
    np.add.at(out[:, 5], u.s.values, 1.0)
    out[out < 1e-3] = 0.0  # remove float residue of the cumulative sums
    return out


def attack_segments(df: pd.DataFrame, gap: int = 5, min_len: int = 3, max_len: int = 120):
    """Cut attack activity on each victim into segments of active seconds."""
    segs = []
    att = df[df.label == 1]
    victims = sorted(set(att.dstip[att.dstip.str.startswith("149.171.126.")]))
    for h in victims:
        fl = att[(att.dstip == h) | (att.srcip == h)]
        if fl.empty:
            continue
        t0, t1 = int(fl.stime.min()), int(fl.ltime.max()) + 1
        ser = host_series(fl, h, t0, t1)
        # category of the dominant flow type per second
        cat_sec = fl.groupby(np.clip(fl.stime.values - t0, 0, t1 - t0 - 1)).attack_cat.agg(
            lambda x: x.value_counts().index[0])
        active = np.flatnonzero(ser[:, 2] + ser[:, 3] > 0)
        if active.size == 0:
            continue
        breaks = np.flatnonzero(np.diff(active) > gap)
        starts = np.r_[active[0], active[breaks + 1]]
        ends = np.r_[active[breaks], active[-1]] + 1
        for a, b in zip(starts, ends):
            for c in range(a, b, max_len):
                d = min(c + max_len, b)
                if d - c < min_len:
                    continue
                cats = cat_sec[(cat_sec.index >= c) & (cat_sec.index < d)]
                cat = cats.value_counts().index[0] if len(cats) else "Unknown"
                segs.append(dict(host=h, t=t0 + c, cat=cat, x=ser[c:d].astype(np.float32)))
    return segs


def main(parquet: str, out: str):
    df = pd.read_parquet(parquet)
    df["day"] = np.where(df.stime < DAY_SPLIT, "jan", "feb")
    # busy hosts .0-.9 carry only normal traffic; quiet hosts .10-.19 are the
    # victims, and their *normal* flows form a low-traffic background
    normal_hosts = [f"149.171.126.{i}" for i in range(20)]
    traces = {}
    for day, g in df.groupby("day"):
        t0, t1 = int(g.stime.min()), int(g.ltime.max()) + 1
        n = g[g.label == 0]
        for h in normal_hosts:
            fl = n[(n.dstip == h) | (n.srcip == h)]
            traces[f"normal|{h}|{day}"] = host_series(fl, h, t0, t1).astype(np.float32)
        segs = attack_segments(g)
        for i, s in enumerate(segs):
            traces[f"attack|{day}|{i}|{s['cat']}|{s['host']}"] = s["x"]
        print(day, "normal seconds", t1 - t0, "attack segments", len(segs),
              pd.Series([s["cat"] for s in segs]).value_counts().to_dict(), flush=True)
    np.savez_compressed(out, **traces)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
