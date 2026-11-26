"""Figures and tables for the paper from results/*.json(l)."""
import json, sys, os
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = sys.argv[1] if len(sys.argv) > 1 else "results"
OUT = sys.argv[2] if len(sys.argv) > 2 else "figures"
os.makedirs(OUT, exist_ok=True)
C = {"IF": "#257de0", "LOF": "#f47230", "OCSVM": "#00b894", "Z": "#f2a600"}
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.edgecolor": "#888", "axes.linewidth": 0.6,
                     "xtick.color": "#444", "ytick.color": "#444"})


def static_df():
    rows = []
    for f in ["res_busy_c0.json", "res_quiet_c0.json", "res_busy_c0.05.json", "res_quiet_c0.05.json"]:
        rows += json.load(open(os.path.join(R, f)))["rows"]
    return pd.DataFrame(rows)


def table_static(df):
    t = df.groupby(["contam", "regime", "fs", "method"]).agg(
        roc_auc=("roc_auc", "mean"), roc_sd=("roc_auc", "std"), pr_auc=("pr_auc", "mean"),
        tpr=("tpr", "mean"), fpr=("fpr", "mean"), f1=("f1", "mean"),
        tpr1=("tpr_at_fpr1", "mean"), lat_ms=("single_ms", "median"), fit_s=("fit_s", "median"))
    t.round(3).to_csv(os.path.join(OUT, "table_static.csv"))
    return t


def fig_auc(df):
    d = df[(df.contam == 0) & (df.fs == "F4")]
    methods = ["IF", "LOF", "OCSVM", "Z"]; regimes = [("quiet", "Quiet hosts"), ("busy", "Busy servers")]
    fig, ax = plt.subplots(figsize=(3.4, 2.1), dpi=300)
    w = 0.19
    for i, m in enumerate(methods):
        for j, (r, _) in enumerate(regimes):
            v = d[(d.method == m) & (d.regime == r)].roc_auc
            x = j + (i - 1.5) * (w + 0.01)
            ax.bar(x, v.mean(), w, color=C[m], label=m if j == 0 else None, zorder=2)
            ax.errorbar(x, v.mean(), v.std(), color="#333", lw=0.6, capsize=1.5, zorder=3)
            ax.text(x, v.mean() + v.std() + 0.015, f"{v.mean():.2f}", ha="center", va="bottom", fontsize=5.5, color="#222")
    ax.axhline(0.5, color="#999", lw=0.6, ls="--", zorder=1)
    ax.text(-0.45, 0.505, "chance", fontsize=5.5, color="#666", ha="left", va="bottom")
    ax.set_xticks([0, 1], [n for _, n in regimes]); ax.set_ylim(0.4, 1.08); ax.set_ylabel("ROC-AUC")
    ax.yaxis.grid(True, color="#e5e5e5", lw=0.5, zorder=0)
    ax.legend(ncol=4, fontsize=6, frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.13), handlelength=1)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_auc.png")); fig.savefig(os.path.join(OUT, "fig_auc.pdf"))


def stream_df():
    return pd.DataFrame([json.loads(l) for l in open(os.path.join(R, "stream_all.jsonl"))])


def table_stream(s):
    t = s.groupby(["regime", "rate", "variant"]).agg(
        tpr=("tpr", "mean"), fpr=("fpr", "mean"), f1=("f1", "mean"), pr_auc=("pr_auc", "mean"),
        event_det=("event_det", "mean"), delay=("delay_med", "median"), n=("host", "size"))
    t.round(3).to_csv(os.path.join(OUT, "table_stream.csv"))
    return t


def fig_stream(s):
    V = [("orig", "NetGuard v0.2", "#257de0"), ("log+filter", "+ poison filter", "#f47230"),
         ("log+filter+guard", "+ filter & drift guard", "#00b894")]
    V = [v for v in V if v[0] in set(s.variant)]
    fig, axes = plt.subplots(1, 2, figsize=(3.4, 2.0), dpi=300, sharey=True)
    for ax, (reg, title) in zip(axes, [("quiet", "Quiet hosts"), ("busy", "Busy servers")]):
        for k, (v, lab, col) in enumerate(V):
            d = s[(s.regime == reg) & (s.variant == v)].groupby("rate")[["tpr", "fpr"]].mean()
            ax.plot(d.fpr * 100, d.tpr * 100, "-", color=col, lw=1.2, zorder=2)
            for rate, row in d.iterrows():
                ax.plot(row.fpr * 100, row.tpr * 100, "o" if rate == 0.03 else "s", ms=4, color=col,
                        mec="white", mew=0.8, label=lab if rate == 0.03 else None, zorder=3)
        ax.set_title(title, fontsize=7); ax.set_xlabel("FPR, %"); ax.grid(color="#e5e5e5", lw=0.5, zorder=0)
        ax.set_xscale("symlog", linthresh=1); ax.set_xlim(0, 60)
        ax.set_xticks([0, 1, 10, 50], ["0", "1", "10", "50"])
    axes[0].set_ylabel("TPR (attack seconds), %"); axes[0].set_ylim(0, 100)
    fig.legend(*axes[0].get_legend_handles_labels(), ncol=3, fontsize=5.5, frameon=False,
               loc="upper center", bbox_to_anchor=(0.5, 1.0), handlelength=1)
    fig.text(0.99, 0.01, "circle: 3% attack seconds, square: 10%", fontsize=5, color="#666", ha="right")
    fig.tight_layout(rect=(0, 0.03, 1, 0.9))
    fig.savefig(os.path.join(OUT, "fig_stream.png")); fig.savefig(os.path.join(OUT, "fig_stream.pdf"))


if __name__ == "__main__":
    df = static_df()
    print(table_static(df).round(3).to_string())
    fig_auc(df)
    if os.path.exists(os.path.join(R, "stream_all.jsonl")):
        s = stream_df(); print(table_stream(s).round(3).to_string()); fig_stream(s)
