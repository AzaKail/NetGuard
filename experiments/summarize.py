import json, sys, numpy as np, pandas as pd, collections
rows=[]
for p in sys.argv[1:]:
    rows+=json.load(open(p))['rows']
df=pd.DataFrame(rows)
g=df.groupby(['regime','fs','method'])
agg=g[['roc_auc','pr_auc','tpr','fpr','f1','tpr_at_fpr1','single_ms','fit_s']].mean()
print(agg.round(3).to_string())
# event-level per category
ev=collections.defaultdict(lambda:[0,0,[]])
for r in rows:
    for cat,lst in r['event'].items():
        k=(r['regime'],r['fs'],r['method'],cat)
        for hit,d in lst:
            ev[k][0]+=hit; ev[k][1]+=1
            if hit: ev[k][2].append(d)
E=pd.DataFrame([dict(regime=k[0],fs=k[1],method=k[2],cat=k[3],det=v[0]/v[1],n=v[1],delay=np.median(v[2]) if v[2] else np.nan) for k,v in ev.items()])
print(E[(E.fs=='F6')].pivot_table(index=['regime','cat'],columns='method',values='det').round(2).to_string())
