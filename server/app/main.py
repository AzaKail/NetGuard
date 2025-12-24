from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from .db import SessionLocal, engine
from .models import Base, Metric, Alert
from .detector import Detector, to_feature_vector

Base.metadata.create_all(bind=engine)

app = FastAPI(title="NetGuard.AI MVP", version="0.1.0")
templates = Jinja2Templates(directory="app/templates")

detector = Detector()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class MetricIn(BaseModel):
    host: str = Field(..., max_length=128)
    iface: str = Field(default="unknown", max_length=128)
    ts: Optional[datetime] = None
    interval_s: float = 5.0

    bps_in: float = 0.0
    bps_out: float = 0.0
    pps_in: float = 0.0
    pps_out: float = 0.0
    err_in: float = 0.0
    err_out: float = 0.0
    drop_in: float = 0.0
    drop_out: float = 0.0

@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    metrics = db.execute(select(Metric).order_by(desc(Metric.id)).limit(50)).scalars().all()
    alerts = db.execute(select(Alert).order_by(desc(Alert.id)).limit(20)).scalars().all()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "metrics": metrics,
        "alerts": alerts,
        "now": datetime.now(timezone.utc),
    })

@app.post("/ingest")
def ingest(item: MetricIn, db: Session = Depends(get_db)):
    ts = item.ts or datetime.now(timezone.utc)

    payload = item.model_dump()
    features = to_feature_vector(payload)
    score_res = detector.add_and_score(features)

    m = Metric(
        host=item.host,
        iface=item.iface,
        ts=ts,
        interval_s=item.interval_s,
        bps_in=item.bps_in,
        bps_out=item.bps_out,
        pps_in=item.pps_in,
        pps_out=item.pps_out,
        err_in=item.err_in,
        err_out=item.err_out,
        drop_in=item.drop_in,
        drop_out=item.drop_out,
        anomaly_score=score_res.score,
        is_anomaly=1 if score_res.is_anomaly else 0,
    )
    db.add(m)
    db.commit()
    db.refresh(m)

    explanation = []
    if score_res.model_ready:
        explanation = detector.explain(features)

    if score_res.model_ready and score_res.is_anomaly:
        reason = "аномалия: " + ", ".join(explanation) if explanation else "аномалия: высокий anomaly_score"
        a = Alert(
            host=item.host,
            iface=item.iface,
            ts=ts,
            score=score_res.score,
            threshold=score_res.threshold,
            reason=reason,
        )
        db.add(a)
        db.commit()

    return {
        "ok": True,
        "id": m.id,
        "model_ready": score_res.model_ready,
        "anomaly_score": score_res.score,
        "threshold": score_res.threshold,
        "is_anomaly": score_res.is_anomaly,
        "explanation": explanation,
    }

@app.get("/api/metrics")
def api_metrics(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = db.execute(select(Metric).order_by(desc(Metric.id)).limit(limit)).scalars().all()
    return [{
        "id": r.id,
        "host": r.host,
        "iface": r.iface,
        "ts": r.ts.isoformat(),
        "bps_in": r.bps_in,
        "bps_out": r.bps_out,
        "pps_in": r.pps_in,
        "pps_out": r.pps_out,
        "score": r.anomaly_score,
        "is_anomaly": bool(r.is_anomaly),
    } for r in rows]

@app.get("/api/alerts")
def api_alerts(limit: int = 20, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    rows = db.execute(select(Alert).order_by(desc(Alert.id)).limit(limit)).scalars().all()
    return [{
        "id": r.id,
        "host": r.host,
        "iface": r.iface,
        "ts": r.ts.isoformat(),
        "score": r.score,
        "threshold": r.threshold,
        "reason": r.reason,
    } for r in rows]
