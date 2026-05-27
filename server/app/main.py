from __future__ import annotations

from datetime import datetime, timezone
import csv
import io
import math
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import AliasChoices, BaseModel, Field

from sqlalchemy import select, desc, func, distinct
from sqlalchemy.orm import Session

from .db import SessionLocal, engine
from .models import Base, Metric, Alert
from .detector import Detector, to_feature_vector

Base.metadata.create_all(bind=engine)

app = FastAPI(title="NetGuard.AI MVP", version="0.2.0")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))

detector = Detector()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class MetricIn(BaseModel):
    host: str = Field(..., max_length=128, validation_alias=AliasChoices("host", "hostname"))
    iface: str = Field(default="unknown", max_length=128)
    ts: Optional[datetime] = None
    interval_s: float = 5.0
    manual_anomaly: bool = False

    bps_in: float = 0.0
    bps_out: float = 0.0
    pps_in: float = 0.0
    pps_out: float = 0.0
    err_in: float = 0.0
    err_out: float = 0.0
    drop_in: float = 0.0
    drop_out: float = 0.0


def _host_rows(db: Session):
    last_seen = func.max(Metric.ts).label("last_seen")
    metric_count = func.count(Metric.id).label("metric_count")
    return db.execute(
        select(Metric.host, last_seen, metric_count)
        .group_by(Metric.host)
        .order_by(desc(last_seen))
    ).all()


def _status_payload(db: Session) -> dict:
    last_metric_ts = db.scalar(select(func.max(Metric.ts)))
    return {
        "total_metrics": db.scalar(select(func.count(Metric.id))) or 0,
        "total_alerts": db.scalar(select(func.count(Alert.id))) or 0,
        "active_hosts": db.scalar(select(func.count(distinct(Metric.host)))) or 0,
        "last_metric_ts": last_metric_ts.isoformat() if last_metric_ts else None,
        "model_status": "Ready" if detector.is_ready else "Training",
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    metrics = db.execute(select(Metric).order_by(desc(Metric.id)).limit(50)).scalars().all()
    alerts = db.execute(select(Alert).order_by(desc(Alert.id)).limit(20)).scalars().all()
    chart_rows = list(reversed(metrics[:30]))
    status = _status_payload(db)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "metrics": metrics,
            "alerts": alerts,
            "hosts": _host_rows(db),
            "status": status,
            "chart_labels": [m.ts.strftime("%H:%M:%S") for m in chart_rows],
            "chart_bps_in": [round(m.bps_in, 2) for m in chart_rows],
            "chart_bps_out": [round(m.bps_out, 2) for m in chart_rows],
            "now": datetime.now(timezone.utc),
        },
    )


@app.post("/ingest")
def ingest(item: MetricIn, db: Session = Depends(get_db)):
    ts = item.ts or datetime.now(timezone.utc)

    payload = item.model_dump()
    features = to_feature_vector(payload)
    score_res = detector.add_and_score(features)

    is_anomaly_value = 1 if score_res.is_anomaly else 0
    if item.manual_anomaly:
        is_anomaly_value = 2

    metric = Metric(
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
        is_anomaly=is_anomaly_value,
    )
    db.add(metric)
    db.commit()
    db.refresh(metric)

    explanation = detector.explain(features) if score_res.model_ready else []
    threshold_value = score_res.threshold if math.isfinite(score_res.threshold) else 0.0

    if item.manual_anomaly:
        reason = "аномалия: включена ручная симуляция"
    elif explanation:
        reason = "аномалия: " + ", ".join(explanation)
    else:
        reason = "аномалия: высокий anomaly_score"

    if (score_res.model_ready and score_res.is_anomaly) or item.manual_anomaly:
        alert = Alert(
            host=item.host,
            iface=item.iface,
            ts=ts,
            score=score_res.score,
            threshold=threshold_value,
            reason=reason,
        )
        db.add(alert)
        db.commit()

    return {
        "ok": True,
        "id": metric.id,
        "model_ready": score_res.model_ready,
        "anomaly_score": score_res.score,
        "threshold": threshold_value if math.isfinite(score_res.threshold) else None,
        "is_anomaly": is_anomaly_value != 0,
        "anomaly_source": "manual" if is_anomaly_value == 2 else "model",
        "explanation": explanation,
        "recommendation": build_recommendation(item, explanation),
    }


def build_recommendation(item: MetricIn, explanation: list[str]) -> str:
    reasons = " ".join(explanation)
    if item.err_in > 0 or item.drop_in > 0 or "err_in" in reasons or "drop_in" in reasons:
        return "Проверить кабель, драйвер сетевой карты, порт коммутатора и наличие перегрузки интерфейса."
    if item.bps_out > item.bps_in * 5 or "bps_out" in reasons:
        return "Проверить процессы с активной отправкой данных и неизвестные сетевые подключения."
    if item.bps_in > item.bps_out * 5 or "bps_in" in reasons:
        return "Проверить входящий поток, источник трафика и правила firewall для данного хоста."
    return "Сравнить текущие значения с обычным профилем хоста и наблюдать следующие измерения."


@app.get("/api/metrics")
def api_metrics(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = db.execute(select(Metric).order_by(desc(Metric.id)).limit(limit)).scalars().all()
    return [
        {
            "id": r.id,
            "host": r.host,
            "iface": r.iface,
            "ts": r.ts.isoformat(),
            "bps_in": r.bps_in,
            "bps_out": r.bps_out,
            "pps_in": r.pps_in,
            "pps_out": r.pps_out,
            "err_in": r.err_in,
            "err_out": r.err_out,
            "drop_in": r.drop_in,
            "drop_out": r.drop_out,
            "score": r.anomaly_score,
            "is_anomaly": bool(r.is_anomaly),
            "anomaly_source": "manual" if r.is_anomaly == 2 else "model",
        }
        for r in rows
    ]


@app.get("/api/alerts")
def api_alerts(limit: int = 20, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    rows = db.execute(select(Alert).order_by(desc(Alert.id)).limit(limit)).scalars().all()
    return [
        {
            "id": r.id,
            "host": r.host,
            "iface": r.iface,
            "ts": r.ts.isoformat(),
            "score": r.score,
            "threshold": r.threshold,
            "reason": r.reason,
            "recommendation": build_recommendation(
                MetricIn(host=r.host, iface=r.iface, ts=r.ts, manual_anomaly=True),
                [r.reason],
            ),
        }
        for r in rows
    ]


@app.get("/api/hosts")
def api_hosts(db: Session = Depends(get_db)):
    return [
        {
            "host": host,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "metric_count": metric_count,
        }
        for host, last_seen, metric_count in _host_rows(db)
    ]


@app.get("/api/status")
def api_status(db: Session = Depends(get_db)):
    return _status_payload(db)


@app.post("/api/simulate/{kind}")
def api_simulate(kind: str, db: Session = Depends(get_db)):
    payload = {
        "host": "demo-admin",
        "iface": "simulation",
        "ts": datetime.now(timezone.utc),
        "interval_s": 1.0,
        "manual_anomaly": True,
        "bps_in": 1200.0,
        "bps_out": 900.0,
        "pps_in": 15.0,
        "pps_out": 12.0,
        "err_in": 0.0,
        "err_out": 0.0,
        "drop_in": 0.0,
        "drop_out": 0.0,
    }
    if kind == "inbound":
        payload["bps_in"] = 80_000_000.0
        payload["pps_in"] = 95_000.0
    elif kind == "outbound":
        payload["bps_out"] = 70_000_000.0
        payload["pps_out"] = 85_000.0
    elif kind == "errors":
        payload["err_in"] = 600.0
        payload["drop_in"] = 450.0
    else:
        raise HTTPException(status_code=404, detail="Unknown simulation kind")

    return ingest(MetricIn(**payload), db)


def _csv_response(filename: str, headers: list[str], rows: list[list[object]]) -> StreamingResponse:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows(rows)
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/metrics.csv")
def export_metrics(db: Session = Depends(get_db)):
    rows = db.execute(select(Metric).order_by(desc(Metric.id))).scalars().all()
    return _csv_response(
        "metrics.csv",
        [
            "id",
            "timestamp",
            "hostname",
            "iface",
            "bps_in",
            "bps_out",
            "pps_in",
            "pps_out",
            "err_in",
            "err_out",
            "drop_in",
            "drop_out",
            "anomaly_score",
            "is_anomaly",
        ],
        [
            [
                r.id,
                r.ts.isoformat(),
                r.host,
                r.iface,
                r.bps_in,
                r.bps_out,
                r.pps_in,
                r.pps_out,
                r.err_in,
                r.err_out,
                r.drop_in,
                r.drop_out,
                r.anomaly_score,
                r.is_anomaly,
            ]
            for r in rows
        ],
    )


@app.get("/api/export/alerts.csv")
def export_alerts(db: Session = Depends(get_db)):
    rows = db.execute(select(Alert).order_by(desc(Alert.id))).scalars().all()
    return _csv_response(
        "alerts.csv",
        ["id", "timestamp", "hostname", "iface", "score", "threshold", "reason"],
        [[r.id, r.ts.isoformat(), r.host, r.iface, r.score, r.threshold, r.reason] for r in rows],
    )
