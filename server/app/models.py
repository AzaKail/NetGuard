from __future__ import annotations
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Float, Integer, DateTime
from datetime import datetime

class Base(DeclarativeBase):
    pass

class Metric(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(128), index=True)
    iface: Mapped[str] = mapped_column(String(128), default="unknown")
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)

    interval_s: Mapped[float] = mapped_column(Float, default=5.0)

    bps_in: Mapped[float] = mapped_column(Float, default=0.0)
    bps_out: Mapped[float] = mapped_column(Float, default=0.0)
    pps_in: Mapped[float] = mapped_column(Float, default=0.0)
    pps_out: Mapped[float] = mapped_column(Float, default=0.0)

    err_in: Mapped[float] = mapped_column(Float, default=0.0)
    err_out: Mapped[float] = mapped_column(Float, default=0.0)
    drop_in: Mapped[float] = mapped_column(Float, default=0.0)
    drop_out: Mapped[float] = mapped_column(Float, default=0.0)

    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_anomaly: Mapped[int] = mapped_column(Integer, default=0)

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(128), index=True)
    iface: Mapped[str] = mapped_column(String(128), default="unknown")
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)

    score: Mapped[float] = mapped_column(Float, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    reason: Mapped[str] = mapped_column(String(256), default="")
