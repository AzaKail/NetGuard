from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional, Dict, Any

import os

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_NAMES = [
    "bps_in",
    "bps_out",
    "pps_in",
    "pps_out",
    "err_in",
    "err_out",
    "drop_in",
    "drop_out",
]

@dataclass
class ScoreResult:
    score: float
    is_anomaly: bool
    threshold: float
    model_ready: bool

class Detector:
    '''
    Минимальный online-like детектор:
    - собирает буфер последних N точек (аномальные точки не попадают в буфер,
      если poison_filter=True)
    - периодически переобучает StandardScaler + IsolationForest
    - порог = q-квантиль по train-scores (чем больше score — тем аномальнее)
    '''
    def __init__(
        self,
        buffer_size: int = 1500,
        min_train: int = 120,
        retrain_every: int = 60,
        contamination: float = 0.01,
        threshold_q: float = 0.99,
        random_state: int = 42,
        poison_filter: bool = os.getenv("NETGUARD_POISON_FILTER", "1") != "0",
        drift_guard: float = 0.10,
        guard_window: int = 300,
    ) -> None:
        self.buffer: Deque[np.ndarray] = deque(maxlen=buffer_size)
        self.min_train = min_train
        self.retrain_every = retrain_every
        self.contamination = contamination
        self.threshold_q = threshold_q
        self.random_state = random_state
        # True: points flagged as anomalous are not added to the training buffer,
        # so an ongoing attack cannot become part of the "normal" profile.
        self.poison_filter = poison_filter
        # Drift guard: if >= drift_guard of the last guard_window points raised
        # alarms, the change is more likely new normal traffic than an attack,
        # so points are admitted anyway. Without it the model can "freeze" and
        # raise 30-40% false alarms on busy hosts (UNSW-NB15 experiment).
        self.drift_guard = drift_guard
        self._recent: Deque[bool] = deque(maxlen=guard_window)

        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None
        self.threshold: float = float("inf")
        self._seen: int = 0

    @property
    def is_ready(self) -> bool:
        return self.model is not None and self.scaler is not None

    def bootstrap_baseline(self, center: np.ndarray, samples: int | None = None) -> None:
        samples = samples or self.min_train
        center = center.astype(np.float32)
        floor = np.array([5_000.0, 3_000.0, 8.0, 5.0, 0.05, 0.05, 0.05, 0.05], dtype=np.float32)
        spread = np.maximum(np.abs(center) * 0.12, floor)
        rng = np.random.default_rng(self.random_state)
        synthetic = rng.normal(center, spread, size=(samples, len(FEATURE_NAMES)))
        synthetic = np.clip(synthetic, 0.0, None).astype(np.float32)
        synthetic[0] = center
        self.bootstrap_samples(synthetic)

    def bootstrap_samples(self, samples: np.ndarray) -> None:
        data = np.asarray(samples, dtype=np.float32)
        if data.ndim != 2 or data.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected samples with shape (n, {len(FEATURE_NAMES)})")
        if len(data) < self.min_train:
            center = np.mean(data, axis=0)
            return self.bootstrap_baseline(center)

        self.buffer.clear()
        for row in data[-self.buffer.maxlen:]:
            self.buffer.append(row)
        self._seen = len(self.buffer)
        self._fit()

    def _fit(self) -> None:
        X = np.vstack(list(self.buffer))
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)

        model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        model.fit(Xs)

        # decision_function: больше => "нормальнее". Инвертируем: больше => "аномальнее".
        train_scores = -model.decision_function(Xs)
        thr = float(np.quantile(train_scores, self.threshold_q))

        self.scaler = scaler
        self.model = model
        self.threshold = thr

    def add_and_score(self, features: np.ndarray) -> ScoreResult:
        self._seen += 1
        x = features.astype(np.float32)

        if self.model is None or self.scaler is None:
            # warm-up: collect points until the first fit
            self.buffer.append(x)
            if len(self.buffer) < self.min_train:
                return ScoreResult(score=0.0, is_anomaly=False, threshold=float("inf"), model_ready=False)
            self._fit()

        # score with the current model first ...
        Xs = self.scaler.transform(x.reshape(1, -1))
        score = float(-self.model.decision_function(Xs)[0])
        is_anomaly = score > self.threshold

        # ... then decide whether the point may enter the training buffer
        drifting = (len(self._recent) == self._recent.maxlen
                    and sum(self._recent) >= self.drift_guard * self._recent.maxlen)
        if not (self.poison_filter and is_anomaly) or drifting:
            self.buffer.append(x)
        self._recent.append(bool(is_anomaly))
        if self._seen % self.retrain_every == 0 and len(self.buffer) >= self.min_train:
            self._fit()

        return ScoreResult(score=score, is_anomaly=is_anomaly, threshold=self.threshold, model_ready=True)

    def explain(self, features: np.ndarray, top_k: int = 2) -> list[str]:
        if self.scaler is None:
            return []
        scale = np.where(self.scaler.scale_ == 0, 1.0, self.scaler.scale_)
        z_scores = np.abs((features - self.scaler.mean_) / scale)
        order = np.argsort(z_scores)[::-1]
        picks = []
        for idx in order[:top_k]:
            name = FEATURE_NAMES[int(idx)]
            value = z_scores[int(idx)]
            picks.append(f"{name} (z={value:.2f})")
        return picks



def to_feature_vector(payload: Dict[str, Any]) -> np.ndarray:
    '''
    Признаки (таблично, без payload пакетов):
    - bps_in, bps_out
    - pps_in, pps_out
    - err_in/out, drop_in/out
    '''
    return np.array([float(payload.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float32)
