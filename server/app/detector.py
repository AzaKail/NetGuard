from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional, Dict, Any

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
    - собирает буфер последних N точек
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
    ) -> None:
        self.buffer: Deque[np.ndarray] = deque(maxlen=buffer_size)
        self.min_train = min_train
        self.retrain_every = retrain_every
        self.contamination = contamination
        self.threshold_q = threshold_q
        self.random_state = random_state

        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None
        self.threshold: float = float("inf")
        self._seen: int = 0

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
        self.buffer.append(features.astype(np.float32))

        model_ready = self.model is not None and self.scaler is not None

        # переобучение, когда накопили минимум и пришло время
        if len(self.buffer) >= self.min_train and (self.model is None or self._seen % self.retrain_every == 0):
            self._fit()
            model_ready = True

        if not model_ready:
            # Пока модель не готова: score=0, аномалии не ставим
            return ScoreResult(score=0.0, is_anomaly=False, threshold=float("inf"), model_ready=False)

        Xs = self.scaler.transform(features.reshape(1, -1))
        score = float(-self.model.decision_function(Xs)[0])
        is_anomaly = score > self.threshold
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
