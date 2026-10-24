from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest


@dataclass(slots=True)
class AnomalyScore:
    timestamp: float
    score: float
    is_anomaly: bool
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0


class BehavioralBaseline:
    def __init__(self, window_size: int = 1000) -> None:
        self.window_size = window_size
        self.traffic_volumes = deque(maxlen=window_size)
        self.packet_rates = deque(maxlen=window_size)
        self.port_frequencies = {}
        self.protocol_frequencies = {}
        self._lock = threading.RLock()
        self.mean_volume = 0.0
        self.std_volume = 0.0
        self.mean_rate = 0.0
        self.std_rate = 0.0

    def update(self, traffic_volume: float, packet_rate: float, port: Optional[int], protocol: str) -> None:
        with self._lock:
            self.traffic_volumes.append(traffic_volume)
            self.packet_rates.append(packet_rate)

            if port:
                self.port_frequencies[port] = self.port_frequencies.get(port, 0) + 1
            if protocol:
                self.protocol_frequencies[protocol] = self.protocol_frequencies.get(protocol, 0) + 1

            if len(self.traffic_volumes) >= 10:
                self.mean_volume = float(np.mean(self.traffic_volumes))
                self.std_volume = float(np.std(self.traffic_volumes)) or 1.0
                self.mean_rate = float(np.mean(self.packet_rates))
                self.std_rate = float(np.std(self.packet_rates)) or 1.0

    def get_z_score(self, traffic_volume: float, packet_rate: float) -> tuple[float, float]:
        z_volume = (traffic_volume - self.mean_volume) / self.std_volume if self.std_volume > 0 else 0.0
        z_rate = (packet_rate - self.mean_rate) / self.std_rate if self.std_rate > 0 else 0.0
        return z_volume, z_rate

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "mean_volume": self.mean_volume,
                "std_volume": self.std_volume,
                "mean_rate": self.mean_rate,
                "std_rate": self.std_rate,
                "samples": len(self.traffic_volumes),
                "top_ports": sorted(self.port_frequencies.items(), key=lambda x: x[1], reverse=True)[:5],
                "protocols": dict(self.protocol_frequencies),
            }


class AnomalyDetector:
    def __init__(self, contamination: float = 0.05) -> None:
        self.contamination = contamination
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        self.baselines: Dict[str, BehavioralBaseline] = {}
        self._lock = threading.RLock()
        self._feature_history = deque(maxlen=5000)
        self.is_trained = False

    def add_sample(
        self,
        traffic_volume: float,
        packet_rate: float,
        port_count: int,
        protocol_entropy: float,
        port_variance: float,
    ) -> None:
        features = [traffic_volume, packet_rate, port_count, protocol_entropy, port_variance]
        with self._lock:
            self._feature_history.append(features)

    def train(self) -> bool:
        with self._lock:
            if len(self._feature_history) < 50:
                return False
            X = np.array(list(self._feature_history), dtype=np.float32)
            try:
                self.isolation_forest.fit(X)
                self.is_trained = True
                return True
            except Exception:
                return False

    def detect(
        self,
        src_ip: str,
        traffic_volume: float,
        packet_rate: float,
        port_count: int,
        protocol_entropy: float,
        port_variance: float,
    ) -> AnomalyScore:
        timestamp = time.time()
        indicators = []
        confidence = 0.0

        if src_ip not in self.baselines:
            self.baselines[src_ip] = BehavioralBaseline()

        baseline = self.baselines[src_ip]
        baseline.update(traffic_volume, packet_rate, None, "")

        z_volume, z_rate = baseline.get_z_score(traffic_volume, packet_rate)
        if abs(z_volume) > 3.0:
            indicators.append(f"Unusual traffic volume (z={z_volume:.2f})")
            confidence += 0.2

        if abs(z_rate) > 3.0:
            indicators.append(f"Unusual packet rate (z={z_rate:.2f})")
            confidence += 0.2

        if port_count > 50:
            indicators.append(f"High port diversity ({port_count} ports)")
            confidence += 0.15

        if protocol_entropy > 2.0:
            indicators.append(f"High protocol entropy ({protocol_entropy:.2f})")
            confidence += 0.15

        is_anomaly = False
        anomaly_score = 0.0

        if self.is_trained:
            with self._lock:
                X = np.array([[traffic_volume, packet_rate, port_count, protocol_entropy, port_variance]], dtype=np.float32)
                prediction = self.isolation_forest.predict(X)[0]
                anomaly_score = float(self.isolation_forest.score_samples(X)[0])
                is_anomaly = prediction == -1

                if is_anomaly:
                    indicators.append(f"Isolation Forest anomaly detected (score={anomaly_score:.2f})")
                    confidence += 0.3

        confidence = min(1.0, confidence)

        return AnomalyScore(
            timestamp=timestamp,
            score=anomaly_score,
            is_anomaly=is_anomaly or confidence > 0.5,
            indicators=indicators,
            confidence=confidence,
        )
