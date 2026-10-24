"""Unsupervised Isolation Forest Network Traffic Anomaly Detector.

Implements machine learning-based traffic flow anomaly detection using scikit-learn's
IsolationForest model as specified in the project architecture.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("firewall.ai.isolation_forest")

MODEL_PATH = Path(__file__).resolve().parent / "isolation_forest.joblib"


class IsolationForestAnomalyDetector:
    """Detects multi-variate anomalies in network traffic flows using Isolation Forest."""

    FEATURE_NAMES = [
        "packet_size",
        "src_port",
        "dst_port",
        "protocol_num",
        "flow_rate",
    ]

    def __init__(self, model_path: Optional[Path] = None, contamination: float = 0.05) -> None:
        self.model_path = model_path or MODEL_PATH
        self.contamination = contamination
        self._lock = threading.Lock()
        self.model: Optional[IsolationForest] = None
        self._load_or_train()

    def _generate_baseline_data(self, n_samples: int = 1500) -> np.ndarray:
        """Synthesize representative baseline benign enterprise traffic patterns.
        
        Features:
        0: packet_size (bytes): Normal distribution around 64-1500 B.
        1: src_port: Ephemeral ports 49152-65535 or client ports.
        2: dst_port: Standard services (80, 443, 53, 22, 123, 8080).
        3: protocol_num: 6 (TCP), 17 (UDP), 1 (ICMP).
        4: flow_rate: Normal inter-arrival rate (1-50 packets/sec).
        """
        rng = np.random.default_rng(42)
        
        # 1. Packet sizes (mix of small ACKs ~64B, DNS ~150B, and MTU data ~1420B)
        sizes = rng.choice([64, 128, 512, 1420, 1500], size=n_samples, p=[0.3, 0.2, 0.2, 0.2, 0.1])
        sizes = np.clip(sizes + rng.normal(0, 10, n_samples), 40, 1514)

        # 2. Ephemeral client source ports (32768 to 61000)
        src_ports = rng.integers(32768, 61000, size=n_samples)

        # 3. Destination ports: standard services
        service_ports = [80, 443, 53, 22, 123, 8080]
        service_probs = [0.25, 0.45, 0.15, 0.05, 0.05, 0.05]
        dst_ports = rng.choice(service_ports, size=n_samples, p=service_probs)

        # 4. Protocol numbers (6=TCP, 17=UDP, 1=ICMP)
        protocols = rng.choice([6, 17, 1], size=n_samples, p=[0.75, 0.22, 0.03])

        # 5. Normal flow rates (1 - 60 pps)
        flow_rates = rng.gamma(shape=2.0, scale=8.0, size=n_samples)
        flow_rates = np.clip(flow_rates, 0.5, 120.0)

        X = np.column_stack([sizes, src_ports, dst_ports, protocols, flow_rates])
        return X

    def _load_or_train(self) -> None:
        """Load trained model or train and persist a fresh Isolation Forest baseline."""
        with self._lock:
            if self.model_path.exists():
                try:
                    self.model = joblib.load(self.model_path)
                    logger.info("Loaded persisted Isolation Forest model from %s", self.model_path)
                    return
                except Exception as exc:
                    logger.warning("Failed loading cached model (%s); retraining fresh baseline", exc)

            X_baseline = self._generate_baseline_data(2000)
            self.model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )
            self.model.fit(X_baseline)
            try:
                joblib.dump(self.model, self.model_path)
                logger.info("Trained and persisted new Isolation Forest model to %s", self.model_path)
            except Exception as exc:
                logger.warning("Could not persist model artifact: %s", exc)

    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract the 5-feature vector from packet or connection metadata."""
        # 1. Packet size
        size = float(data.get("packet_size") or data.get("bytes") or data.get("length") or 64.0)
        
        # 2. Source port
        src_port = float(data.get("src_port") or data.get("source_port") or 49152.0)
        
        # 3. Destination port
        dst_port = float(data.get("dst_port") or data.get("destination_port") or 80.0)
        
        # 4. Protocol number
        proto = str(data.get("protocol", "TCP")).upper()
        if "TCP" in proto:
            proto_num = 6.0
        elif "UDP" in proto:
            proto_num = 17.0
        elif "ICMP" in proto:
            proto_num = 1.0
        else:
            proto_num = float(data.get("protocol_num", 6.0))

        # 5. Flow rate / packet rate
        flow_rate = float(data.get("flow_rate") or data.get("rate") or data.get("packets_sent", 1.0))

        return np.array([[size, src_port, dst_port, proto_num, flow_rate]], dtype=np.float64)

    def predict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate traffic data and return multi-variate anomaly score and explanation."""
        if self.model is None:
            self._load_or_train()

        features = self.extract_features(data)
        
        with self._lock:
            # decision_function returns negative values for anomalies, positive for inliers
            raw_score = float(self.model.decision_function(features)[0])
            pred = int(self.model.predict(features)[0])  # -1 = anomaly, 1 = normal

        # Map raw decision score [-0.5, 0.5] to a normalized anomaly score [0.0, 1.0]
        # In scikit-learn IsolationForest, lower decision_function value = higher anomaly.
        # Typically scores lie between -0.4 and +0.3.
        # Normalize: anomaly_score = 1.0 - (raw_score - min_val) / range
        clamped_score = np.clip(raw_score, -0.35, 0.35)
        anomaly_score = float(round(1.0 - (clamped_score - (-0.35)) / 0.70, 4))
        is_anomaly = (pred == -1) or (anomaly_score >= 0.65)

        # Generate diagnostic signals/explanation
        signals = []
        size = features[0][0]
        dst_port = int(features[0][2])
        flow_rate = features[0][4]

        if size > 4000:
            signals.append(f"Unusually large frame size ({int(size)} bytes)")
        elif size < 20:
            signals.append(f"Suspiciously undersized packet ({int(size)} bytes)")

        if dst_port not in (80, 443, 53, 22, 123, 8080, 8443, 3389, 445):
            if dst_port in (31337, 4444, 1337, 6667, 9999):
                signals.append(f"Known hacker/malware port ({dst_port})")
            elif dst_port > 1024:
                signals.append(f"Unconventional high destination port ({dst_port})")

        if flow_rate > 100.0:
            signals.append(f"Abnormally high burst rate ({flow_rate:.1f} pps)")

        if not signals and is_anomaly:
            signals.append("Multi-variate statistical divergence from enterprise baseline")

        classification = "Anomalous Traffic" if is_anomaly else "Normal Traffic"

        return {
            "model": "Isolation Forest (Unsupervised)",
            "classification": classification,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "raw_decision_score": round(raw_score, 4),
            "signals": signals,
            "features_evaluated": {
                "packet_size": size,
                "src_port": int(features[0][1]),
                "dst_port": dst_port,
                "protocol": data.get("protocol", "TCP"),
                "flow_rate": flow_rate,
            },
        }


# Singleton accessor
_detector_instance: Optional[IsolationForestAnomalyDetector] = None
_instance_lock = threading.Lock()


def get_traffic_anomaly_detector() -> IsolationForestAnomalyDetector:
    global _detector_instance
    with _instance_lock:
        if _detector_instance is None:
            _detector_instance = IsolationForestAnomalyDetector()
        return _detector_instance
