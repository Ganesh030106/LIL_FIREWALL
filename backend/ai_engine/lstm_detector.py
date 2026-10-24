"""PyTorch-based LSTM Flow Sequence Anomaly Detector.

Implements deep recurrent neural network (LSTM) for sequential network traffic
anomaly detection, evaluating multi-packet temporal patterns, inter-arrival time
fluctuations, and burst behaviors as specified in the project report (Section 5.1).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn

logger = logging.getLogger("firewall.ai.lstm")

MODEL_PATH = Path(__file__).resolve().parent / "traffic_lstm.pt"
SEQ_LENGTH = 8
INPUT_DIM = 4  # [inter_arrival_time, packet_size, direction (0=in, 1=out), protocol_num]


class TrafficLSTMModel(nn.Module):
    """Recurrent LSTM neural network for temporal traffic anomaly scoring."""

    def __init__(self, input_size: int = INPUT_DIM, hidden_size: int = 32, num_layers: int = 1) -> None:
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size, num_layers=num_layers, batch_first=True)
        self.fc = nn.Sequential(
            nn.Linear(hidden_size, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: [batch_size, seq_len, input_size]
        lstm_out, _ = self.lstm(x)
        # Take hidden state of last timestep
        last_step = lstm_out[:, -1, :]
        out = self.fc(last_step)
        return out


class LSTMTrafficAnomalyDetector:
    """Manages training, inference, and temporal flow evaluation using the PyTorch LSTM model."""

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = model_path or MODEL_PATH
        self.model = TrafficLSTMModel()
        self._lock = threading.Lock()
        self._load_or_train()

    def _generate_synthetic_sequences(self, n_sequences: int = 600) -> Tuple[np.ndarray, np.ndarray]:
        """Generate benign enterprise baseline sequences and synthetic anomalous sequences.
        
        Features per packet:
        0: delta_time (s): Benign 0.01 - 0.5s; Floods < 0.001s; Beacons perfectly fixed ~1.00s.
        1: packet_size (B): Benign 64 - 1500B; Exfil > 4000B; Recon ~40-60B.
        2: direction: 0 for inbound, 1 for outbound.
        3: protocol: 6 for TCP, 17 for UDP, 1 for ICMP.
        """
        rng = np.random.default_rng(1337)
        sequences = []
        labels = []

        half = n_sequences // 2

        # 1. Normal benign traffic sequences (label = 0)
        for _ in range(half):
            seq = []
            for _ in range(SEQ_LENGTH):
                dt = float(rng.exponential(0.08) + 0.01)
                size = float(rng.choice([64, 128, 512, 1420]))
                direction = float(rng.choice([0, 1]))
                proto = float(rng.choice([6, 17]))
                seq.append([dt, size, direction, proto])
            sequences.append(seq)
            labels.append([0.0])

        # 2. Anomalous traffic sequences (label = 1)
        for i in range(half):
            seq = []
            anomaly_type = i % 3
            if anomaly_type == 0:
                # Volumetric DDoS / SYN flood: microsecond delta times, fixed small packet size
                for _ in range(SEQ_LENGTH):
                    seq.append([float(rng.uniform(0.0001, 0.001)), 40.0, 0.0, 6.0])
            elif anomaly_type == 1:
                # Periodic C2 Beaconing: rigid clockwork delta times, constant payload
                base_dt = 5.0
                for _ in range(SEQ_LENGTH):
                    seq.append([float(base_dt + rng.normal(0, 0.002)), 256.0, 1.0, 6.0])
            else:
                # High-volume Exfiltration burst: huge sizes back-to-back
                for _ in range(SEQ_LENGTH):
                    seq.append([float(rng.uniform(0.005, 0.02)), float(rng.uniform(8000, 32000)), 1.0, 6.0])
            sequences.append(seq)
            labels.append([1.0])

        x_data = np.array(sequences, dtype=np.float32)
        y_data = np.array(labels, dtype=np.float32)

        # Normalize features
        x_data[:, :, 0] = np.clip(x_data[:, :, 0] / 5.0, 0.0, 1.0)
        x_data[:, :, 1] = np.clip(x_data[:, :, 1] / 1500.0, 0.0, 5.0)

        return x_data, y_data

    def _load_or_train(self) -> None:
        """Load pretrained model weights or train a new baseline model."""
        if self.model_path.exists():
            try:
                state_dict = torch.load(self.model_path, map_location="cpu", weights_only=True)
                self.model.load_state_dict(state_dict)
                self.model.eval()
                logger.info(f"[LSTM] Loaded model from {self.model_path}")
                return
            except Exception as e:
                logger.warning(f"[LSTM] Failed to load {self.model_path} ({e}), retraining...")

        self._train_and_save()

    def _train_and_save(self) -> None:
        """Train model with PyTorch."""
        logger.info("[LSTM] Training baseline LSTM sequence model...")
        x_data, y_data = self._generate_synthetic_sequences(n_sequences=800)
        
        x_tensor = torch.from_numpy(x_data)
        y_tensor = torch.from_numpy(y_data)

        self.model.train()
        criterion = nn.BCELoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.01)

        dataset = torch.utils.data.TensorDataset(x_tensor, y_tensor)
        loader = torch.utils.data.DataLoader(dataset, batch_size=32, shuffle=True)

        for _ in range(12):
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                pred = self.model(batch_x)
                loss = criterion(pred, batch_y)
                loss.backward()
                optimizer.step()

        self.model.eval()
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save(self.model.state_dict(), self.model_path)
            logger.info(f"[LSTM] Model trained and saved to {self.model_path}")
        except Exception as e:
            logger.warning(f"[LSTM] Could not save weights to disk: {e}")

    def predict_sequence(self, sequence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate a sequence of packet events and return anomaly score.
        
        Each item in sequence dict can contain:
        delta_time: float (seconds)
        packet_size: float (bytes)
        direction: int or str ('in'=0, 'out'=1)
        protocol: str ('TCP'=6, 'UDP'=17, 'ICMP'=1) or int
        """
        if not sequence:
            sequence = [{"delta_time": 0.05, "packet_size": 1420, "direction": 1, "protocol": 6}]

        # Pad or trim to SEQ_LENGTH
        raw_steps = []
        for item in sequence[-SEQ_LENGTH:]:
            dt = float(item.get("delta_time", item.get("interval", 0.05)))
            size = float(item.get("packet_size", item.get("size", 512.0)))
            raw_dir = item.get("direction", 1)
            direction = 0.0 if str(raw_dir).lower() in ("in", "0", "ingress") else 1.0
            raw_proto = str(item.get("protocol", "TCP")).upper()
            proto_num = 17.0 if "UDP" in raw_proto else (1.0 if "ICMP" in raw_proto else 6.0)

            # Normalize
            norm_dt = min(1.0, max(0.0, dt / 5.0))
            norm_size = min(5.0, max(0.0, size / 1500.0))
            raw_steps.append([norm_dt, norm_size, direction, proto_num])

        while len(raw_steps) < SEQ_LENGTH:
            raw_steps.insert(0, [0.02, 0.34, 1.0, 6.0])

        x_input = torch.tensor([raw_steps], dtype=torch.float32)

        with self._lock:
            with torch.no_grad():
                anomaly_prob = float(self.model(x_input)[0][0].item())

        is_anomaly = anomaly_prob >= 0.50
        classification = "Sequential Anomaly" if is_anomaly else "Normal Sequence"

        signals = []
        avg_dt = float(np.mean([s[0] * 5.0 for s in raw_steps]))
        avg_size = float(np.mean([s[1] * 1500.0 for s in raw_steps]))

        if avg_dt < 0.002:
            signals.append(f"Sub-millisecond flood burst detected ({avg_dt*1000:.2f} ms avg inter-arrival)")
        elif avg_dt > 3.0:
            signals.append("Rigid periodic time gap matches C2 beaconing profile")

        if avg_size > 3000:
            signals.append(f"Abnormally oversized data frame sequence ({avg_size:.0f} B avg)")

        if not signals and is_anomaly:
            signals.append("Temporal recurrent pattern diverged from baseline sequence distribution")

        return {
            "model": "LSTM Recurrent Neural Network (PyTorch)",
            "classification": classification,
            "is_anomaly": is_anomaly,
            "anomaly_probability": round(anomaly_prob, 4),
            "sequence_length": SEQ_LENGTH,
            "signals": signals,
            "metrics": {
                "avg_inter_arrival_sec": round(avg_dt, 4),
                "avg_packet_size_bytes": round(avg_size, 1),
            },
        }


# Singleton accessor
_lstm_instance: Optional[LSTMTrafficAnomalyDetector] = None
_lstm_lock = threading.Lock()


def get_lstm_traffic_detector() -> LSTMTrafficAnomalyDetector:
    """Retrieve or initialize the singleton LSTMTrafficAnomalyDetector."""
    global _lstm_instance
    if _lstm_instance is None:
        with _lstm_lock:
            if _lstm_instance is None:
                _lstm_instance = LSTMTrafficAnomalyDetector()
    return _lstm_instance
