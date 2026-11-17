"""
Model Training and Baseline Profiling for ML Anomaly Detection.

Trains an unsupervised Isolation Forest model on network baseline flow profiles,
calibrates decision boundaries against synthetic attack anomalies, and serializes
the trained model pipeline to ml/models/isolation_forest.pkl.
"""

import os
import sys
import time
import joblib
import numpy as np
from typing import Dict, Any, Tuple
from sklearn.ensemble import IsolationForest

# Ensure project root in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_pipeline import FEATURE_NAMES

MODEL_DIR = os.path.join(PROJECT_ROOT, "ml", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")


def generate_normal_baseline_dataset(n_samples: int = 3000, seed: int = 42) -> np.ndarray:
    """
    Synthesize diverse normal network traffic flow profiles:
    - Standard Web Browsing (HTTP/HTTPS: ports 80, 443)
    - DNS Resolution (UDP port 53)
    - Periodic API sync / background services
    - Routine administrative SSH / low-rate ICMP
    """
    rng = np.random.default_rng(seed)
    data = []

    for _ in range(n_samples):
        traffic_type = rng.choice(["web", "dns", "api_sync", "idle_mixed"], p=[0.55, 0.20, 0.15, 0.10])

        if traffic_type == "web":
            # Web browsing: moderate PPS, balanced TCP handshake, low port entropy
            duration = rng.uniform(1.0, 5.0)
            pps = rng.uniform(2.0, 30.0)
            packet_count = max(int(pps * duration), 3)
            avg_size = rng.uniform(250.0, 1100.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            tcp_ratio = rng.uniform(0.85, 1.0)
            udp_ratio = 1.0 - tcp_ratio
            icmp_ratio = 0.0
            syn_ratio = rng.uniform(0.05, 0.25)
            ack_ratio = rng.uniform(0.70, 0.98)
            rst_ratio = rng.uniform(0.0, 0.05)
            unique_dst_ports = rng.integers(1, 4)
            port_entropy = rng.uniform(0.0, 1.2)

        elif traffic_type == "dns":
            # DNS queries: low PPS, UDP dominant, port 53, small packets
            duration = rng.uniform(0.5, 4.0)
            pps = rng.uniform(1.0, 8.0)
            packet_count = max(int(pps * duration), 2)
            avg_size = rng.uniform(60.0, 200.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            tcp_ratio = 0.0
            udp_ratio = rng.uniform(0.90, 1.0)
            icmp_ratio = 0.0
            syn_ratio = 0.0
            ack_ratio = 0.0
            rst_ratio = 0.0
            unique_dst_ports = 1
            port_entropy = 0.0

        elif traffic_type == "api_sync":
            # Background cloud sync / API polling: intermittent TCP
            duration = rng.uniform(2.0, 5.0)
            pps = rng.uniform(0.5, 10.0)
            packet_count = max(int(pps * duration), 2)
            avg_size = rng.uniform(300.0, 900.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            tcp_ratio = rng.uniform(0.95, 1.0)
            udp_ratio = 1.0 - tcp_ratio
            icmp_ratio = 0.0
            syn_ratio = rng.uniform(0.05, 0.20)
            ack_ratio = rng.uniform(0.80, 0.98)
            rst_ratio = rng.uniform(0.0, 0.02)
            unique_dst_ports = rng.integers(1, 3)
            port_entropy = rng.uniform(0.0, 0.8)

        else:  # idle_mixed
            # Low rate mixed traffic with occasional ping
            duration = rng.uniform(1.0, 5.0)
            pps = rng.uniform(0.2, 4.0)
            packet_count = max(int(pps * duration), 1)
            avg_size = rng.uniform(60.0, 500.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            tcp_ratio = rng.uniform(0.4, 0.7)
            udp_ratio = rng.uniform(0.2, 0.4)
            icmp_ratio = 1.0 - tcp_ratio - udp_ratio
            syn_ratio = rng.uniform(0.05, 0.3) if tcp_ratio > 0 else 0.0
            ack_ratio = rng.uniform(0.6, 0.95) if tcp_ratio > 0 else 0.0
            rst_ratio = 0.0
            unique_dst_ports = rng.integers(1, 3)
            port_entropy = rng.uniform(0.0, 0.9)

        data.append([
            duration,
            float(packet_count),
            float(byte_count),
            pps,
            bps,
            avg_size,
            tcp_ratio,
            udp_ratio,
            icmp_ratio,
            syn_ratio,
            ack_ratio,
            rst_ratio,
            float(unique_dst_ports),
            port_entropy,
        ])

    return np.array(data, dtype=np.float64)


def generate_attack_anomaly_dataset(n_samples: int = 300, seed: int = 99) -> np.ndarray:
    """
    Synthesize distinct network attack anomalies for validation:
    - Volumetric Port Scans (high unique ports & high entropy)
    - SYN Floods (extreme PPS, 100% SYN, zero ACK)
    - ICMP Floods (extreme PPS, 100% ICMP)
    - Data exfiltration / burst anomalies (huge BPS, abnormal size)
    """
    rng = np.random.default_rng(seed)
    data = []

    for _ in range(n_samples):
        attack_type = rng.choice(["port_scan", "syn_flood", "icmp_flood", "exfil_burst"])

        if attack_type == "port_scan":
            # Scanning 20-200 distinct ports in 1-3 seconds, high entropy
            duration = rng.uniform(1.0, 3.0)
            pps = rng.uniform(25.0, 120.0)
            packet_count = int(pps * duration)
            avg_size = rng.uniform(40.0, 70.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            unique_dst_ports = rng.integers(18, 150)
            port_entropy = rng.uniform(3.5, 6.5)  # High entropy
            tcp_ratio = rng.uniform(0.9, 1.0)
            udp_ratio = 1.0 - tcp_ratio
            icmp_ratio = 0.0
            syn_ratio = rng.uniform(0.85, 1.0)
            ack_ratio = 0.0
            rst_ratio = 0.0

        elif attack_type == "syn_flood":
            # SYN flood: 80-500 PPS, 100% SYN, 0% ACK
            duration = rng.uniform(1.0, 4.0)
            pps = rng.uniform(80.0, 400.0)
            packet_count = int(pps * duration)
            avg_size = rng.uniform(54.0, 66.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            unique_dst_ports = 1
            port_entropy = 0.0
            tcp_ratio = 1.0
            udp_ratio = 0.0
            icmp_ratio = 0.0
            syn_ratio = 1.0  # Pure SYN
            ack_ratio = 0.0
            rst_ratio = 0.0

        elif attack_type == "icmp_flood":
            # ICMP flood: 60-350 PPS, 100% ICMP
            duration = rng.uniform(1.0, 3.0)
            pps = rng.uniform(60.0, 300.0)
            packet_count = int(pps * duration)
            avg_size = rng.uniform(64.0, 128.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            unique_dst_ports = 0
            port_entropy = 0.0
            tcp_ratio = 0.0
            udp_ratio = 0.0
            icmp_ratio = 1.0  # Pure ICMP
            syn_ratio = 0.0
            ack_ratio = 0.0
            rst_ratio = 0.0

        else:  # exfil_burst
            # Huge volumetric burst: high BPS and jumbo packets
            duration = rng.uniform(1.0, 3.0)
            pps = rng.uniform(150.0, 600.0)
            packet_count = int(pps * duration)
            avg_size = rng.uniform(1400.0, 1500.0)
            byte_count = packet_count * avg_size
            bps = (byte_count * 8.0) / duration
            unique_dst_ports = 1
            port_entropy = 0.0
            tcp_ratio = 1.0
            udp_ratio = 0.0
            icmp_ratio = 0.0
            syn_ratio = 0.0
            ack_ratio = 1.0
            rst_ratio = 0.0

        data.append([
            duration,
            float(packet_count),
            float(byte_count),
            pps,
            bps,
            avg_size,
            tcp_ratio,
            udp_ratio,
            icmp_ratio,
            syn_ratio,
            ack_ratio,
            rst_ratio,
            float(unique_dst_ports),
            port_entropy,
        ])

    return np.array(data, dtype=np.float64)


def train_isolation_forest_pipeline(
    n_normal_samples: int = 4000,
    contamination: float = 0.03,
    save_path: str = MODEL_PATH,
) -> Dict[str, Any]:
    """
    Train Isolation Forest model on baseline traffic and validate against attacks.
    Saves serialized model and calibration metadata to disk.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    print(f"[*] Generating {n_normal_samples} normal traffic baseline samples...")
    X_normal = generate_normal_baseline_dataset(n_samples=n_normal_samples, seed=42)

    print(f"[*] Generating 400 synthetic attack anomaly verification samples...")
    X_attack = generate_attack_anomaly_dataset(n_samples=400, seed=123)

    print(f"[*] Training Isolation Forest (n_estimators=100, contamination={contamination})...")
    start_train = time.time()
    iso_forest = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    iso_forest.fit(X_normal)
    train_duration = time.time() - start_train
    print(f"[+] Isolation Forest trained successfully in {train_duration:.2f}s.")

    # Validation: Normal baseline prediction (should be ~97% normal (+1))
    normal_preds = iso_forest.predict(X_normal)
    normal_acc = np.mean(normal_preds == 1) * 100.0

    # Validation: Attack anomaly prediction (should be >95% anomaly (-1))
    attack_preds = iso_forest.predict(X_attack)
    attack_recall = np.mean(attack_preds == -1) * 100.0

    # Score distributions
    normal_scores = iso_forest.decision_function(X_normal)
    attack_scores = iso_forest.decision_function(X_attack)

    print("\n" + "=" * 60)
    print(" ISOLATION FOREST VALIDATION RESULTS")
    print("=" * 60)
    print(f"  Normal Specificity (Predicted Normal) : {normal_acc:.2f}%")
    print(f"  Attack Recall (Detected Anomaly)      : {attack_recall:.2f}%")
    print(f"  Normal Flow Score (Mean / Min)        : {np.mean(normal_scores):.4f} / {np.min(normal_scores):.4f}")
    print(f"  Attack Flow Score (Mean / Max)        : {np.mean(attack_scores):.4f} / {np.max(attack_scores):.4f}")
    print("=" * 60)

    # Package metadata payload
    pipeline_artifact = {
        "model": iso_forest,
        "feature_names": FEATURE_NAMES,
        "trained_at": time.time(),
        "n_samples": n_normal_samples,
        "contamination": contamination,
        "normal_accuracy": float(normal_acc),
        "attack_recall": float(attack_recall),
        "score_threshold": float(np.percentile(normal_scores, 3.0)),  # 3rd percentile calibration
    }

    joblib.dump(pipeline_artifact, save_path)
    print(f"[+] Model artifact successfully exported to: {save_path}\n")
    return pipeline_artifact


if __name__ == "__main__":
    train_isolation_forest_pipeline()
