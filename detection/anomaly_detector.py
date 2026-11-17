"""
Machine Learning Anomaly Detection Engine (Isolation Forest).

Ingests parsed network packets, aggregates flow windows per source IP,
extracts high-dimensional statistical feature vectors, and performs real-time
unsupervised anomaly inference using the trained Isolation Forest model.
"""

import os
import sys
import time
import logging
from collections import defaultdict, deque
from typing import Optional, List, Dict, Any, Tuple

# Ensure project root in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.packet_parser import ParsedPacket
from ml.feature_pipeline import FlowFeatureExtractor, FEATURE_NAMES
from detection.alert_manager import AlertManager, SecurityAlert

logger = logging.getLogger("NIDS.MLDetector")

DEFAULT_MODEL_PATH = os.path.join(PROJECT_ROOT, "ml", "models", "isolation_forest.pkl")


class MLAnomalyDetector:
    """
    Real-time Unsupervised Flow Anomaly Detector powered by Isolation Forest.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        alert_manager: Optional[AlertManager] = None,
        min_flow_packets: int = 10,
        flow_window_seconds: float = 3.0,
        score_threshold_override: Optional[float] = None,
    ):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.alert_manager = alert_manager
        self.min_flow_packets = min_flow_packets
        self.flow_window_seconds = flow_window_seconds
        self.score_threshold_override = score_threshold_override

        self.feature_extractor = FlowFeatureExtractor(feature_names=FEATURE_NAMES)
        self.model = None
        self.score_threshold = 0.0
        self.model_metadata: Dict[str, Any] = {}
        self.is_loaded = False

        # In-memory sliding flow buffers per source IP: src_ip -> deque of (timestamp, ParsedPacket)
        self._flow_buffers: Dict[str, deque] = defaultdict(deque)

        # Rate limiter for ML evaluations per IP to avoid excessive inference overhead
        self._last_eval_time: Dict[str, float] = {}
        self.eval_interval = 1.0  # Max once per second per IP

        # Load trained model if available
        self._load_model()

    def _load_model(self) -> bool:
        """Load trained Isolation Forest model artifact from disk."""
        if not os.path.isfile(self.model_path):
            logger.warning(
                f"[MLDetector] Model file not found at '{self.model_path}'. "
                f"ML Anomaly Detection is in STANDBY until trained."
            )
            self.is_loaded = False
            return False

        try:
            import joblib
            artifact = joblib.load(self.model_path)
            self.model = artifact.get("model")
            self.score_threshold = (
                self.score_threshold_override
                if self.score_threshold_override is not None
                else artifact.get("score_threshold", 0.0)
            )
            self.model_metadata = {
                "trained_at": artifact.get("trained_at"),
                "n_samples": artifact.get("n_samples"),
                "contamination": artifact.get("contamination"),
                "normal_accuracy": artifact.get("normal_accuracy"),
                "attack_recall": artifact.get("attack_recall"),
            }
            self.is_loaded = True
            logger.info(
                f"[MLDetector] Loaded Isolation Forest model successfully. "
                f"(Threshold: {self.score_threshold:.4f})"
            )
            return True
        except Exception as e:
            logger.error(f"[MLDetector] Failed to load model from '{self.model_path}': {e}")
            self.is_loaded = False
            return False

    def process_packet(
        self,
        packet: ParsedPacket,
        current_time: Optional[float] = None,
    ) -> Optional[SecurityAlert]:
        """
        Ingest a parsed packet, update the source IP flow window, and
        evaluate for ML flow anomalies if minimum packet quota is met.

        :param packet: Dissected ParsedPacket instance.
        :param current_time: Current timestamp (defaults to time.time()).
        :return: SecurityAlert if an anomaly is detected and new; otherwise None.
        """
        if not self.is_loaded:
            return None

        src_ip = getattr(packet, "src_ip", getattr(packet, "source_ip", None))
        if not src_ip:
            return None

        now = current_time if current_time is not None else time.time()

        # Update flow buffer for this source IP
        buf = self._flow_buffers[src_ip]
        buf.append((now, packet))

        # Evict packets older than the sliding window
        cutoff = now - self.flow_window_seconds
        while buf and buf[0][0] < cutoff:
            buf.popleft()

        # Check if flow buffer meets minimum evaluation threshold
        if len(buf) < self.min_flow_packets:
            return None

        # Rate-limit evaluation frequency per IP
        last_eval = self._last_eval_time.get(src_ip, 0.0)
        if now - last_eval < self.eval_interval:
            return None

        self._last_eval_time[src_ip] = now

        # Extract features from current sliding window
        window_packets = [p for _, p in buf]
        feature_dict = self.feature_extractor.extract_features_from_packets(
            window_packets, window_duration=self.flow_window_seconds
        )
        vector = self.feature_extractor.to_vector(feature_dict)

        # Run model inference
        is_anomaly, score = self._predict_single(vector)

        if is_anomaly:
            alert = self._create_anomaly_alert(
                packet=packet,
                src_ip=src_ip,
                score=score,
                features=feature_dict,
                now=now,
            )
            return alert

        return None

    def evaluate_flow(
        self,
        packets: List[ParsedPacket],
        window_duration: Optional[float] = None,
    ) -> Tuple[bool, float, Dict[str, float]]:
        """
        Directly evaluate a list of packets without updating state.
        Useful for batch testing, offline PCAP forensics, and unit tests.
        """
        if not self.is_loaded or not packets:
            return False, 0.0, {}

        features = self.feature_extractor.extract_features_from_packets(
            packets, window_duration=window_duration
        )
        vector = self.feature_extractor.to_vector(features)
        is_anomaly, score = self._predict_single(vector)
        return is_anomaly, score, features

    def _predict_single(self, vector: List[float]) -> Tuple[bool, float]:
        """
        Evaluate a single 1D feature vector against the Isolation Forest model.
        Returns (is_anomaly, decision_score).
        """
        if not self.is_loaded or self.model is None:
            return False, 0.0

        try:
            import numpy as np
            X = np.array([vector], dtype=np.float64)
            # IsolationForest decision_function: lower (negative) values indicate anomalies
            score = float(self.model.decision_function(X)[0])
            pred = int(self.model.predict(X)[0])

            # An anomaly if predict == -1 or score is below calibrated threshold
            is_anomaly = (pred == -1) or (score <= self.score_threshold)
            return is_anomaly, score
        except Exception as e:
            logger.error(f"[MLDetector] Inference error: {e}")
            return False, 0.0

    def _create_anomaly_alert(
        self,
        packet: ParsedPacket,
        src_ip: str,
        score: float,
        features: Dict[str, float],
        now: float,
    ) -> Optional[SecurityAlert]:
        """
        Formulate a detailed, explainable security alert for an ML anomaly.
        """
        pps = features.get("pps", 0.0)
        unique_ports = int(features.get("unique_dst_ports", 0))
        syn_ratio = features.get("syn_ratio", 0.0)
        entropy = features.get("port_entropy", 0.0)

        # Determine subcategory and severity
        if score < -0.15 or pps > 80.0:
            severity = "CRITICAL"
        elif score < -0.05 or unique_ports >= 15:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        # Construct explainable rationale
        reasons = []
        if pps > 40:
            reasons.append(f"High Velocity: {pps:.1f} PPS")
        if unique_ports > 8:
            reasons.append(f"Port Dispersion: {unique_ports} ports (Entropy: {entropy:.2f})")
        if syn_ratio > 0.8:
            reasons.append(f"Asymmetric SYN ratio: {syn_ratio*100:.0f}%")
        if not reasons:
            reasons.append("Multi-dimensional flow vector outlier")

        details = (
            f"Isolation Forest Anomaly Detected (Score: {score:.4f}, Threshold: {self.score_threshold:.4f}). "
            f"Indicators: {', '.join(reasons)}. "
            f"Flow summary: {int(features.get('packet_count', 0))} pkts, "
            f"{int(features.get('byte_count', 0))} bytes over {features.get('flow_duration', 0):.2f}s."
        )

        dst_ip = getattr(packet, "dst_ip", getattr(packet, "destination_ip", "0.0.0.0"))
        src_port = getattr(packet, "src_port", getattr(packet, "source_port", None))
        dst_port = getattr(packet, "dst_port", getattr(packet, "destination_port", None))
        proto = getattr(packet, "transport_proto", getattr(packet, "protocol", "IP"))

        if self.alert_manager:
            alert, is_new = self.alert_manager.record_alert(
                attack_type="ML Anomaly: Flow Deviation",
                severity=severity,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=proto,
                description=details,
                mitigation_tip="Isolate source IP or inspect anomalous host processes for zero-day/automated activity.",
                timestamp=now,
            )
            return alert if is_new else None
        else:
            return SecurityAlert(
                alert_id=0,
                attack_type="ML Anomaly: Flow Deviation",
                severity=severity,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=proto,
                description=details,
                timestamp=now,
            )

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic health and training status of the ML engine."""
        return {
            "is_loaded": self.is_loaded,
            "model_path": self.model_path,
            "score_threshold": self.score_threshold,
            "active_flows_tracked": len(self._flow_buffers),
            "metadata": self.model_metadata,
        }
