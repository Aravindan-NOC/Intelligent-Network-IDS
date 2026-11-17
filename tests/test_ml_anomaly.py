"""
Unit and Integration Tests for Machine Learning Anomaly Detection Pipeline.
Validates FlowFeatureExtractor, dataset generators, Isolation Forest training,
and real-time ML anomaly inference.
"""

import os
import sys
import time
import tempfile
import shutil
import unittest
import numpy as np
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Ensure project root in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.packet_parser import parse_packet
from ml.feature_pipeline import FlowFeatureExtractor, FEATURE_NAMES
from ml.train_model import (
    generate_normal_baseline_dataset,
    generate_attack_anomaly_dataset,
    train_isolation_forest_pipeline,
)
from detection.anomaly_detector import MLAnomalyDetector
from detection.alert_manager import AlertManager


class TestMLAnomalyPipeline(unittest.TestCase):
    """Test suite for feature extraction, model training, and ML inference."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.extractor = FlowFeatureExtractor()

    def tearDown(self):
        try:
            shutil.rmtree(self.test_dir)
        except Exception:
            pass

    def test_feature_extraction_empty(self):
        """Verify empty packet list returns zeroed feature vector without errors."""
        feats = self.extractor.extract_features_from_packets([])
        self.assertEqual(len(feats), len(FEATURE_NAMES))
        for name in FEATURE_NAMES:
            self.assertEqual(feats[name], 0.0)

        vec = self.extractor.to_vector(feats)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertTrue(all(v == 0.0 for v in vec))

    def test_feature_extraction_normal_web_flow(self):
        """Verify feature extraction on realistic TCP web browsing packets."""
        packets = []
        base_time = 1700000000.0

        # Construct 10 TCP packets: 2 SYN, 7 ACK/PSH, 1 FIN
        for i in range(10):
            flags = "S" if i < 2 else "A"
            scapy_pkt = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(
                sport=49152 + i, dport=443, flags=flags
            )
            parsed = parse_packet(scapy_pkt)
            parsed.timestamp = base_time + (i * 0.1)  # 0.9s duration
            packets.append(parsed)

        feats = self.extractor.extract_features_from_packets(packets, window_duration=1.0)

        self.assertEqual(feats["packet_count"], 10.0)
        self.assertEqual(feats["tcp_ratio"], 1.0)
        self.assertEqual(feats["udp_ratio"], 0.0)
        self.assertEqual(feats["icmp_ratio"], 0.0)
        self.assertAlmostEqual(feats["syn_ratio"], 0.20, places=2)
        self.assertAlmostEqual(feats["ack_ratio"], 0.80, places=2)
        self.assertEqual(feats["unique_dst_ports"], 1.0)  # All to port 443
        self.assertEqual(feats["port_entropy"], 0.0)      # Single port -> zero entropy
        self.assertGreater(feats["pps"], 0.0)
        self.assertGreater(feats["bps"], 0.0)

    def test_feature_extraction_port_scan_entropy(self):
        """Verify high unique ports produce elevated Shannon entropy."""
        packets = []
        base_time = 1700000000.0

        # Contact 20 distinct ports
        for port in range(20, 40):
            scapy_pkt = IP(src="10.0.0.99", dst="192.168.1.1") / TCP(
                sport=50000, dport=port, flags="S"
            )
            parsed = parse_packet(scapy_pkt)
            parsed.timestamp = base_time + 0.05 * (port - 20)
            packets.append(parsed)

        feats = self.extractor.extract_features_from_packets(packets, window_duration=1.0)

        self.assertEqual(feats["unique_dst_ports"], 20.0)
        # Shannon entropy of 20 uniform choices is log2(20) ~ 4.32
        self.assertGreater(feats["port_entropy"], 4.0)
        self.assertEqual(feats["syn_ratio"], 1.0)
        self.assertEqual(feats["ack_ratio"], 0.0)

    def test_baseline_and_attack_dataset_generation(self):
        """Verify synthetic baseline and attack generators produce valid matrices."""
        X_normal = generate_normal_baseline_dataset(n_samples=50, seed=1)
        self.assertEqual(X_normal.shape, (50, len(FEATURE_NAMES)))
        self.assertFalse(np.isnan(X_normal).any())
        self.assertFalse(np.isinf(X_normal).any())

        X_attack = generate_attack_anomaly_dataset(n_samples=30, seed=2)
        self.assertEqual(X_attack.shape, (30, len(FEATURE_NAMES)))
        self.assertFalse(np.isnan(X_attack).any())
        self.assertFalse(np.isinf(X_attack).any())

    def test_isolation_forest_training_and_inference(self):
        """Train Isolation Forest model on temporary path and verify anomaly detection."""
        test_model_path = os.path.join(self.test_dir, "test_iso_forest.pkl")

        # Train mini model
        artifact = train_isolation_forest_pipeline(
            n_normal_samples=500,
            contamination=0.03,
            save_path=test_model_path,
        )
        self.assertTrue(os.path.isfile(test_model_path))
        self.assertIn("model", artifact)
        self.assertIn("score_threshold", artifact)

        # Initialize detector with trained model
        alert_mgr = AlertManager(cooldown_seconds=30.0)
        detector = MLAnomalyDetector(
            model_path=test_model_path,
            alert_manager=alert_mgr,
            min_flow_packets=5,
            flow_window_seconds=2.0,
        )
        self.assertTrue(detector.is_loaded)

        # 1. Normal flow evaluation
        normal_pkts = []
        for i in range(8):
            scapy_pkt = IP(src="192.168.1.100", dst="93.184.216.34") / TCP(
                sport=50000 + i, dport=443, flags="A"
            )
            parsed = parse_packet(scapy_pkt)
            parsed.timestamp = time.time() + (i * 0.1)
            normal_pkts.append(parsed)

        is_anomaly_norm, score_norm, _ = detector.evaluate_flow(normal_pkts, window_duration=2.0)
        self.assertFalse(is_anomaly_norm, f"Normal flow was falsely flagged (score: {score_norm})")

        # 2. Anomalous port scan burst evaluation
        scan_pkts = []
        for port in range(1, 30):
            scapy_pkt = IP(src="10.10.10.10", dst="192.168.1.1") / TCP(
                sport=40000, dport=port, flags="S"
            )
            parsed = parse_packet(scapy_pkt)
            parsed.timestamp = time.time() + (port * 0.02)
            scan_pkts.append(parsed)

        is_anomaly_scan, score_scan, _ = detector.evaluate_flow(scan_pkts, window_duration=1.0)
        self.assertTrue(is_anomaly_scan, f"Port scan burst was not detected as anomaly (score: {score_scan})")

    def test_detector_standby_on_missing_model(self):
        """Verify detector enters standby when model path does not exist."""
        non_existent_path = os.path.join(self.test_dir, "missing.pkl")
        detector = MLAnomalyDetector(model_path=non_existent_path)
        self.assertFalse(detector.is_loaded)

        pkt = parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80))
        alert = detector.process_packet(pkt)
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main(verbosity=2)
