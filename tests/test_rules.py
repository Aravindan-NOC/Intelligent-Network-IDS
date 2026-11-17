"""
Comprehensive Unit Tests for Rule-Based Detection Engine (detection/rule_engine.py).
Tests Port Scan, SYN Flood, ICMP Flood, Suspicious Traffic, and Alert Deduplication.
"""

import os
import sys
import time
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.packet_parser import ParsedPacket
from detection.flow_analyzer import FlowAnalyzer
from detection.alert_manager import AlertManager
from detection.rule_engine import RuleEngine


def make_packet(
    src_ip="192.168.1.100",
    dst_ip="192.168.1.1",
    proto="TCP",
    src_port=50000,
    dst_port=80,
    flags=None,
    icmp_type=None,
    timestamp=None,
    size=64,
) -> ParsedPacket:
    """Helper to construct a mock ParsedPacket quickly for rule testing."""
    return ParsedPacket(
        timestamp=timestamp or time.time(),
        packet_size=size,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_version=4,
        ttl=64,
        transport_proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags if flags is not None else ["ACK"],
        icmp_type=icmp_type,
        summary=f"{proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
    )


class TestRuleEngine(unittest.TestCase):
    """Test suite validating all signature and heuristic intrusion detection rules."""

    def setUp(self):
        self.flow_analyzer = FlowAnalyzer(
            port_scan_window=5.0,
            syn_flood_window=3.0,
            icmp_flood_window=2.0,
        )
        self.alert_manager = AlertManager(cooldown_seconds=30.0)
        self.engine = RuleEngine(
            flow_analyzer=self.flow_analyzer,
            alert_manager=self.alert_manager,
            config={
                "PORT_SCAN_THRESHOLD": 15,
                "SYN_FLOOD_MIN_PACKETS": 20,
                "SYN_FLOOD_RATIO_THRESHOLD": 0.80,
                "ICMP_FLOOD_MIN_PACKETS": 20,
            },
        )

    def test_volumetric_port_scan_detection(self):
        """Verify rapid probing of 16 distinct ports triggers Port Scan alert."""
        attacker_ip = "10.0.0.99"
        base_time = time.time()
        alerts = []

        # Probe ports 1 to 14 (below threshold of 15)
        for port in range(1, 15):
            pkt = make_packet(
                src_ip=attacker_ip, dst_port=port, flags=["SYN"], timestamp=base_time + 0.1 * port
            )
            alerts.extend(self.engine.evaluate_packet(pkt))

        # Threshold not yet reached
        self.assertEqual(len(alerts), 0)

        # 15th port breach
        pkt15 = make_packet(
            src_ip=attacker_ip, dst_port=15, flags=["SYN"], timestamp=base_time + 1.5
        )
        alerts15 = self.engine.evaluate_packet(pkt15)

        self.assertGreaterEqual(len(alerts15), 1)
        alert = alerts15[0]
        self.assertEqual(alert.attack_type, "Port Scan")
        self.assertEqual(alert.source_ip, attacker_ip)
        self.assertEqual(alert.severity, "HIGH")

    def test_stealth_xmas_scan_detection(self):
        """Verify TCP packet with FIN+PSH+URG triggers instant Port Scan alert."""
        pkt = make_packet(src_ip="10.0.0.5", dst_port=80, flags=["FIN", "PSH", "URG"])
        alerts = self.engine.evaluate_packet(pkt)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "Port Scan")
        self.assertIn("Xmas", alerts[0].description)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_stealth_null_scan_detection(self):
        """Verify TCP packet with empty flags triggers instant Port Scan alert."""
        pkt = make_packet(src_ip="10.0.0.6", dst_port=22, flags=[])
        alerts = self.engine.evaluate_packet(pkt)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "Port Scan")
        self.assertIn("Null", alerts[0].description)

    def test_illegal_syn_fin_scan_detection(self):
        """Verify illegal SYN+FIN combination triggers Port Scan alert."""
        pkt = make_packet(src_ip="10.0.0.7", dst_port=443, flags=["SYN", "FIN"])
        alerts = self.engine.evaluate_packet(pkt)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "Port Scan")
        self.assertIn("SYN+FIN", alerts[0].description)

    def test_syn_flood_detection(self):
        """Verify high volume of pure SYN packets with no ACKs triggers SYN Flood alert."""
        attacker_ip = "172.16.1.100"
        base_time = time.time()
        triggered = []

        # Send 22 pure SYN packets
        for i in range(22):
            pkt = make_packet(
                src_ip=attacker_ip,
                dst_port=80,
                flags=["SYN"],
                timestamp=base_time + (i * 0.05),
            )
            alerts = self.engine.evaluate_packet(pkt)
            if alerts:
                triggered.extend([a for a in alerts if a.attack_type == "SYN Flood"])

        self.assertGreaterEqual(len(triggered), 1)
        syn_alert = triggered[0]
        self.assertEqual(syn_alert.attack_type, "SYN Flood")
        self.assertEqual(syn_alert.severity, "CRITICAL")
        self.assertEqual(syn_alert.source_ip, attacker_ip)

    def test_icmp_flood_detection(self):
        """Verify rapid ICMP Echo Requests trigger ICMP Flood alert."""
        attacker_ip = "192.168.10.50"
        base_time = time.time()
        triggered = []

        # Send 22 ICMP Echo Requests (type 8)
        for i in range(22):
            pkt = make_packet(
                src_ip=attacker_ip,
                proto="ICMP",
                icmp_type=8,
                timestamp=base_time + (i * 0.05),
            )
            alerts = self.engine.evaluate_packet(pkt)
            if alerts:
                triggered.extend([a for a in alerts if a.attack_type == "ICMP Flood"])

        self.assertGreaterEqual(len(triggered), 1)
        icmp_alert = triggered[0]
        self.assertEqual(icmp_alert.attack_type, "ICMP Flood")
        self.assertEqual(icmp_alert.severity, "HIGH")
        self.assertEqual(icmp_alert.source_ip, attacker_ip)

    def test_suspicious_backdoor_port_detection(self):
        """Verify traffic targeting port 4444 or 31337 triggers Suspicious Traffic alert."""
        # 1. Metasploit Default Listener (4444)
        pkt1 = make_packet(src_ip="10.0.0.101", dst_port=4444, flags=["SYN"])
        alerts1 = self.engine.evaluate_packet(pkt1)
        self.assertEqual(len(alerts1), 1)
        self.assertEqual(alerts1[0].attack_type, "Suspicious Traffic")
        self.assertIn("Metasploit", alerts1[0].description)

        # 2. Back Orifice Trojan (31337)
        pkt2 = make_packet(src_ip="10.0.0.102", dst_port=31337, flags=["SYN"])
        alerts2 = self.engine.evaluate_packet(pkt2)
        self.assertEqual(len(alerts2), 1)
        self.assertEqual(alerts2[0].attack_type, "Suspicious Traffic")
        self.assertIn("Back Orifice", alerts2[0].description)

    def test_illegal_syn_rst_flag_combination(self):
        """Verify illegal SYN+RST flags trigger Suspicious Traffic alert."""
        pkt = make_packet(dst_port=80, flags=["SYN", "RST"])
        alerts = self.engine.evaluate_packet(pkt)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].attack_type, "Suspicious Traffic")
        self.assertIn("SYN+RST", alerts[0].description)

    def test_alert_deduplication_and_throttling(self):
        """Verify recurring flood packets aggregate into one episode instead of spamming DB."""
        attacker_ip = "10.0.0.200"
        base_time = time.time()

        # Send 50 SYN flood packets over 2 seconds
        for i in range(50):
            pkt = make_packet(
                src_ip=attacker_ip,
                dst_port=80,
                flags=["SYN"],
                timestamp=base_time + (i * 0.04),
            )
            self.engine.evaluate_packet(pkt)

        # Check total recorded alerts in history
        alerts = self.alert_manager.get_alerts(limit=10, attack_type="SYN Flood")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], attacker_ip)
        # Verify the episode aggregated the packet count
        self.assertGreaterEqual(alerts[0]["packet_count"], 30)

    def test_clean_normal_traffic_zero_false_positives(self):
        """Verify normal web browsing produces zero alerts."""
        client_ip = "192.168.1.15"
        server_ip = "142.250.190.46"
        base_time = time.time()

        normal_flow = [
            # 1. TCP 3-way Handshake: Client SYN
            make_packet(src_ip=client_ip, dst_ip=server_ip, dst_port=443, flags=["SYN"], timestamp=base_time),
            # 2. Server SYN+ACK
            make_packet(src_ip=server_ip, dst_ip=client_ip, src_port=443, dst_port=50000, flags=["SYN", "ACK"], timestamp=base_time + 0.02),
            # 3. Client ACK
            make_packet(src_ip=client_ip, dst_ip=server_ip, dst_port=443, flags=["ACK"], timestamp=base_time + 0.03),
            # 4. HTTPS Application Data
            make_packet(src_ip=client_ip, dst_ip=server_ip, dst_port=443, flags=["PSH", "ACK"], size=500, timestamp=base_time + 0.05),
            make_packet(src_ip=server_ip, dst_ip=client_ip, src_port=443, dst_port=50000, flags=["ACK"], size=64, timestamp=base_time + 0.07),
        ]

        all_alerts = []
        for pkt in normal_flow:
            alerts = self.engine.evaluate_packet(pkt)
            all_alerts.extend(alerts)

        self.assertEqual(len(all_alerts), 0)
        self.assertEqual(self.alert_manager.get_total_alert_count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
