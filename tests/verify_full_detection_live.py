"""
All-in-One Automated Live Detection Verification Script.
Starts the sniffer on loopback, launches safe localhost attack scenarios,
and verifies real-time intrusion detection and alert generation.
"""

import os
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.sniffer import SnifferWorker
from core.packet_parser import parse_packet
from core.network_utils import is_admin
from detection.flow_analyzer import FlowAnalyzer
from detection.alert_manager import AlertManager
from detection.rule_engine import RuleEngine
from detection.anomaly_detector import MLAnomalyDetector
from tests.test_attack_simulator import (
    simulate_port_scan,
    simulate_syn_flood,
    simulate_icmp_flood,
    simulate_stealth_xmas,
    simulate_suspicious_port,
)


def run_automated_live_test():
    print("=" * 70)
    print(" INTELLIGENT NIDS - AUTOMATED LIVE ATTACK & DETECTION VERIFIER")
    print("=" * 70)

    admin = is_admin()
    print(f"[*] Windows Administrator Privilege: {'[YES] Elevated' if admin else '[WARN] Standard User'}")
    if not admin:
        print("[!] Note: Packet capture and raw packet sending require Administrator privileges.")

    # 1. Initialize NIDS components
    flow_analyzer = FlowAnalyzer()
    alert_manager = AlertManager(cooldown_seconds=10.0)
    rule_engine = RuleEngine(flow_analyzer=flow_analyzer, alert_manager=alert_manager)
    ml_detector = MLAnomalyDetector(
        alert_manager=alert_manager,
        min_flow_packets=8,
        flow_window_seconds=3.0,
    )

    # 2. Start SnifferWorker on Loopback
    worker = SnifferWorker(interface="loopback", max_queue_size=5000)
    print("[*] Starting sniffer on loopback interface...")
    started = worker.start_monitoring()
    if not started:
        print("[FAIL] Could not start loopback sniffer.")
        return

    print(f"[*] Sniffer actively listening on: {worker.active_interface}")
    time.sleep(1.0)  # Brief warm-up

    detected_attacks = {}

    def drain_and_evaluate():
        """Pull pending packets from queue and evaluate them."""
        while True:
            pkt = worker.get_packet(timeout=0.05)
            if not pkt:
                break
            parsed = parse_packet(pkt)
            if parsed:
                alerts = rule_engine.evaluate_packet(parsed)
                ml_alert = ml_detector.process_packet(parsed)
                if ml_alert:
                    alerts.append(ml_alert)

                for alert in alerts:
                    detected_attacks[alert.attack_type] = alert
                    border = "!" * 70 if alert.severity == "CRITICAL" else "=" * 70
                    print("\n" + border)
                    print(f" 🚨 [DETECTED] {alert.attack_type} (Severity: {alert.severity})")
                    print(border)
                    print(f"  Source       : {alert.source_ip}:{alert.source_port or 'N/A'}")
                    print(f"  Target       : {alert.destination_ip}:{alert.destination_port or 'N/A'}")
                    print(f"  Description  : {alert.description}")
                    print(f"  Mitigation   : {alert.mitigation_tip}")
                    print(border)

    try:
        # Scenario 1: Port Scan
        print("\n>>> Launching Scenario 1: TCP Port Scan...")
        simulate_port_scan("127.0.0.1", 20, 38)
        time.sleep(0.5)
        drain_and_evaluate()

        # Scenario 2: SYN Flood
        print("\n>>> Launching Scenario 2: TCP SYN Flood...")
        simulate_syn_flood("127.0.0.1", 80, count=60)
        time.sleep(0.5)
        drain_and_evaluate()

        # Scenario 3: ICMP Ping Flood
        print("\n>>> Launching Scenario 3: ICMP Ping Flood...")
        simulate_icmp_flood("127.0.0.1", count=50)
        time.sleep(0.5)
        drain_and_evaluate()

        # Scenario 4: Stealth Xmas Scan
        print("\n>>> Launching Scenario 4: Stealth Xmas Scan...")
        simulate_stealth_xmas("127.0.0.1", 80)
        time.sleep(0.5)
        drain_and_evaluate()

        # Scenario 5: Exploit Port 4444
        print("\n>>> Launching Scenario 5: Suspicious Exploit Port (4444)...")
        simulate_suspicious_port("127.0.0.1", 4444)
        time.sleep(0.5)
        drain_and_evaluate()

    finally:
        worker.stop_monitoring()

    # Final Verification Checklist
    metrics = worker.get_metrics()
    print("\n" + "=" * 70)
    print(" VERIFICATION RESULTS CHECKLIST:")
    print("=" * 70)
    print(f"  Total Packets Captured : {metrics['total_captured']}")
    print(f"  Total Packets Dequeued : {metrics['total_dequeued']}")
    print(f"  Total Unique Incidents : {alert_manager.get_total_alert_count()}")
    print("-" * 70)

    expected_threats = [
        "Port Scan",
        "SYN Flood",
        "ICMP Flood",
        "Suspicious Traffic",
        "ML Anomaly: Flow Deviation",
    ]
    all_passed = True
    for threat in expected_threats:
        status = "PASSED [DETECTED]" if threat in detected_attacks else "FAILED [MISSED]"
        if threat not in detected_attacks:
            all_passed = False
        print(f"  * {threat:<20}: {status}")

    print("=" * 70)
    if all_passed:
        print("[SUCCESS] All 4 attack categories successfully detected in real time!")
    else:
        print("[WARN] Some attack scenarios were not captured. Re-run in an Administrator shell.")
    print("=" * 70)


if __name__ == "__main__":
    run_automated_live_test()
