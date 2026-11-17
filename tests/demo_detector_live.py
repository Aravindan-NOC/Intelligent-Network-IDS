"""
Live Intrusion Detection System Console Demonstration.
Integrates SnifferWorker + PacketParser + FlowAnalyzer + RuleEngine + AlertManager.
Monitors live network traffic in real time and displays SOC alerts for detected attacks.
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


def run_live_ids_demo(duration: int = 30, interface: str = None):
    print("=" * 70)
    print(" INTELLIGENT NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
    print(" LIVE SOC MONITORING CONSOLE")
    print("=" * 70)

    admin = is_admin()
    print(f"[*] Windows Administrator Privilege: {'[YES] Elevated' if admin else '[WARN] Standard User'}")
    if not admin:
        print("[!] Note: Packet capture requires Administrator privileges on Windows.")

    # Initialize NIDS Pipeline Components
    print("[*] Initializing Sliding-Window Flow Analyzer...")
    flow_analyzer = FlowAnalyzer(
        port_scan_window=5.0,
        syn_flood_window=3.0,
        icmp_flood_window=2.0,
    )

    print("[*] Initializing Alert Manager (30s episode deduplication)...")
    alert_manager = AlertManager(cooldown_seconds=30.0)

    print("[*] Initializing Rule-Based Detection Engine...")
    rule_engine = RuleEngine(
        flow_analyzer=flow_analyzer,
        alert_manager=alert_manager,
    )

    print(f"[*] Starting SnifferWorker...")
    worker = SnifferWorker(interface=interface, max_queue_size=5000)
    started = worker.start_monitoring()
    if not started:
        print("[FAIL] Could not start packet capture.")
        return

    print(f"[*] Active Interface: {worker.active_interface}")
    print(f"[*] IDS Engine is ACTIVE. Listening for {duration} seconds... (Press Ctrl+C to stop)\n")

    start_time = time.time()
    packets_processed = 0
    alerts_fired = 0

    try:
        while time.time() - start_time < duration:
            # Pull next packet from queue
            pkt = worker.get_packet(timeout=0.2)
            if pkt is None:
                continue

            parsed = parse_packet(pkt)
            if parsed is None:
                continue

            packets_processed += 1

            # Evaluate packet against Rule-Based Detection Core
            new_alerts = rule_engine.evaluate_packet(parsed)

            if new_alerts:
                for alert in new_alerts:
                    alerts_fired += 1
                    border = "!" * 70 if alert.severity == "CRITICAL" else "=" * 70
                    print("\n" + border)
                    print(f" [!] SECURITY ALERT #{alert.id} [{alert.severity}] - {alert.attack_type}")
                    print(border)
                    print(f"  Source IP        : {alert.source_ip}:{alert.source_port or 'N/A'}")
                    print(f"  Destination IP   : {alert.destination_ip}:{alert.destination_port or 'N/A'}")
                    print(f"  Protocol         : {alert.protocol}")
                    print(f"  Incident Packets : {alert.packet_count}")
                    print(f"  Description      : {alert.description}")
                    print(f"  Mitigation Tip   : {alert.mitigation_tip}")
                    print(border + "\n")

    except KeyboardInterrupt:
        print("\n[!] IDS monitoring stopped by user.")

    finally:
        worker.stop_monitoring()

    metrics = worker.get_metrics()
    alert_counts = alert_manager.get_alert_counts_by_severity()
    summary = flow_analyzer.get_traffic_summary()

    print("\n" + "=" * 70)
    print(" SOC MONITORING SESSION SUMMARY")
    print("=" * 70)
    print(f"  Capture Runtime      : {metrics['uptime_seconds']}s")
    print(f"  Packets Captured     : {metrics['total_captured']}")
    print(f"  Packets Processed    : {packets_processed}")
    print(f"  Throughput (PPS)     : {metrics['packets_per_second']}")
    print(f"  Security Incidents   : {alert_manager.get_total_alert_count()}")
    print(f"    - CRITICAL Alerts  : {alert_counts['CRITICAL']}")
    print(f"    - HIGH Alerts      : {alert_counts['HIGH']}")
    print(f"    - MEDIUM Alerts    : {alert_counts['MEDIUM']}")
    print(f"    - LOW Alerts       : {alert_counts['LOW']}")
    print("  Protocol Breakdown   :")
    for proto, cnt in summary["protocol_distribution"].items():
        if cnt > 0:
            print(f"    * {proto:<8}: {cnt} packets")
    print("=" * 70)


if __name__ == "__main__":
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    iface = sys.argv[2] if len(sys.argv) > 2 else None
    run_live_ids_demo(duration=dur, interface=iface)
