"""
Live Demonstration: Integration of SnifferWorker with PacketParser.
Captures real network packets from the wire, passes them through parse_packet(),
and prints their standardized, structured fields.
"""

import os
import sys
import time
import json

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.sniffer import SnifferWorker
from core.packet_parser import parse_packet
from core.network_utils import is_admin


def run_live_parser_demo(target_packets: int = 5, timeout: int = 15, interface: str = None):
    print("=" * 70)
    print(" INTELLIGENT NIDS - LIVE PARSER INTEGRATION DEMO")
    print("=" * 70)

    admin = is_admin()
    print(f"[*] Windows Administrator Privilege: {'[YES] Elevated' if admin else '[WARN] Standard User'}")
    if not admin:
        print("[!] Note: For live physical capture, run in an Administrator terminal.")

    worker = SnifferWorker(interface=interface, max_queue_size=2000)

    print(f"[*] Starting background capture engine...")
    started = worker.start_monitoring()
    if not started:
        print("[FAIL] Could not start packet capture engine.")
        return

    print(f"[*] Capturing on: {worker.active_interface}")
    print(f"[*] Waiting to capture and parse {target_packets} real packets (Timeout: {timeout}s)...")
    print("    (Generate network activity like opening a website if on Wi-Fi)\n")

    parsed_count = 0
    start_time = time.time()

    try:
        while parsed_count < target_packets and (time.time() - start_time < timeout):
            pkt = worker.get_packet(timeout=0.5)
            if pkt is None:
                continue

            parsed = parse_packet(pkt)
            if parsed is None:
                continue

            parsed_count += 1
            print(f"[{parsed_count}/{target_packets}] --- PARSED PACKET DISSECTION ---")
            print(f"  Timestamp        : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(parsed.timestamp))}.{int((parsed.timestamp % 1) * 1000):03d}")
            print(f"  Frame Size       : {parsed.packet_size} bytes")
            print(f"  Ethernet L2      : {parsed.src_mac or 'N/A'} -> {parsed.dst_mac or 'N/A'}")
            
            # Layer 3 info
            if parsed.ip_version:
                print(f"  Network L3       : IPv{parsed.ip_version} | {parsed.src_ip} -> {parsed.dst_ip} (TTL/HopLimit: {parsed.ttl})")
            elif parsed.transport_proto == "ARP":
                print(f"  Network L3 (ARP) : Opcode {parsed.arp_op} | {parsed.src_ip} -> {parsed.dst_ip}")
            else:
                print(f"  Network L3       : Non-IP / Unknown")

            # Layer 4 info
            if parsed.transport_proto == "TCP":
                flags_str = ", ".join(parsed.tcp_flags) if parsed.tcp_flags else "NULL (No Flags)"
                print(f"  Transport L4     : TCP | Port {parsed.src_port} -> {parsed.dst_port} | Flags: [{flags_str}] | Seq: {parsed.tcp_seq} | Ack: {parsed.tcp_ack}")
            elif parsed.transport_proto == "UDP":
                print(f"  Transport L4     : UDP | Port {parsed.src_port} -> {parsed.dst_port} | Datagram Len: {parsed.udp_len}")
            elif parsed.transport_proto in ["ICMP", "ICMPv6"]:
                print(f"  Transport L4     : {parsed.transport_proto} | Type: {parsed.icmp_type} | Code: {parsed.icmp_code}")
            else:
                print(f"  Transport L4     : {parsed.transport_proto or 'N/A'}")

            # Layer 7 info
            print(f"  Application L7   : {parsed.app_proto or 'Unclassified / Raw Transport'}")
            print(f"  Fragmented       : {'YES' if parsed.is_fragment else 'NO'}")
            print(f"  Summary          : {parsed.summary}")
            print("-" * 70)

    except KeyboardInterrupt:
        print("\n[!] Capture aborted by user.")

    finally:
        worker.stop_monitoring()

    metrics = worker.get_metrics()
    print("\n" + "=" * 70)
    print(" DEMO SESSION SUMMARY:")
    print("=" * 70)
    print(f"  Packets Parsed   : {parsed_count}/{target_packets}")
    print(f"  Total Captured   : {metrics['total_captured']}")
    print(f"  Total Dequeued   : {metrics['total_dequeued']}")
    print(f"  Capture Runtime  : {metrics['uptime_seconds']}s")
    print(f"  Throughput (PPS) : {metrics['packets_per_second']}")
    print("=" * 70)


if __name__ == "__main__":
    count_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    iface_arg = sys.argv[2] if len(sys.argv) > 2 else None
    run_live_parser_demo(target_packets=count_arg, interface=iface_arg)
