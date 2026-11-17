"""
Live Real-Time Packet Capture Demonstration Script.
Tests the SnifferWorker against real live traffic.
"""

import os
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.sniffer import SnifferWorker
from core.network_utils import is_admin, list_network_interfaces


def run_live_sniffer_demo(duration: int = 10, interface: str = None):
    print("=" * 65)
    print(" INTELLIGENT NIDS - LIVE SNIFFER DEMO")
    print("=" * 65)
    
    admin = is_admin()
    print(f"[*] Windows Administrator Privilege: {'[YES] Elevated' if admin else '[WARN] Standard User'}")
    if not admin:
        print("[!] Note: If packet capture fails, re-launch your terminal as Administrator.")

    print(f"[*] Initializing SnifferWorker (Queue capacity: 5000)...")
    worker = SnifferWorker(interface=interface, max_queue_size=5000)

    print(f"[*] Starting background capture for {duration} seconds...")
    success = worker.start_monitoring()
    if not success:
        print("[FAIL] Could not start packet capture.")
        return

    print(f"[*] Monitoring active on: {worker.active_interface}")
    print("[*] Generating / Listening for network traffic... (Press Ctrl+C to abort)\n")

    packets_dequeued = 0
    start_time = time.time()

    try:
        while time.time() - start_time < duration:
            # Poll and dequeue up to 5 packets each cycle
            for _ in range(5):
                pkt = worker.get_packet(timeout=0.1)
                if pkt is not None:
                    packets_dequeued += 1
                    print(f"  [#{packets_dequeued:03d}] {pkt.summary()}")
                else:
                    break

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[!] User interrupted capture.")

    print("\n[*] Stopping sniffer worker...")
    worker.stop_monitoring()

    metrics = worker.get_metrics()
    print("\n" + "=" * 65)
    print(" FINAL SNIFFER METRICS:")
    print("=" * 65)
    print(f"  Active Interface   : {metrics['active_interface']}")
    print(f"  Total Captured     : {metrics['total_captured']}")
    print(f"  Total Dequeued     : {metrics['total_dequeued']}")
    print(f"  Dropped (Full Q)   : {metrics['total_dropped']}")
    print(f"  Pending in Queue   : {metrics['pending_queue']}")
    print(f"  Packets Per Second : {metrics['packets_per_second']}")
    print(f"  Runtime (Seconds)  : {metrics['uptime_seconds']}s")
    print("=" * 65)


if __name__ == "__main__":
    duration_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    iface_arg = sys.argv[2] if len(sys.argv) > 2 else None
    run_live_sniffer_demo(duration=duration_arg, interface=iface_arg)
