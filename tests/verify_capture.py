"""
Verification script for Scapy packet capture on Windows.
Tests Npcap availability, administrative elevation, and basic packet capture.
"""

import sys
import os
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.network_utils import is_admin, check_npcap_installed, list_network_interfaces, get_default_monitoring_interface


def run_capture_test(interface: str = None, packet_count: int = 5, timeout: int = 5):
    """
    Attempt to capture a small sample of packets using Scapy and print diagnostics.
    """
    print("=" * 65)
    print(" INTELLIGENT NIDS - PHASE 1 PACKET CAPTURE VERIFICATION")
    print("=" * 65)
    
    # 1. Admin privilege check
    admin = is_admin()
    print(f"[*] Step 1: Admin Privileges Check: {'[PASS] Elevated' if admin else '[WARN] Not elevated (Standard User)'}")
    if not admin:
        print("    -> Note: Windows packet capture requires running in an elevated shell ('Run as Administrator').")

    # 2. Npcap driver check
    npcap_info = check_npcap_installed()
    print(f"[*] Step 2: Npcap Driver Check: {'[PASS] Installed' if npcap_info['installed'] else '[FAIL] Missing'}")
    if not npcap_info["installed"]:
        print(f"    -> Action Required: {npcap_info['advice']}")
        print("=" * 65)
        print("[!] Cannot capture packets without Npcap. Please install Npcap and re-run.")
        print("=" * 65)
        return False

    # 3. Import Scapy Sniff
    print("[*] Step 3: Initializing Scapy sniffer engine...")
    try:
        from scapy.all import sniff, conf
    except ImportError as e:
        print(f"[FAIL] Could not import Scapy: {e}")
        return False

    if not interface:
        interface = get_default_monitoring_interface()
    print(f"[*] Target Monitoring Interface: {interface}")

    # 4. Attempt sniff
    print(f"[*] Step 4: Sniffing up to {packet_count} packets (Timeout: {timeout}s)...")
    print("    (Generate some network activity like refreshing a browser page if on Wi-Fi)")
    
    captured_packets = []
    
    def packet_callback(pkt):
        captured_packets.append(pkt)
        summary = pkt.summary()
        print(f"    [Captured #{len(captured_packets)}] {summary}")

    start_time = time.time()
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            count=packet_count,
            timeout=timeout,
            store=False
        )
    except Exception as e:
        print(f"\n[FAIL] Packet capture encountered an exception: {e}")
        print("\nCommon Causes & Solutions:")
        print("  1. Administrative Privileges: Launch terminal using 'Run as Administrator'.")
        print("  2. WinPcap Mode: Reinstall Npcap with 'Install Npcap in WinPcap API-compatible Mode' enabled.")
        print("  3. Interface: Ensure the selected adapter name matches Scapy's Windows interface list.")
        return False

    duration = round(time.time() - start_time, 2)
    print(f"\n[*] Capture finished in {duration}s. Total packets received: {len(captured_packets)}")
    
    if len(captured_packets) > 0:
        print("[SUCCESS] Real-time packet capture is fully functional on this system!")
        print("=" * 65)
        return True
    else:
        print("[WARN] Sniffer timed out without receiving packets.")
        print("       Check that the selected interface has active traffic, or test with ping.")
        print("=" * 65)
        return False


if __name__ == "__main__":
    target_iface = sys.argv[1] if len(sys.argv) > 1 else None
    run_capture_test(interface=target_iface)
