"""
Network utilities for interface discovery, administrative privilege validation,
and Npcap driver status checking on Windows.
"""

import os
import sys
import ctypes
import psutil
from typing import Dict, List, Optional, Any


def is_admin() -> bool:
    """
    Check if the current script is running with administrative privileges on Windows.
    Returns:
        bool: True if elevated as Administrator, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_npcap_installed() -> Dict[str, Any]:
    """
    Check whether Npcap or WinPcap driver and associated DLLs are present on Windows.
    Returns:
        Dict with status (bool), dll paths found, and diagnostic advice.
    """
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    npcap_dir = os.path.join(system32, "Npcap")
    
    wpcap_system32 = os.path.join(system32, "wpcap.dll")
    wpcap_npcap = os.path.join(npcap_dir, "wpcap.dll")
    packet_system32 = os.path.join(system32, "Packet.dll")
    packet_npcap = os.path.join(npcap_dir, "Packet.dll")
    
    found_dlls = []
    if os.path.exists(wpcap_system32):
        found_dlls.append(wpcap_system32)
    if os.path.exists(wpcap_npcap):
        found_dlls.append(wpcap_npcap)
    if os.path.exists(packet_system32):
        found_dlls.append(packet_system32)
    if os.path.exists(packet_npcap):
        found_dlls.append(packet_npcap)
        
    is_installed = len(found_dlls) > 0

    return {
        "installed": is_installed,
        "found_dlls": found_dlls,
        "advice": (
            "Npcap is operational."
            if is_installed
            else "Npcap is NOT installed. Please download Npcap from https://npcap.com and "
                 "install with 'Install Npcap in WinPcap API-compatible Mode' checked."
        )
    }


def list_network_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerate all network interfaces on the system using psutil.
    Provides friendly names, IPv4, IPv6, MAC addresses, and operational status.
    
    Returns:
        List of dictionaries detailing each interface.
    """
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface_name, addr_list in addrs.items():
        iface_info = {
            "name": iface_name,
            "ipv4": [],
            "ipv6": [],
            "mac": None,
            "is_up": False,
            "speed_mbps": 0,
            "is_loopback": "loopback" in iface_name.lower(),
            "is_virtual": any(v in iface_name.lower() for v in ["virtual", "tap", "wintun", "vethernet"])
        }

        # Query stats
        if iface_name in stats:
            stat = stats[iface_name]
            iface_info["is_up"] = stat.isup
            iface_info["speed_mbps"] = stat.speed

        # Parse addresses
        for addr in addr_list:
            # Address family values: AF_INET=2, AF_INET6=23 or 30, AF_LINK=-1
            family_name = str(addr.family)
            if "AF_INET6" in family_name or getattr(addr.family, "name", "") == "AF_INET6":
                # Strip scope id if present
                clean_ip = addr.address.split("%")[0]
                iface_info["ipv6"].append(clean_ip)
            elif "AF_INET" in family_name or getattr(addr.family, "name", "") == "AF_INET":
                iface_info["ipv4"].append(addr.address)
            elif "AF_LINK" in family_name or getattr(addr.family, "name", "") == "AF_LINK":
                iface_info["mac"] = addr.address

        interfaces.append(iface_info)

    return interfaces


def get_default_monitoring_interface() -> Optional[str]:
    """
    Automatically pick the best active interface for real network monitoring.
    Prefers the active interface matching the system default gateway (lowest metric).
    """
    # Attempt to resolve via Scapy routing table first
    try:
        from scapy.all import conf
        # Find default route (destination 0.0.0.0) with lowest metric
        default_routes = []
        for route in conf.route.routes:
            dest, netmask, gw, iface, out_ip, metric = route
            if dest == 0 and netmask == 0 and gw != "0.0.0.0":
                default_routes.append((metric, iface, out_ip))
        
        if default_routes:
            default_routes.sort(key=lambda x: x[0])  # sort by lowest metric
            best_iface = default_routes[0][1]
            return getattr(best_iface, "name", str(best_iface))
    except Exception:
        pass

    # Fallback via psutil
    interfaces = list_network_interfaces()
    for iface in interfaces:
        if iface["is_up"] and not iface["is_loopback"] and not iface["is_virtual"]:
            if "wi-fi" in iface["name"].lower() or "wireless" in iface["name"].lower():
                return iface["name"]

    for iface in interfaces:
        if iface["is_up"] and not iface["is_loopback"] and not iface["is_virtual"]:
            for ip in iface["ipv4"]:
                if not ip.startswith("169.254.") and ip != "127.0.0.1":
                    return iface["name"]

    return None


def resolve_scapy_interface(target_name: Optional[str] = None) -> Any:
    """
    Resolve a user-provided interface name (e.g., 'Wi-Fi', 'Ethernet', 'Loopback', GUID)
    to a valid Scapy-compatible interface identifier.

    Args:
        target_name: User-provided interface name, friendly name, or None for auto-detect.

    Returns:
        Scapy interface object or string identifier ready for AsyncSniffer(iface=...).
    """
    try:
        from scapy.all import conf
    except ImportError:
        return target_name

    explicit_request = bool(target_name)
    if not target_name:
        default_iface = get_default_monitoring_interface()
        target_name = default_iface if default_iface else conf.iface

    target_str = str(target_name).strip()
    target_lower = target_str.lower()

    # 1. Exact match on Scapy interface keys or attributes
    for dev_name, iface in conf.ifaces.items():
        if (target_lower == dev_name.lower() or
            target_lower == getattr(iface, "name", "").lower() or
            target_lower == getattr(iface, "win_name", "").lower() or
            target_lower == getattr(iface, "guid", "").lower()):
            return iface

    # 2. Substring match (e.g. 'loopback' in '\Device\NPF_Loopback')
    for dev_name, iface in conf.ifaces.items():
        if (target_lower in dev_name.lower() or
            target_lower in getattr(iface, "name", "").lower() or
            target_lower in getattr(iface, "description", "").lower()):
            return iface

    # 3. Match via IP address mapping from psutil
    try:
        addrs = psutil.net_if_addrs()
        if target_str in addrs:
            ips = [a.address for a in addrs[target_str] if str(a.family) in ["2", "AddressFamily.AF_INET", "AF_INET"]]
            if ips:
                target_ip = ips[0]
                for dev_name, iface in conf.ifaces.items():
                    if getattr(iface, "ip", None) == target_ip:
                        return iface
    except Exception:
        pass

    # 4. Fallback: If not explicitly requested by user and target could not be matched,
    # fall back to Scapy's default interface (conf.iface)
    if not explicit_request and getattr(conf, "iface", None) is not None:
        return conf.iface

    return target_name if target_name else conf.iface


if __name__ == "__main__":
    print("=" * 60)
    print(" INTELLIGENT NIDS - WINDOWS ENVIRONMENT & INTERFACE AUDIT")
    print("=" * 60)
    
    admin_status = is_admin()
    print(f"[*] Windows Administrator Privilege: {'[YES] ELEVATED' if admin_status else '[NO] STANDARD USER'}")
    
    npcap_status = check_npcap_installed()
    print(f"[*] Npcap Driver Status: {'[FOUND]' if npcap_status['installed'] else '[MISSING]'}")
    if npcap_status["found_dlls"]:
        for dll in npcap_status["found_dlls"]:
            print(f"    - Located: {dll}")
    else:
        print(f"    ! Advice: {npcap_status['advice']}")

    print("\n[*] Detected Network Interfaces:")
    ifaces = list_network_interfaces()
    for idx, iface in enumerate(ifaces, 1):
        status_flag = "UP" if iface["is_up"] else "DOWN"
        ips = ", ".join(iface["ipv4"]) if iface["ipv4"] else "No IPv4"
        print(f"  {idx:2d}. [{status_flag:4s}] {iface['name']:<28} | MAC: {str(iface['mac']):<17} | IP: {ips}")

    recommended = get_default_monitoring_interface()
    print(f"\n[*] Recommended Default Interface: {recommended}")
    print("=" * 60)
