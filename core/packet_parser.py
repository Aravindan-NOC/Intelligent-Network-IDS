"""
Packet Parsing and Protocol Dissection Engine for Intelligent NIDS.

This module decodes raw Scapy packets into a standardized, lightweight ParsedPacket
data structure. It extracts Layer 2 (Ethernet), Layer 3 (IPv4/IPv6), Layer 4
(TCP/UDP/ICMP/ARP), and identifies common Layer 7 application protocols without
retaining raw sensitive payloads in memory.
"""

import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple
from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, _ICMPv6

# Module-level logger
logger = logging.getLogger("NIDS.PacketParser")

# Standard TCP Flag Bitmasks (RFC 793, RFC 3168, RFC 3540)
TCP_FLAG_MASKS: List[Tuple[int, str]] = [
    (0x001, "FIN"),
    (0x002, "SYN"),
    (0x004, "RST"),
    (0x008, "PSH"),
    (0x010, "ACK"),
    (0x020, "URG"),
    (0x040, "ECE"),
    (0x080, "CWR"),
    (0x100, "NS"),
]

# Configurable Port-to-Application Protocol Mapping
PORT_PROTOCOL_MAP: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    88: "KERBEROS",
    110: "POP3",
    123: "NTP",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUBMISSION",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5060: "SIP",
    5353: "MDNS",
    5432: "POSTGRESQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-PROXY",
}


@dataclass
class ParsedPacket:
    """
    Standardized, lightweight representation of an analyzed network packet.
    
    Contains decoded protocol headers across Layers 2-4 and application hints.
    Deliberately excludes raw packet payloads to maintain privacy, reduce memory
    overhead, and adhere to cybersecurity operational standards.
    """
    # Metadata
    timestamp: float
    packet_size: int

    # Layer 2 - Ethernet
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ether_type: Optional[int] = None

    # Layer 3 - Network (IPv4 / IPv6)
    ip_version: Optional[int] = None      # 4 or 6
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None             # Time to Live (IPv4) or Hop Limit (IPv6)
    ip_len: Optional[int] = None          # Total IP packet length
    ip_proto: Optional[int] = None        # Protocol number (e.g., 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)
    is_fragment: bool = False             # True if packet is fragmented

    # Layer 4 - Transport / Link Resolution
    transport_proto: Optional[str] = None # 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'OTHER'
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP Specific Fields
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None
    tcp_flags: List[str] = field(default_factory=list)
    tcp_flags_hex: Optional[int] = None

    # UDP Specific Fields
    udp_len: Optional[int] = None

    # ICMP / ICMPv6 Specific Fields
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # ARP Specific Fields
    arp_op: Optional[int] = None          # 1 = Request, 2 = Reply
    arp_src_ip: Optional[str] = None
    arp_dst_ip: Optional[str] = None
    arp_src_mac: Optional[str] = None
    arp_dst_mac: Optional[str] = None

    # Layer 7 - Application Protocol
    app_proto: Optional[str] = None

    # Human-readable summary
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the ParsedPacket object into a Python dictionary.
        Suitable for JSON serialization, database inserts, and dashboard feeds.
        """
        return asdict(self)


def extract_tcp_flags(flags_val: Any) -> Tuple[List[str], int]:
    """
    Extract individual TCP flag names from a Scapy FlagValue or integer.

    Args:
        flags_val: Raw flag value from packet[TCP].flags (FlagValue, int, or str).

    Returns:
        Tuple of (list of flag names, integer bitmask).
    """
    try:
        flags_int = int(flags_val)
    except (ValueError, TypeError):
        flags_int = 0

    flag_names = [name for mask, name in TCP_FLAG_MASKS if flags_int & mask]
    return flag_names, flags_int


def identify_app_protocol(
    src_port: Optional[int],
    dst_port: Optional[int],
    port_map: Optional[Dict[int, str]] = None
) -> Optional[str]:
    """
    Identify common application protocols using port heuristics.

    Args:
        src_port: Source transport port.
        dst_port: Destination transport port.
        port_map: Optional custom port mapping dictionary.

    Returns:
        Protocol string (e.g., 'HTTPS', 'DNS') or None if unmapped.
    """
    mapping = port_map if port_map is not None else PORT_PROTOCOL_MAP

    # Destination port usually indicates the service for outgoing client requests
    if dst_port is not None and dst_port in mapping:
        return mapping[dst_port]
    # Source port indicates the service for incoming server responses
    if src_port is not None and src_port in mapping:
        return mapping[src_port]

    return None


def parse_packet(
    packet: Any,
    port_map: Optional[Dict[int, str]] = None
) -> Optional[ParsedPacket]:
    """
    Dissect a raw Scapy packet into a standardized ParsedPacket dataclass.

    Defensive Parsing Guarantees:
    - Never modifies the original Scapy packet.
    - Gracefully handles missing layers, malformed frames, and non-IP traffic.
    - Never raises unhandled exceptions to downstream consumers.
    - Omits raw payloads to protect privacy and optimize performance.

    Args:
        packet: Scapy Packet object or raw frame.
        port_map: Optional custom port dictionary for application identification.

    Returns:
        ParsedPacket instance, or None if the packet cannot be processed.
    """
    if not isinstance(packet, Packet):
        logger.debug("Provided object is not a valid Scapy Packet instance.")
        return None

    try:
        # 1. Packet Metadata
        pkt_time = float(getattr(packet, "time", time.time()))
        pkt_len = len(packet)
        pkt_summary = packet.summary()

        parsed = ParsedPacket(
            timestamp=pkt_time,
            packet_size=pkt_len,
            summary=pkt_summary
        )

        # 2. Layer 2: Ethernet Header
        if packet.haslayer(Ether):
            eth = packet[Ether]
            parsed.src_mac = getattr(eth, "src", None)
            parsed.dst_mac = getattr(eth, "dst", None)
            parsed.ether_type = getattr(eth, "type", None)

        # 3. Layer 3: ARP Protocol
        if packet.haslayer(ARP):
            arp = packet[ARP]
            parsed.transport_proto = "ARP"
            parsed.arp_op = getattr(arp, "op", None)
            parsed.arp_src_ip = getattr(arp, "psrc", None)
            parsed.arp_dst_ip = getattr(arp, "pdst", None)
            parsed.arp_src_mac = getattr(arp, "hwsrc", None)
            parsed.arp_dst_mac = getattr(arp, "hwdst", None)
            # Map IPs for unified query capability
            parsed.src_ip = parsed.arp_src_ip
            parsed.dst_ip = parsed.arp_dst_ip

        # 4. Layer 3: IPv4 Header
        elif packet.haslayer(IP):
            ip = packet[IP]
            parsed.ip_version = 4
            parsed.src_ip = getattr(ip, "src", None)
            parsed.dst_ip = getattr(ip, "dst", None)
            parsed.ttl = getattr(ip, "ttl", None)
            parsed.ip_len = getattr(ip, "len", pkt_len)
            parsed.ip_proto = getattr(ip, "proto", None)

            # Fragmentation detection in IPv4: MF bit set or Fragment offset > 0
            flags_int = int(getattr(ip, "flags", 0))
            frag_offset = getattr(ip, "frag", 0)
            parsed.is_fragment = (bool(flags_int & 1) or frag_offset > 0)

        # 5. Layer 3: IPv6 Header
        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            parsed.ip_version = 6
            parsed.src_ip = getattr(ip6, "src", None)
            parsed.dst_ip = getattr(ip6, "dst", None)
            parsed.ttl = getattr(ip6, "hlim", None)  # Hop Limit
            plen = getattr(ip6, "plen", None)
            parsed.ip_len = (plen + 40) if plen is not None else pkt_len
            parsed.ip_proto = getattr(ip6, "nh", None)  # Next Header

            # Fragmentation in IPv6 is indicated by the presence of IPv6ExtHdrFragment
            parsed.is_fragment = packet.haslayer(IPv6ExtHdrFragment)

        # 6. Layer 4: TCP Protocol
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            parsed.transport_proto = "TCP"
            parsed.src_port = getattr(tcp, "sport", None)
            parsed.dst_port = getattr(tcp, "dport", None)
            parsed.tcp_seq = getattr(tcp, "seq", None)
            parsed.tcp_ack = getattr(tcp, "ack", None)
            parsed.tcp_window = getattr(tcp, "window", None)

            # Dissect TCP flags
            raw_flags = getattr(tcp, "flags", 0)
            flag_list, flag_hex = extract_tcp_flags(raw_flags)
            parsed.tcp_flags = flag_list
            parsed.tcp_flags_hex = flag_hex

            # App protocol classification
            parsed.app_proto = identify_app_protocol(parsed.src_port, parsed.dst_port, port_map)

        # 7. Layer 4: UDP Protocol
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            parsed.transport_proto = "UDP"
            parsed.src_port = getattr(udp, "sport", None)
            parsed.dst_port = getattr(udp, "dport", None)
            parsed.udp_len = getattr(udp, "len", None)

            # App protocol classification
            parsed.app_proto = identify_app_protocol(parsed.src_port, parsed.dst_port, port_map)

        # 8. Layer 4: ICMP (IPv4)
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            parsed.transport_proto = "ICMP"
            parsed.icmp_type = getattr(icmp, "type", None)
            parsed.icmp_code = getattr(icmp, "code", None)

        # 9. Layer 4: ICMPv6 (IPv6)
        elif parsed.ip_version == 6:
            # Check for any ICMPv6 class or subclass in packet layers
            for layer_cls in packet.layers():
                if issubclass(layer_cls, _ICMPv6) or "icmpv6" in layer_cls.__name__.lower():
                    icmpv6_layer = packet[layer_cls]
                    parsed.transport_proto = "ICMPv6"
                    parsed.icmp_type = getattr(icmpv6_layer, "type", None)
                    parsed.icmp_code = getattr(icmpv6_layer, "code", None)
                    break

        # Fallback for other non-TCP/UDP/ICMP/ARP transport layers
        if parsed.transport_proto is None and (parsed.ip_version is not None):
            parsed.transport_proto = "OTHER"

        return parsed

    except Exception as ex:
        logger.warning(f"Error parsing packet: {ex}", exc_info=False)
        return None
