"""
Rule-Based Intrusion Detection Engine for Intelligent NIDS.

Implements real-time signature and heuristic detection for:
1. Port Scanning (Volumetric threshold + Stealth Xmas/Null/SYN+FIN scans)
2. SYN Flood (Half-open connection ratios and PPS spikes)
3. ICMP Flood (Echo Request burst rates)
4. Suspicious Traffic (High-risk exploit ports and RFC flag violations)
"""

import logging
from typing import List, Optional, Dict, Any, Set
from core.packet_parser import ParsedPacket
from detection.flow_analyzer import FlowAnalyzer
from detection.alert_manager import AlertManager, SecurityAlert

logger = logging.getLogger("NIDS.RuleEngine")


class RuleEngine:
    """
    Signature and Stateful Heuristic Intrusion Detection Engine.
    """

    def __init__(
        self,
        flow_analyzer: Optional[FlowAnalyzer] = None,
        alert_manager: Optional[AlertManager] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the RuleEngine.

        Args:
            flow_analyzer: FlowAnalyzer instance for stateful velocity queries.
            alert_manager: AlertManager instance for alert logging and deduplication.
            config: Optional configuration dictionary overriding default thresholds.
        """
        self.flow_analyzer = flow_analyzer or FlowAnalyzer()
        self.alert_manager = alert_manager or AlertManager()

        # Detection Threshold Defaults
        cfg = config or {}
        self.port_scan_threshold = cfg.get("PORT_SCAN_THRESHOLD", 15)
        self.port_scan_window = cfg.get("PORT_SCAN_WINDOW_SECONDS", 5.0)

        self.syn_flood_pps = cfg.get("SYN_FLOOD_PPS_THRESHOLD", 50)
        self.syn_flood_ratio = cfg.get("SYN_FLOOD_RATIO_THRESHOLD", 0.80)
        self.syn_min_packets = cfg.get("SYN_FLOOD_MIN_PACKETS", 20)

        self.icmp_flood_pps = cfg.get("ICMP_FLOOD_PPS_THRESHOLD", 40)
        self.icmp_min_packets = cfg.get("ICMP_FLOOD_MIN_PACKETS", 20)

        self.suspicious_ports: Dict[int, str] = cfg.get(
            "SUSPICIOUS_PORTS",
            {
                4444: "Metasploit Default Payload Listener",
                31337: "Back Orifice Trojan Port",
                1337: "Common Hacker / Exploit Shell Port",
                6667: "IRC Botnet Command & Control",
                8888: "Suspicious HTTP Alternative / C2 Proxy",
                5555: "Android ADB Remote Debugging Exploit",
            },
        )

    def evaluate_packet(self, packet: ParsedPacket) -> List[SecurityAlert]:
        """
        Analyze a parsed packet through all intrusion detection rules.

        1. Ingests packet into FlowAnalyzer to update stateful sliding windows.
        2. Evaluates immediate packet-level rules (Stealth scans, suspicious ports, illegal flags).
        3. Evaluates stateful rate-based rules (Volumetric port scans, SYN floods, ICMP floods).
        4. Dispatches any breaches to AlertManager.

        Returns:
            List of generated SecurityAlert objects (if any).
        """
        if not isinstance(packet, ParsedPacket) or not packet.src_ip:
            return []

        # 1. Update sliding window flow metrics
        self.flow_analyzer.update(packet)

        alerts_triggered: List[SecurityAlert] = []
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip or "0.0.0.0"
        proto = packet.transport_proto or "OTHER"
        dst_port = packet.dst_port
        pkt_time = packet.timestamp

        # =====================================================================
        # RULE 1: PORT SCANNING DETECTION
        # =====================================================================
        if proto == "TCP":
            flags = packet.tcp_flags

            # 1A. Stealth Xmas Scan (FIN, PSH, URG all set)
            if "FIN" in flags and "PSH" in flags and "URG" in flags:
                alert, is_new = self.alert_manager.record_alert(
                    attack_type="Port Scan",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    source_port=packet.src_port,
                    destination_port=dst_port,
                    description=f"Stealth TCP Xmas Scan detected (Flags: FIN+PSH+URG) targeting port {dst_port}",
                    mitigation_tip="Block attacker IP at firewall. Check if host was probed with Nmap -sX.",
                    timestamp=pkt_time,
                )
                if is_new:
                    alerts_triggered.append(alert)

            # 1B. Stealth Null Scan (No flags set)
            elif len(flags) == 0:
                alert, is_new = self.alert_manager.record_alert(
                    attack_type="Port Scan",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    source_port=packet.src_port,
                    destination_port=dst_port,
                    description=f"Stealth TCP Null Scan detected (Empty TCP Flags) targeting port {dst_port}",
                    mitigation_tip="Drop packets with no flags set via firewall rule. Common Nmap -sN reconnaissance.",
                    timestamp=pkt_time,
                )
                if is_new:
                    alerts_triggered.append(alert)

            # 1C. Illegal SYN + FIN Scan
            elif "SYN" in flags and "FIN" in flags:
                alert, is_new = self.alert_manager.record_alert(
                    attack_type="Port Scan",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    source_port=packet.src_port,
                    destination_port=dst_port,
                    description=f"Illegal SYN+FIN scan packet detected targeting port {dst_port}",
                    mitigation_tip="Drop malformed TCP flag combinations. Common signature of IDS evasion tools.",
                    timestamp=pkt_time,
                )
                if is_new:
                    alerts_triggered.append(alert)

        # 1D. Volumetric Port Scan (High number of distinct ports visited within sliding window)
        distinct_ports = self.flow_analyzer.get_distinct_ports(src_ip, current_time=pkt_time)
        if len(distinct_ports) >= self.port_scan_threshold:
            alert, is_new = self.alert_manager.record_alert(
                attack_type="Port Scan",
                severity="HIGH",
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=proto,
                source_port=packet.src_port,
                destination_port=dst_port,
                description=(
                    f"Rapid Port Scan detected: Host contacted {len(distinct_ports)} distinct ports "
                    f"within {self.port_scan_window}s window"
                ),
                mitigation_tip="Enforce firewall connection limits and consider temporary IP blacklisting.",
                timestamp=pkt_time,
            )
            if is_new:
                alerts_triggered.append(alert)

        # =====================================================================
        # RULE 2: SYN FLOOD DETECTION
        # =====================================================================
        if proto == "TCP":
            syn_count, ack_count, syn_pps, syn_ratio = self.flow_analyzer.get_syn_ack_stats(
                src_ip, current_time=pkt_time
            )

            # Trigger condition: high SYN arrival rate OR high SYN/ACK ratio with sufficient volume OR high burst volume
            if (syn_pps >= self.syn_flood_pps) or (
                syn_count >= self.syn_min_packets and syn_ratio >= self.syn_flood_ratio
            ) or (syn_count >= 35):
                alert, is_new = self.alert_manager.record_alert(
                    attack_type="SYN Flood",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    source_port=packet.src_port,
                    destination_port=dst_port,
                    description=(
                        f"TCP SYN Flood in progress: {syn_count} half-open SYNs ({syn_pps} pps, "
                        f"SYN ratio: {int(syn_ratio * 100)}%)"
                    ),
                    mitigation_tip="Enable SYN cookies (net.ipv4.tcp_syncookies=1) and rate-limit TCP SYN arrival.",
                    timestamp=pkt_time,
                )
                if is_new:
                    alerts_triggered.append(alert)

        # =====================================================================
        # RULE 3: ICMP FLOOD DETECTION
        # =====================================================================
        if proto in ["ICMP", "ICMPv6"]:
            icmp_count, icmp_pps = self.flow_analyzer.get_icmp_stats(src_ip, current_time=pkt_time)
            if (icmp_pps >= self.icmp_flood_pps) or (icmp_count >= self.icmp_min_packets):
                alert, is_new = self.alert_manager.record_alert(
                    attack_type="ICMP Flood",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=proto,
                    source_port=packet.src_port,
                    destination_port=dst_port,
                    description=(
                        f"ICMP Ping Flood detected: {icmp_count} Echo Requests ({icmp_pps} pps) "
                        f"within {self.flow_analyzer.icmp_flood_window}s"
                    ),
                    mitigation_tip="Throttle or drop ICMP Echo Requests at the perimeter router or local firewall.",
                    timestamp=pkt_time,
                )
                if is_new:
                    alerts_triggered.append(alert)

        # =====================================================================
        # RULE 4: SUSPICIOUS TRAFFIC DETECTION
        # =====================================================================
        # 4A. Well-known Backdoor / Exploit Ports
        if dst_port is not None and dst_port in self.suspicious_ports:
            threat_name = self.suspicious_ports[dst_port]
            alert, is_new = self.alert_manager.record_alert(
                attack_type="Suspicious Traffic",
                severity="MEDIUM",
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=proto,
                source_port=packet.src_port,
                destination_port=dst_port,
                description=f"Traffic directed to known high-risk/exploit port {dst_port} ({threat_name})",
                mitigation_tip=f"Investigate process listening on port {dst_port}. Ensure service is legitimate.",
                timestamp=pkt_time,
            )
            if is_new:
                alerts_triggered.append(alert)

        # 4B. Illegal Flag Combination: SYN + RST
        if proto == "TCP" and "SYN" in packet.tcp_flags and "RST" in packet.tcp_flags:
            alert, is_new = self.alert_manager.record_alert(
                attack_type="Suspicious Traffic",
                severity="MEDIUM",
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol="TCP",
                source_port=packet.src_port,
                destination_port=dst_port,
                description=f"Illegal TCP flag combination (SYN+RST) detected targeting port {dst_port}",
                mitigation_tip="RFC 793 violation. Typically indicative of port knocking, scanner evasion, or OS fingerprinting.",
                timestamp=pkt_time,
            )
            if is_new:
                alerts_triggered.append(alert)

        return alerts_triggered
