"""
Flow Feature Extraction Pipeline for ML Anomaly Detection.

Transforms raw parsed packet streams and flow windows into standardized
numerical feature vectors for unsupervised Isolation Forest anomaly detection.
"""

import math
from collections import Counter
from typing import List, Dict, Any, Optional
from core.packet_parser import ParsedPacket

FEATURE_NAMES = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "pps",
    "bps",
    "avg_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "unique_dst_ports",
    "port_entropy",
]


class FlowFeatureExtractor:
    """
    Extracts statistical, behavioral, and protocol distribution features
    from a window of network packets originating from or destined to an IP.
    """

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feature_names = feature_names or FEATURE_NAMES

    def extract_features_from_packets(
        self,
        packets: List[ParsedPacket],
        window_duration: Optional[float] = None,
    ) -> Dict[str, float]:
        """
        Extract numerical features from a list of ParsedPacket objects.

        :param packets: List of ParsedPacket objects observed in the flow window.
        :param window_duration: Optional known window duration in seconds.
        :return: Dict mapping feature names to numerical values.
        """
        if not packets:
            return {name: 0.0 for name in self.feature_names}

        packet_count = len(packets)
        byte_count = sum(getattr(p, "packet_size", getattr(p, "packet_length", 0)) or 0 for p in packets)

        # Calculate time duration
        timestamps = [p.timestamp for p in packets if getattr(p, "timestamp", None) is not None]
        if timestamps:
            duration = max(timestamps) - min(timestamps)
        else:
            duration = 0.0

        if window_duration is not None and window_duration > 0:
            effective_duration = max(window_duration, 0.05)
        else:
            effective_duration = max(duration, 0.05)

        pps = packet_count / effective_duration
        bps = (byte_count * 8.0) / effective_duration
        avg_packet_size = byte_count / max(packet_count, 1)

        # Protocol counts
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        syn_count = 0
        ack_count = 0
        rst_count = 0
        dst_ports = []

        for p in packets:
            proto = (getattr(p, "transport_proto", getattr(p, "protocol", "")) or "").upper()
            if proto == "TCP":
                tcp_count += 1
                flags = getattr(p, "tcp_flags", [])
                if isinstance(flags, (list, tuple, set)):
                    if "SYN" in flags:
                        syn_count += 1
                    if "ACK" in flags:
                        ack_count += 1
                    if "RST" in flags:
                        rst_count += 1
                elif isinstance(flags, dict):
                    if flags.get("SYN", False):
                        syn_count += 1
                    if flags.get("ACK", False):
                        ack_count += 1
                    if flags.get("RST", False):
                        rst_count += 1
            elif proto == "UDP":
                udp_count += 1
            elif proto in ("ICMP", "ICMPV6"):
                icmp_count += 1

            dport = getattr(p, "dst_port", getattr(p, "destination_port", None))
            if dport is not None:
                dst_ports.append(dport)

        # Ratios
        tcp_ratio = tcp_count / packet_count
        udp_ratio = udp_count / packet_count
        icmp_ratio = icmp_count / packet_count

        syn_ratio = syn_count / max(tcp_count, 1)
        ack_ratio = ack_count / max(tcp_count, 1)
        rst_ratio = rst_count / max(tcp_count, 1)

        # Unique destination ports and Shannon Entropy
        unique_dst_ports = len(set(dst_ports))
        port_entropy = self._calculate_entropy(dst_ports)

        return {
            "flow_duration": round(float(effective_duration), 4),
            "packet_count": float(packet_count),
            "byte_count": float(byte_count),
            "pps": round(float(pps), 2),
            "bps": round(float(bps), 2),
            "avg_packet_size": round(float(avg_packet_size), 2),
            "tcp_ratio": round(float(tcp_ratio), 4),
            "udp_ratio": round(float(udp_ratio), 4),
            "icmp_ratio": round(float(icmp_ratio), 4),
            "syn_ratio": round(float(syn_ratio), 4),
            "ack_ratio": round(float(ack_ratio), 4),
            "rst_ratio": round(float(rst_ratio), 4),
            "unique_dst_ports": float(unique_dst_ports),
            "port_entropy": round(float(port_entropy), 4),
        }

    def to_vector(self, feature_dict: Dict[str, float]) -> List[float]:
        """Convert feature dictionary into an ordered list of floats matching FEATURE_NAMES."""
        return [float(feature_dict.get(name, 0.0)) for name in self.feature_names]

    @staticmethod
    def _calculate_entropy(values: List[Any]) -> float:
        """Calculate Shannon entropy for a discrete distribution."""
        if not values:
            return 0.0
        total = len(values)
        counts = Counter(values)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
