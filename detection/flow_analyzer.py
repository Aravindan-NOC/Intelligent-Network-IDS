"""
Sliding-Window Flow and Velocity Analyzer for Intelligent NIDS.

Maintains stateful sliding windows of network traffic to track host velocity,
connection ratios, unique destination ports, and protocol distributions
without causing unbounded memory growth.
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, Set, Tuple, Any, List, Optional
from core.packet_parser import ParsedPacket


class FlowAnalyzer:
    """
    Sliding-Window Stateful Metric Tracker.

    Tracks network metrics per source IP and across the global network segment
    over configurable rolling time windows (e.g., 2s, 5s). Automatically purges
    expired timestamps to ensure constant memory bounds.
    """

    def __init__(
        self,
        port_scan_window: float = 5.0,
        syn_flood_window: float = 3.0,
        icmp_flood_window: float = 2.0,
        traffic_snapshot_window: float = 5.0,
    ):
        """
        Initialize the FlowAnalyzer with sliding-window time thresholds.

        Args:
            port_scan_window: Seconds to retain destination port history for port scanning.
            syn_flood_window: Seconds to retain SYN/ACK history for SYN flood detection.
            icmp_flood_window: Seconds to retain ICMP history for ICMP flood detection.
            traffic_snapshot_window: Seconds to aggregate overall traffic velocity.
        """
        self.port_scan_window = port_scan_window
        self.syn_flood_window = syn_flood_window
        self.icmp_flood_window = icmp_flood_window
        self.traffic_snapshot_window = traffic_snapshot_window

        # Thread synchronization
        self._lock = threading.Lock()

        # Per-host destination port history: src_ip -> deque of (timestamp, dst_port)
        self._host_ports: Dict[str, deque] = defaultdict(deque)

        # Per-host TCP connection state: src_ip -> deque of (timestamp, is_syn, is_ack)
        self._host_tcp_flags: Dict[str, deque] = defaultdict(deque)

        # Per-host ICMP Echo state: src_ip -> deque of (timestamp, icmp_type)
        self._host_icmp: Dict[str, deque] = defaultdict(deque)

        # Rolling overall traffic velocity: deque of (timestamp, packet_size, transport_proto)
        self._rolling_traffic: deque = deque()

        # Cumulative lifetime counters
        self.total_packets_processed = 0
        self.total_bytes_processed = 0
        self.protocol_counts: Dict[str, int] = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ICMPv6": 0,
            "ARP": 0,
            "OTHER": 0,
        }

    def _purge_old_entries(self, dq: deque, cutoff: float) -> None:
        """Helper to discard entries with timestamp older than cutoff."""
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def update(self, packet: ParsedPacket) -> None:
        """
        Ingest a parsed packet and update sliding-window state.

        Args:
            packet: ParsedPacket instance from core/packet_parser.py.
        """
        if not isinstance(packet, ParsedPacket):
            return

        pkt_time = packet.timestamp
        src_ip = packet.src_ip
        proto = packet.transport_proto or "OTHER"
        pkt_size = packet.packet_size

        with self._lock:
            # 1. Update cumulative and rolling velocity metrics
            self.total_packets_processed += 1
            self.total_bytes_processed += pkt_size
            if proto in self.protocol_counts:
                self.protocol_counts[proto] += 1
            else:
                self.protocol_counts["OTHER"] += 1

            self._rolling_traffic.append((pkt_time, pkt_size, proto))
            self._purge_old_entries(self._rolling_traffic, pkt_time - self.traffic_snapshot_window)

            # If there is no source IP (e.g. pure L2 frame), no host-specific tracking
            if not src_ip:
                return

            # 2. Port Scan Tracking (TCP and UDP destination ports)
            if packet.dst_port is not None:
                host_dq = self._host_ports[src_ip]
                host_dq.append((pkt_time, packet.dst_port))
                self._purge_old_entries(host_dq, pkt_time - self.port_scan_window)

            # 3. SYN Flood Tracking (TCP flags)
            if proto == "TCP":
                flags = packet.tcp_flags
                is_syn = "SYN" in flags and "ACK" not in flags
                is_ack = "ACK" in flags
                if is_syn or is_ack:
                    tcp_dq = self._host_tcp_flags[src_ip]
                    tcp_dq.append((pkt_time, is_syn, is_ack))
                    self._purge_old_entries(tcp_dq, pkt_time - self.syn_flood_window)

            # 4. ICMP Flood Tracking (Echo Request: type 8 for IPv4, type 128 for IPv6)
            if proto in ["ICMP", "ICMPv6"] and packet.icmp_type in [8, 128]:
                icmp_dq = self._host_icmp[src_ip]
                icmp_dq.append((pkt_time, packet.icmp_type))
                self._purge_old_entries(icmp_dq, pkt_time - self.icmp_flood_window)

    def get_distinct_ports(self, src_ip: str, current_time: Optional[float] = None) -> Set[int]:
        """
        Return the set of distinct destination ports targeted by src_ip
        within the port scan sliding window.
        """
        now = current_time or time.time()
        cutoff = now - self.port_scan_window

        with self._lock:
            if src_ip not in self._host_ports:
                return set()
            dq = self._host_ports[src_ip]
            self._purge_old_entries(dq, cutoff)
            if not dq:
                del self._host_ports[src_ip]
                return set()
            return {dst_port for _, dst_port in dq}

    def get_distinct_ports_count(self, src_ip: str, current_time: Optional[float] = None) -> int:
        """Return the count of unique destination ports targeted by src_ip."""
        return len(self.get_distinct_ports(src_ip, current_time))

    def get_syn_ack_stats(
        self, src_ip: str, current_time: Optional[float] = None
    ) -> Tuple[int, int, float, float]:
        """
        Calculate SYN flood metrics for a source host within the syn flood window.

        Returns:
            Tuple of (syn_count, ack_count, syn_pps, syn_ratio).
            - syn_count: Number of pure SYN packets.
            - ack_count: Number of ACK packets.
            - syn_pps: SYN packets per second.
            - syn_ratio: Ratio of SYN to total (SYN + ACK) packets (0.0 to 1.0).
        """
        now = current_time or time.time()
        cutoff = now - self.syn_flood_window

        with self._lock:
            if src_ip not in self._host_tcp_flags:
                return 0, 0, 0.0, 0.0

            dq = self._host_tcp_flags[src_ip]
            self._purge_old_entries(dq, cutoff)
            if not dq:
                del self._host_tcp_flags[src_ip]
                return 0, 0, 0.0, 0.0

            syn_count = sum(1 for _, is_syn, _ in dq if is_syn)
            ack_count = sum(1 for _, _, is_ack in dq if is_ack)

            if len(dq) >= 2:
                duration = max(0.2, dq[-1][0] - dq[0][0])
            else:
                duration = max(0.001, self.syn_flood_window)

            syn_pps = round(syn_count / duration, 2)
            total = syn_count + ack_count
            syn_ratio = round(syn_count / total, 2) if total > 0 else 0.0

            return syn_count, ack_count, syn_pps, syn_ratio

    def get_icmp_stats(
        self, src_ip: str, current_time: Optional[float] = None
    ) -> Tuple[int, float]:
        """
        Calculate ICMP flood metrics for a source host within the ICMP window.

        Returns:
            Tuple of (icmp_echo_count, icmp_pps).
        """
        now = current_time or time.time()
        cutoff = now - self.icmp_flood_window

        with self._lock:
            if src_ip not in self._host_icmp:
                return 0, 0.0

            dq = self._host_icmp[src_ip]
            self._purge_old_entries(dq, cutoff)
            if not dq:
                del self._host_icmp[src_ip]
                return 0, 0.0

            icmp_count = len(dq)
            if len(dq) >= 2:
                duration = max(0.2, dq[-1][0] - dq[0][0])
            else:
                duration = max(0.001, self.icmp_flood_window)

            icmp_pps = round(icmp_count / duration, 2)

            return icmp_count, icmp_pps

    def get_traffic_summary(self, current_time: Optional[float] = None) -> Dict[str, Any]:
        """
        Get rolling velocity and cumulative protocol metrics for SOC charts.

        Returns:
            Dict containing real-time traffic statistics.
        """
        now = current_time or time.time()
        cutoff = now - self.traffic_snapshot_window

        with self._lock:
            self._purge_old_entries(self._rolling_traffic, cutoff)
            rolling_count = len(self._rolling_traffic)
            rolling_bytes = sum(size for _, size, _ in self._rolling_traffic)
            duration = max(0.001, self.traffic_snapshot_window)

            pps = round(rolling_count / duration, 2)
            bps = round((rolling_bytes * 8) / duration, 2)  # bits per second

            return {
                "rolling_window_seconds": self.traffic_snapshot_window,
                "current_pps": pps,
                "current_bps": bps,
                "total_packets": self.total_packets_processed,
                "total_bytes": self.total_bytes_processed,
                "protocol_distribution": dict(self.protocol_counts),
                "active_tracked_hosts": len(self._host_ports),
            }

    def reset(self) -> None:
        """Reset all tracked metrics and sliding windows (useful for testing)."""
        with self._lock:
            self._host_ports.clear()
            self._host_tcp_flags.clear()
            self._host_icmp.clear()
            self._rolling_traffic.clear()
            self.total_packets_processed = 0
            self.total_bytes_processed = 0
            for k in self.protocol_counts:
                self.protocol_counts[k] = 0
