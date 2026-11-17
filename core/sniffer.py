"""
Core Packet Ingestion Engine for Intelligent NIDS.

This module implements the SnifferWorker class, which handles real-time packet capture
using Scapy's AsyncSniffer. It runs independently in a background worker thread and 
transfers captured packets into a thread-safe memory queue (Producer-Consumer architecture)
without blocking or performing heavy operations inside the capture callback.
"""

import logging
import queue
import threading
import time
from typing import Optional, Dict, Any
from scapy.all import AsyncSniffer, Packet
from core.network_utils import resolve_scapy_interface, get_default_monitoring_interface

# Configure module-level logger
logger = logging.getLogger("NIDS.SnifferWorker")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [SnifferWorker] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class SnifferWorker:
    """
    Manages non-blocking real-time packet capture on Windows using Scapy's AsyncSniffer.
    
    Architecture Role: PRODUCER
    - Captures raw Ethernet/IP frames from the selected network interface.
    - Pushes packets immediately into an in-memory thread-safe queue.
    - Operates completely decoupled from the Flask web app and detection engines.
    """

    def __init__(self, interface: Optional[str] = None, max_queue_size: int = 10000, bpf_filter: Optional[str] = None):
        """
        Initialize the SnifferWorker.

        Args:
            interface: Windows interface name (friendly name like 'Wi-Fi' or Npcap GUID).
                       If None, the default active network interface is automatically resolved.
            max_queue_size: Maximum number of packets allowed in memory queue before dropping.
            bpf_filter: Optional Berkeley Packet Filter syntax (e.g. 'ip', 'tcp or udp').
        """
        self.requested_interface = interface
        self.active_interface = None
        self.bpf_filter = bpf_filter
        self.max_queue_size = max_queue_size

        # Thread-safe packet queue (FIFO) shared with downstream consumers
        self.packet_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)

        # Scapy AsyncSniffer instance
        self._sniffer: Optional[AsyncSniffer] = None

        # Thread synchronization and lifecycle state
        self._lock = threading.Lock()
        self._is_running = False

        # Performance & Health Metrics
        self.total_captured = 0
        self.total_dequeued = 0
        self.total_dropped = 0
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self.last_packet_time: Optional[float] = None
        self._last_drop_warning_time = 0.0

    def _packet_callback(self, packet: Packet) -> None:
        """
        Lightweight Scapy callback executed for every captured packet.

        CRITICAL DESIGN RULE:
        This callback MUST remain ultra-lightweight ($O(1)$). Never perform database writes,
        heavy disk I/O, regex matching, or deep ML calculations here. Any delay in this
        callback causes Scapy's socket buffer to overflow, resulting in dropped packets.
        """
        current_time = time.time()
        self.total_captured += 1
        self.last_packet_time = current_time

        try:
            # Enqueue the packet non-blockingly
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            # Queue is full: downstream consumers are too slow. Drop packet and track metrics.
            self.total_dropped += 1
            
            # Rate-limit the warning log to once every 5 seconds to avoid log storming
            if current_time - self._last_drop_warning_time > 5.0:
                logger.warning(
                    f"Packet queue full ({self.packet_queue.qsize()}/{self.max_queue_size})! "
                    f"Dropped {self.total_dropped} packets so far."
                )
                self._last_drop_warning_time = current_time

    def start_monitoring(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None) -> bool:
        """
        Start the background packet capture engine.

        Args:
            interface: Override or specify the target interface.
            bpf_filter: Override or specify the BPF filter.

        Returns:
            bool: True if monitoring started successfully, False otherwise.
        """
        with self._lock:
            # Prevent duplicate instances
            if self._is_running:
                logger.warning("Monitoring is already active! Duplicate start ignored.")
                return False

            if interface:
                self.requested_interface = interface
            if bpf_filter is not None:
                self.bpf_filter = bpf_filter

            # Resolve Windows interface (Friendly name -> Scapy NPF device)
            try:
                resolved_iface = resolve_scapy_interface(self.requested_interface)
                self.active_interface = getattr(resolved_iface, "name", str(resolved_iface))
                logger.info(f"Target network interface resolved: {self.active_interface}")
            except Exception as e:
                logger.error(f"Failed to resolve network interface '{self.requested_interface}': {e}")
                return False

            # Configure and launch Scapy AsyncSniffer
            try:
                logger.info(f"Launching Scapy AsyncSniffer on interface: {self.active_interface}...")
                
                # store=False ensures Scapy does NOT accumulate all packets in memory indefinitely
                self._sniffer = AsyncSniffer(
                    iface=resolved_iface,
                    prn=self._packet_callback,
                    store=False,
                    filter=self.bpf_filter
                )
                
                self._sniffer.start()
                self._is_running = True
                self.start_time = time.time()
                self.stop_time = None
                logger.info("Packet capture engine successfully started in background.")
                return True

            except PermissionError as pe:
                logger.error(f"Permission denied while attaching to network interface: {pe}")
                logger.error("Make sure your terminal / script is running with 'Run as Administrator'.")
                self._sniffer = None
                self._is_running = False
                return False

            except Exception as ex:
                logger.error(f"Failed to initialize packet sniffer: {ex}")
                self._sniffer = None
                self._is_running = False
                return False

    def stop_monitoring(self) -> bool:
        """
        Stop the background packet capture engine cleanly.

        Returns:
            bool: True if monitoring was successfully stopped, False if not running.
        """
        with self._lock:
            if not self._is_running:
                logger.warning("Stop called, but monitoring is not running.")
                return False

            logger.info("Stopping Scapy AsyncSniffer background worker...")
            try:
                if self._sniffer is not None and self._sniffer.running:
                    self._sniffer.stop()
                    logger.info("Scapy sniffer stopped successfully.")
            except Exception as ex:
                logger.error(f"Error occurred while stopping sniffer: {ex}")
            finally:
                self.stop_time = time.time()
                self._is_running = False
                self._sniffer = None

            logger.info(
                f"Monitoring stopped. Total captured: {self.total_captured}, "
                f"Total dequeued: {self.total_dequeued}, Total dropped: {self.total_dropped}, "
                f"Queue items remaining: {self.packet_queue.qsize()}"
            )
            return True

    def get_packet(self, timeout: float = 1.0) -> Optional[Packet]:
        """
        Retrieve the next available packet from the thread-safe queue.
        Used by the downstream analysis worker thread.

        Args:
            timeout: Maximum seconds to wait before returning None.

        Returns:
            Packet object or None if the queue is empty.
        """
        try:
            packet = self.packet_queue.get(timeout=timeout)
            with self._lock:
                self.total_dequeued += 1
            return packet
        except queue.Empty:
            return None

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current operational and performance metrics.
        Thread-safe: accurately computes runtime and PPS both while running
        and after monitoring has been stopped.

        Returns:
            Dict containing real-time capture metrics.
        """
        with self._lock:
            current_time = time.time()
            if self._is_running and self.start_time is not None:
                elapsed = max(0.001, current_time - self.start_time)
            elif self.start_time is not None and self.stop_time is not None:
                elapsed = max(0.001, self.stop_time - self.start_time)
            else:
                elapsed = 0.0

            current_pps = round(self.total_captured / elapsed, 2) if elapsed > 0 else 0.0
            pending = self.packet_queue.qsize()

            return {
                "is_running": self._is_running,
                "active_interface": self.active_interface,
                "queue_size": pending,
                "pending_queue": pending,
                "max_queue_size": self.max_queue_size,
                "total_captured": self.total_captured,
                "total_dequeued": self.total_dequeued,
                "total_dropped": self.total_dropped,
                "packets_per_second": current_pps,
                "uptime_seconds": round(elapsed, 2),
                "start_time": self.start_time,
                "stop_time": self.stop_time,
                "last_packet_time": self.last_packet_time,
            }

    def clear_queue(self) -> int:
        """
        Clear all pending packets from the queue.

        Returns:
            int: Number of cleared packets.
        """
        count = 0
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
                count += 1
            except queue.Empty:
                break
        return count

    @property
    def is_running(self) -> bool:
        """Return True if sniffer is actively capturing packets."""
        return self._is_running
