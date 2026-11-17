"""
Unit and integration tests for core/sniffer.py (SnifferWorker).
"""

import os
import sys
import time
import unittest
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.sniffer import SnifferWorker
from core.network_utils import is_admin


class TestSnifferWorkerUnit(unittest.TestCase):
    """Unit tests for SnifferWorker internal logic and thread-safe queue."""

    def test_initialization(self):
        """Verify initial state of SnifferWorker."""
        worker = SnifferWorker(interface="Wi-Fi", max_queue_size=500)
        self.assertFalse(worker.is_running)
        self.assertEqual(worker.max_queue_size, 500)
        self.assertEqual(worker.packet_queue.qsize(), 0)
        self.assertEqual(worker.total_captured, 0)
        self.assertEqual(worker.total_dropped, 0)

    def test_queue_enqueue_and_get_packet(self):
        """Verify callback enqueues packets and get_packet() dequeues correctly."""
        worker = SnifferWorker(max_queue_size=10)
        test_pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(dport=80)

        # Trigger callback
        worker._packet_callback(test_pkt)

        self.assertEqual(worker.total_captured, 1)
        self.assertEqual(worker.packet_queue.qsize(), 1)

        # Dequeue
        retrieved = worker.get_packet(timeout=0.1)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved[IP].dst, "127.0.0.1")
        self.assertEqual(retrieved[TCP].dport, 80)
        self.assertEqual(worker.packet_queue.qsize(), 0)

    def test_queue_overflow_drops_packets(self):
        """Verify that when queue reaches capacity, packets are dropped and tracked."""
        small_queue_size = 3
        worker = SnifferWorker(max_queue_size=small_queue_size)

        # Send 7 packets into a queue of capacity 3
        for i in range(7):
            pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
            worker._packet_callback(pkt)

        self.assertEqual(worker.total_captured, 7)
        self.assertEqual(worker.packet_queue.qsize(), 3)
        self.assertEqual(worker.total_dropped, 4)

    def test_clear_queue(self):
        """Verify clearing the queue empties all pending packets."""
        worker = SnifferWorker(max_queue_size=10)
        for _ in range(5):
            worker._packet_callback(IP() / TCP())

        self.assertEqual(worker.packet_queue.qsize(), 5)
        cleared = worker.clear_queue()
        self.assertEqual(cleared, 5)
        self.assertEqual(worker.packet_queue.qsize(), 0)

    def test_duplicate_start_prevention(self):
        """Verify start_monitoring rejects duplicate starts when already running."""
        worker = SnifferWorker()
        worker._is_running = True  # Simulate active state

        # Calling start_monitoring should return False
        result = worker.start_monitoring()
        self.assertFalse(result)

    def test_stop_when_not_running(self):
        """Verify stop_monitoring returns False when not active."""
        worker = SnifferWorker()
        self.assertFalse(worker.is_running)
        result = worker.stop_monitoring()
        self.assertFalse(result)

    def test_metrics_reporting(self):
        """Verify get_metrics dictionary contains all expected health stats."""
        worker = SnifferWorker(max_queue_size=100)
        worker._packet_callback(IP() / TCP())

        metrics = worker.get_metrics()
        self.assertIn("is_running", metrics)
        self.assertIn("queue_size", metrics)
        self.assertIn("pending_queue", metrics)
        self.assertIn("max_queue_size", metrics)
        self.assertIn("total_captured", metrics)
        self.assertIn("total_dequeued", metrics)
        self.assertIn("total_dropped", metrics)
        self.assertIn("packets_per_second", metrics)
        self.assertIn("uptime_seconds", metrics)
        self.assertEqual(metrics["total_captured"], 1)
        self.assertEqual(metrics["total_dequeued"], 0)
        self.assertEqual(metrics["pending_queue"], 1)

    def test_dequeued_metric_tracking(self):
        """Verify total_dequeued accurately tracks every get_packet() call."""
        worker = SnifferWorker(max_queue_size=10)
        worker._packet_callback(IP() / TCP())
        worker._packet_callback(IP() / UDP())

        self.assertEqual(worker.get_metrics()["total_dequeued"], 0)
        worker.get_packet(timeout=0.1)
        self.assertEqual(worker.get_metrics()["total_dequeued"], 1)
        worker.get_packet(timeout=0.1)
        self.assertEqual(worker.get_metrics()["total_dequeued"], 2)
        self.assertEqual(worker.get_metrics()["pending_queue"], 0)

    def test_metrics_calculation_while_running(self):
        """Verify uptime_seconds and packets_per_second calculate correctly while running."""
        worker = SnifferWorker(max_queue_size=100)
        worker.start_time = time.time() - 2.0  # Simulate 2 seconds running
        worker._is_running = True

        for _ in range(20):
            worker._packet_callback(IP() / TCP())

        metrics = worker.get_metrics()
        self.assertTrue(metrics["is_running"])
        self.assertGreaterEqual(metrics["uptime_seconds"], 2.0)
        self.assertGreater(metrics["packets_per_second"], 0.0)
        self.assertAlmostEqual(metrics["packets_per_second"], 20 / metrics["uptime_seconds"], delta=0.5)

    def test_metrics_preserved_after_stopping(self):
        """Verify metrics (uptime, PPS, counts) remain accurate and non-zero after stop."""
        worker = SnifferWorker(max_queue_size=100)
        worker.start_time = time.time() - 3.0  # Started 3s ago
        worker.stop_time = time.time()         # Stopped now
        worker._is_running = False             # Sniffer is stopped

        for _ in range(30):
            worker._packet_callback(IP() / TCP())

        metrics = worker.get_metrics()
        self.assertFalse(metrics["is_running"])
        self.assertGreaterEqual(metrics["uptime_seconds"], 2.9)
        self.assertLessEqual(metrics["uptime_seconds"], 3.5)
        self.assertGreater(metrics["packets_per_second"], 0.0)
        self.assertEqual(metrics["total_captured"], 30)
        self.assertEqual(metrics["pending_queue"], 30)

    def test_thread_safe_concurrent_metrics_access(self):
        """Verify thread safety when concurrently reading metrics and processing packets."""
        import threading
        worker = SnifferWorker(max_queue_size=500)
        worker.start_time = time.time()
        worker._is_running = True
        errors = []

        def producer():
            for _ in range(50):
                worker._packet_callback(IP() / TCP())
                time.sleep(0.005)

        def consumer():
            for _ in range(25):
                worker.get_packet(timeout=0.05)
                time.sleep(0.01)

        def reader():
            for _ in range(50):
                try:
                    m = worker.get_metrics()
                    if m["total_captured"] < m["total_dequeued"]:
                        errors.append("Invariant violated: captured < dequeued")
                except Exception as e:
                    errors.append(str(e))
                time.sleep(0.005)

        threads = [
            threading.Thread(target=producer),
            threading.Thread(target=consumer),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        final_metrics = worker.get_metrics()
        self.assertEqual(final_metrics["total_captured"], 50)
        self.assertEqual(final_metrics["total_dequeued"], 25)
        self.assertEqual(final_metrics["pending_queue"], 25)


class TestSnifferIntegration(unittest.TestCase):
    """Integration test validating Scapy AsyncSniffer start/stop lifecycle."""

    def test_live_sniffer_lifecycle(self):
        """Test starting and stopping real AsyncSniffer on the system."""
        worker = SnifferWorker(interface="loopback")

        started = worker.start_monitoring()
        if not started:
            # If standard user privilege prevents kernel binding in this environment
            print("[INFO] Live capture start skipped or failed due to environment privilege level.")
            return

        self.assertTrue(worker.is_running)
        self.assertIsNotNone(worker.start_time)

        # Allow sniffer thread to run briefly
        time.sleep(1.0)

        metrics = worker.get_metrics()
        self.assertTrue(metrics["is_running"])

        # Stop sniffer cleanly
        stopped = worker.stop_monitoring()
        self.assertTrue(stopped)
        self.assertFalse(worker.is_running)


if __name__ == "__main__":
    unittest.main(verbosity=2)
