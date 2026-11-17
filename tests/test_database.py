"""
Comprehensive Unit Tests for SQLite Database Layer (database/db_manager.py).
Tests WAL mode, CRUD operations, indexing, statistics aggregation, and concurrent writes.
"""

import os
import sys
import time
import shutil
import tempfile
import threading
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db_manager import DatabaseManager
from database.models import AlertRecord, TrafficSnapshotRecord, PacketLogRecord
from detection.alert_manager import SecurityAlert
from core.packet_parser import ParsedPacket


class TestDatabaseManager(unittest.TestCase):
    """Test suite validating SQLite WAL persistence and queries."""

    def setUp(self):
        # Create a unique temporary directory for each test run
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_ids.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        # Clean up temporary files
        try:
            shutil.rmtree(self.test_dir)
        except Exception:
            pass

    def test_schema_and_wal_mode(self):
        """Verify database tables, indexes, and WAL journal mode."""
        status = self.db.get_db_status()
        self.assertEqual(status["journal_mode"].lower(), "wal")
        self.assertEqual(status["alerts_count"], 0)
        self.assertEqual(status["snapshots_count"], 0)
        self.assertEqual(status["packets_count"], 0)

    def test_save_and_retrieve_alert(self):
        """Verify inserting and querying a SecurityAlert object."""
        alert = SecurityAlert(
            id=None,
            timestamp=time.time(),
            attack_type="SYN Flood",
            severity="CRITICAL",
            source_ip="192.168.1.50",
            source_port=12345,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="TCP",
            packet_count=60,
            description="TCP SYN flood test episode",
            mitigation_tip="Enable SYN Cookies",
            status="NEW",
        )

        row_id = self.db.save_alert(alert)
        self.assertGreater(row_id, 0)

        # Retrieve by ID
        fetched = self.db.get_alert_by_id(row_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["attack_type"], "SYN Flood")
        self.assertEqual(fetched["severity"], "CRITICAL")
        self.assertEqual(fetched["source_ip"], "192.168.1.50")
        self.assertEqual(fetched["destination_port"], 80)
        self.assertEqual(fetched["packet_count"], 60)
        self.assertEqual(fetched["status"], "NEW")

    def test_alert_filtering_and_search(self):
        """Verify filtering alerts by severity, attack type, and search keyword."""
        # Insert 3 diverse alerts
        self.db.save_alert(AlertRecord(
            attack_type="Port Scan", severity="HIGH", source_ip="10.0.0.5",
            destination_ip="192.168.1.1", destination_port=22, description="Nmap scan"
        ))
        self.db.save_alert(AlertRecord(
            attack_type="SYN Flood", severity="CRITICAL", source_ip="10.0.0.6",
            destination_ip="192.168.1.1", destination_port=80, description="Web SYN flood"
        ))
        self.db.save_alert(AlertRecord(
            attack_type="Suspicious Traffic", severity="MEDIUM", source_ip="10.0.0.7",
            destination_ip="192.168.1.1", destination_port=4444, description="Metasploit shell"
        ))

        # Filter by severity
        crit = self.db.get_alerts(severity="CRITICAL")
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["attack_type"], "SYN Flood")

        # Filter by attack type
        scan = self.db.get_alerts(attack_type="Port Scan")
        self.assertEqual(len(scan), 1)
        self.assertEqual(scan[0]["source_ip"], "10.0.0.5")

        # Search keyword
        search_res = self.db.get_alerts(search="Metasploit")
        self.assertEqual(len(search_res), 1)
        self.assertEqual(search_res[0]["destination_port"], 4444)

    def test_update_alert_status(self):
        """Verify alert lifecycle status transitions (NEW -> ACKNOWLEDGED -> RESOLVED)."""
        row_id = self.db.save_alert(AlertRecord(
            attack_type="ICMP Flood", severity="HIGH", source_ip="1.1.1.1", destination_ip="2.2.2.2"
        ))

        # 1. Acknowledge
        success_ack = self.db.update_alert_status(row_id, "ACKNOWLEDGED")
        self.assertTrue(success_ack)
        self.assertEqual(self.db.get_alert_by_id(row_id)["status"], "ACKNOWLEDGED")

        # 2. Resolve
        success_res = self.db.update_alert_status(row_id, "RESOLVED")
        self.assertTrue(success_res)
        self.assertEqual(self.db.get_alert_by_id(row_id)["status"], "RESOLVED")

        # 3. Invalid status should fail
        invalid = self.db.update_alert_status(row_id, "INVALID_STATUS")
        self.assertFalse(invalid)

    def test_alert_statistics_aggregation(self):
        """Verify calculation of aggregate stats (severities, top talkers, distributions)."""
        self.db.save_alert(AlertRecord(attack_type="Port Scan", severity="HIGH", source_ip="10.0.0.1", packet_count=10))
        self.db.save_alert(AlertRecord(attack_type="Port Scan", severity="HIGH", source_ip="10.0.0.1", packet_count=15))
        self.db.save_alert(AlertRecord(attack_type="SYN Flood", severity="CRITICAL", source_ip="10.0.0.2", packet_count=50))
        self.db.save_alert(AlertRecord(attack_type="Suspicious Traffic", severity="MEDIUM", source_ip="10.0.0.3", packet_count=2))

        stats = self.db.get_alert_statistics()
        self.assertEqual(stats["total_alerts"], 4)
        self.assertEqual(stats["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(stats["severity_counts"]["HIGH"], 2)
        self.assertEqual(stats["severity_counts"]["MEDIUM"], 1)
        self.assertEqual(stats["severity_counts"]["LOW"], 0)

        # Top attacker should be 10.0.0.1 (2 incidents)
        top = stats["top_attackers"]
        self.assertEqual(top[0]["source_ip"], "10.0.0.1")
        self.assertEqual(top[0]["incident_count"], 2)

    def test_traffic_snapshots_history(self):
        """Verify saving and retrieving time-series snapshots in chronological order."""
        base_t = time.time()
        for i in range(5):
            self.db.save_traffic_snapshot(
                total_packets=100 + i * 10,
                total_bytes=1000 + i * 100,
                tcp_packets=80 + i * 8,
                udp_packets=15 + i,
                icmp_packets=5 + i,
                other_packets=0,
                packets_per_second=10.0 + i,
                bytes_per_second=500.0 + i * 50,
                timestamp=base_t + i * 2,
            )

        history = self.db.get_traffic_history(limit=5)
        self.assertEqual(len(history), 5)
        # Chronological order check: first item should have earliest total_packets
        self.assertEqual(history[0]["total_packets"], 100)
        self.assertEqual(history[-1]["total_packets"], 140)

    def test_packet_logs_forensics(self):
        """Verify saving a ParsedPacket into packet_logs and querying recent logs."""
        parsed = ParsedPacket(
            timestamp=time.time(),
            packet_size=128,
            src_ip="192.168.0.6",
            dst_ip="142.250.190.46",
            src_port=54321,
            dst_port=443,
            transport_proto="TCP",
            tcp_flags=["SYN", "ACK"],
            summary="Ether / IP / TCP 192.168.0.6:54321 > 142.250.190.46:443 SA",
        )

        row_id = self.db.save_packet_log(parsed)
        self.assertGreater(row_id, 0)

        logs = self.db.get_recent_packets(limit=10)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["source_ip"], "192.168.0.6")
        self.assertEqual(logs[0]["destination_ip"], "142.250.190.46")
        self.assertEqual(logs[0]["tcp_flags"], "SYN, ACK")
        self.assertEqual(logs[0]["packet_length"], 128)

    def test_concurrent_multithreaded_writes(self):
        """Verify thread safety under concurrent writes from multiple threads (WAL mode)."""
        errors = []

        def alert_writer():
            for i in range(25):
                try:
                    self.db.save_alert(AlertRecord(
                        attack_type="Port Scan", severity="HIGH", source_ip=f"10.0.0.{i}"
                    ))
                except Exception as e:
                    errors.append(f"Alert error: {e}")

        def snapshot_writer():
            for i in range(25):
                try:
                    self.db.save_traffic_snapshot(
                        total_packets=i * 10, total_bytes=i * 100, tcp_packets=i,
                        udp_packets=0, icmp_packets=0, other_packets=0,
                        packets_per_second=5.0, bytes_per_second=250.0
                    )
                except Exception as e:
                    errors.append(f"Snapshot error: {e}")

        def packet_writer():
            for i in range(25):
                try:
                    self.db.save_packet_log(PacketLogRecord(
                        source_ip=f"192.168.1.{i}", destination_ip="8.8.8.8",
                        protocol="UDP", destination_port=53, packet_length=64
                    ))
                except Exception as e:
                    errors.append(f"Packet error: {e}")

        threads = [
            threading.Thread(target=alert_writer),
            threading.Thread(target=snapshot_writer),
            threading.Thread(target=packet_writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        status = self.db.get_db_status()
        self.assertEqual(status["alerts_count"], 25)
        self.assertEqual(status["snapshots_count"], 25)
        self.assertEqual(status["packets_count"], 25)

    def test_clear_all_data(self):
        """Verify clear_all_data truncates all tables and resets counts to zero."""
        self.db.save_alert(AlertRecord(attack_type="Port Scan", severity="HIGH"))
        self.db.save_traffic_snapshot(10, 100, 10, 0, 0, 0, 1.0, 10.0)
        self.db.save_packet_log(PacketLogRecord(source_ip="1.1.1.1"))

        self.db.clear_all_data()
        status = self.db.get_db_status()
        self.assertEqual(status["alerts_count"], 0)
        self.assertEqual(status["snapshots_count"], 0)
        self.assertEqual(status["packets_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
