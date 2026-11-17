"""
SQLite Database Manager for Intelligent NIDS.

Provides thread-safe relational persistence for security alerts, traffic velocity
snapshots, and packet logs. Operates in Write-Ahead Logging (WAL) mode to allow
concurrent reader threads (Flask REST API) and writer threads (Sniffer/Rule Engine)
without database locks.
"""

import os
import sqlite3
import threading
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Union
from contextlib import contextmanager

from database.models import AlertRecord, TrafficSnapshotRecord, PacketLogRecord

logger = logging.getLogger("NIDS.DatabaseManager")


class DatabaseManager:
    """
    Manages SQLite database connections, schema migrations, and high-performance CRUD queries.
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize DatabaseManager.

        Args:
            db_path: Path to the SQLite database file. Defaults to database/ids_database.db.
        """
        if db_path is None:
            # Default to database/ids_database.db in project root
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(base_dir, "ids_database.db")
        else:
            self.db_path = os.path.abspath(db_path)

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        # Thread synchronization for write transactions
        self._write_lock = threading.Lock()

        # Initialize schema and configure WAL mode
        self.init_db()

    @contextmanager
    def get_connection(self):
        """
        Context manager for acquiring a SQLite connection configured with:
        - WAL journal mode (Write-Ahead Logging)
        - Row factory for dict-like column access
        - Foreign keys enabled
        - 15-second busy timeout
        """
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            # Optimize PRAGMAs for concurrent SOC environment
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """
        Initialize the SQLite database schema and indexes if they do not exist.
        """
        with self._write_lock, self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Security Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_ip TEXT NOT NULL,
                    destination_port INTEGER,
                    protocol TEXT NOT NULL,
                    packet_count INTEGER DEFAULT 1,
                    anomaly_score REAL DEFAULT 0.0,
                    description TEXT,
                    status TEXT DEFAULT 'NEW',
                    mitigation_tip TEXT
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON security_alerts(source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);")

            # 2. Traffic Velocity Snapshots Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_packets INTEGER NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    tcp_packets INTEGER NOT NULL,
                    udp_packets INTEGER NOT NULL,
                    icmp_packets INTEGER NOT NULL,
                    other_packets INTEGER NOT NULL,
                    packets_per_second REAL NOT NULL,
                    bytes_per_second REAL NOT NULL
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON traffic_snapshots(timestamp DESC);")

            # 3. Inspected / Forensic Packet Logs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packet_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    packet_length INTEGER,
                    tcp_flags TEXT,
                    info TEXT
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packet_logs(timestamp DESC);")

            logger.info(f"Database initialized in WAL mode at: {self.db_path}")

    # =========================================================================
    # SECURITY ALERTS CRUD
    # =========================================================================

    def save_alert(self, alert: Any) -> int:
        """
        Insert a new alert or update an existing active episode.

        Args:
            alert: SecurityAlert instance, AlertRecord, or dictionary.

        Returns:
            int: The primary key ID of the inserted or updated alert row.
        """
        # Extract attributes safely whether alert is a dataclass or dict
        if hasattr(alert, "to_dict"):
            data = alert.to_dict()
        elif isinstance(alert, dict):
            data = alert
        else:
            data = alert.__dict__

        raw_ts = data.get("timestamp")
        if isinstance(raw_ts, (int, float)):
            ts_str = datetime.fromtimestamp(raw_ts).strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(raw_ts, str):
            ts_str = raw_ts
        else:
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._write_lock, self.get_connection() as conn:
            cursor = conn.cursor()

            # Check if this alert corresponds to an existing active incident ID
            alert_id = data.get("id")
            if alert_id:
                cursor.execute("SELECT id FROM security_alerts WHERE id = ?;", (alert_id,))
                existing = cursor.fetchone()
                if existing:
                    cursor.execute("""
                        UPDATE security_alerts
                        SET timestamp = ?,
                            packet_count = ?,
                            destination_port = COALESCE(?, destination_port),
                            description = ?
                        WHERE id = ?;
                    """, (
                        ts_str,
                        data.get("packet_count", 1),
                        data.get("destination_port"),
                        data.get("description", ""),
                        alert_id
                    ))
                    return alert_id

            # Insert brand new alert
            cursor.execute("""
                INSERT INTO security_alerts (
                    timestamp, attack_type, severity, source_ip, source_port,
                    destination_ip, destination_port, protocol, packet_count,
                    anomaly_score, description, status, mitigation_tip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                ts_str,
                data.get("attack_type", "Unknown"),
                data.get("severity", "MEDIUM").upper(),
                data.get("source_ip", "0.0.0.0"),
                data.get("source_port"),
                data.get("destination_ip", "0.0.0.0"),
                data.get("destination_port"),
                data.get("protocol", "TCP").upper(),
                data.get("packet_count", 1),
                float(data.get("anomaly_score", 0.0)),
                data.get("description", ""),
                data.get("status", "NEW").upper(),
                data.get("mitigation_tip", "")
            ))
            return cursor.lastrowid

    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Query alerts with dynamic filtering, search, and pagination.
        """
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if search:
            query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR description LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single alert by its primary key ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_alerts WHERE id = ?;", (alert_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_alert_status(self, alert_id: int, new_status: str) -> bool:
        """
        Update the status of an alert (e.g. 'NEW' -> 'ACKNOWLEDGED' -> 'RESOLVED').
        """
        valid_statuses = {"NEW", "ACKNOWLEDGED", "RESOLVED"}
        status_clean = new_status.upper()
        if status_clean not in valid_statuses:
            return False

        with self._write_lock, self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE security_alerts SET status = ? WHERE id = ?;", (status_clean, alert_id))
            return cursor.rowcount > 0

    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Compute aggregate alert statistics for the SOC summary cards and charts.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total counts
            cursor.execute("SELECT COUNT(*) FROM security_alerts;")
            total_alerts = cursor.fetchone()[0]

            # Counts by severity
            cursor.execute("SELECT severity, COUNT(*) FROM security_alerts GROUP BY severity;")
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for row in cursor.fetchall():
                sev = row[0].upper()
                if sev in severity_counts:
                    severity_counts[sev] = row[1]

            # Counts by attack type
            cursor.execute("SELECT attack_type, COUNT(*) FROM security_alerts GROUP BY attack_type;")
            type_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Top 5 attacking source IPs
            cursor.execute("""
                SELECT source_ip, COUNT(*) as incident_count, SUM(packet_count) as total_packets
                FROM security_alerts
                GROUP BY source_ip
                ORDER BY incident_count DESC
                LIMIT 5;
            """)
            top_attackers = [
                {"source_ip": row[0], "incident_count": row[1], "total_packets": row[2]}
                for row in cursor.fetchall()
            ]

            # Counts by status
            cursor.execute("SELECT status, COUNT(*) FROM security_alerts GROUP BY status;")
            status_counts = {"NEW": 0, "ACKNOWLEDGED": 0, "RESOLVED": 0}
            for row in cursor.fetchall():
                st = row[0].upper()
                if st in status_counts:
                    status_counts[st] = row[1]

            return {
                "total_alerts": total_alerts,
                "severity_counts": severity_counts,
                "attack_type_distribution": type_counts,
                "top_attackers": top_attackers,
                "status_counts": status_counts,
            }

    # =========================================================================
    # TRAFFIC VELOCITY SNAPSHOTS
    # =========================================================================

    def save_traffic_snapshot(
        self,
        total_packets: int,
        total_bytes: int,
        tcp_packets: int,
        udp_packets: int,
        icmp_packets: int,
        other_packets: int,
        packets_per_second: float,
        bytes_per_second: float,
        timestamp: Optional[Union[float, str]] = None
    ) -> int:
        """
        Insert a periodic traffic throughput snapshot.
        """
        if isinstance(timestamp, (int, float)):
            ts_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(timestamp, str):
            ts_str = timestamp
        else:
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self._write_lock, self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO traffic_snapshots (
                    timestamp, total_packets, total_bytes, tcp_packets,
                    udp_packets, icmp_packets, other_packets,
                    packets_per_second, bytes_per_second
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                ts_str, total_packets, total_bytes, tcp_packets,
                udp_packets, icmp_packets, other_packets,
                round(packets_per_second, 2), round(bytes_per_second, 2)
            ))
            return cursor.lastrowid

    def get_traffic_history(self, limit: int = 60) -> List[Dict[str, Any]]:
        """
        Retrieve recent traffic velocity snapshots in chronological order
        (for Chart.js live time-series graphing).
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM (
                    SELECT * FROM traffic_snapshots
                    ORDER BY id DESC
                    LIMIT ?
                ) ORDER BY id ASC;
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # =========================================================================
    # PACKET LOGS FORENSICS
    # =========================================================================

    def save_packet_log(self, packet: Any) -> int:
        """
        Insert an inspected packet into the forensic packet_logs table.
        Accepts ParsedPacket instance or dictionary.
        """
        if hasattr(packet, "to_dict"):
            data = packet.to_dict()
        elif isinstance(packet, dict):
            data = packet
        else:
            data = packet.__dict__

        raw_ts = data.get("timestamp")
        if isinstance(raw_ts, (int, float)):
            ts_str = datetime.fromtimestamp(raw_ts).strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(raw_ts, str):
            ts_str = raw_ts
        else:
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        flags_val = data.get("tcp_flags")
        flags_str = ", ".join(flags_val) if isinstance(flags_val, list) else str(flags_val or "")

        with self._write_lock, self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO packet_logs (
                    timestamp, source_ip, destination_ip, source_port,
                    destination_port, protocol, packet_length, tcp_flags, info
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                ts_str,
                data.get("src_ip"),
                data.get("dst_ip"),
                data.get("src_port"),
                data.get("dst_port"),
                data.get("transport_proto", "OTHER"),
                data.get("packet_size", 0),
                flags_str,
                data.get("summary", "")[:255]
            ))
            return cursor.lastrowid

    def get_recent_packets(self, limit: int = 50, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Query sampled forensic packets for inspection table.
        """
        query = "SELECT * FROM packet_logs WHERE 1=1"
        params: List[Any] = []

        if search:
            query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR protocol LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term])

        query += " ORDER BY id DESC LIMIT ?;"
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    # =========================================================================
    # MAINTENANCE & HEALTH
    # =========================================================================

    def clear_all_data(self) -> None:
        """
        Delete all rows from all tables (for reset and testing).
        """
        with self._write_lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM security_alerts;")
                cursor.execute("DELETE FROM traffic_snapshots;")
                cursor.execute("DELETE FROM packet_logs;")

            # Run VACUUM in autocommit mode outside open transaction
            try:
                conn_vac = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
                conn_vac.execute("VACUUM;")
                conn_vac.close()
            except Exception as e:
                logger.debug(f"VACUUM skipped: {e}")

    def get_db_status(self) -> Dict[str, Any]:
        """
        Return diagnostic health info about the database.
        """
        size_bytes = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_alerts;")
            alerts_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM traffic_snapshots;")
            snapshots_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM packet_logs;")
            packets_count = cursor.fetchone()[0]

            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0]

            return {
                "db_path": self.db_path,
                "file_size_kb": round(size_bytes / 1024, 2),
                "journal_mode": journal_mode,
                "alerts_count": alerts_count,
                "snapshots_count": snapshots_count,
                "packets_count": packets_count,
            }
