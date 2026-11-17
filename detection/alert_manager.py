"""
Alert Management and Incident Deduplication Engine for Intelligent NIDS.

Provides structured SecurityAlert objects with severity ratings, mitigation recommendations,
and episode-based alert deduplication/throttling to prevent alert storms during high-speed floods.
"""

import time
import logging
import threading
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger("NIDS.AlertManager")


@dataclass
class SecurityAlert:
    """
    Standardized Security Incident Alert data model.
    """
    id: Optional[int]
    timestamp: float
    attack_type: str            # 'Port Scan', 'SYN Flood', 'ICMP Flood', 'Suspicious Traffic'
    severity: str               # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    source_ip: str
    source_port: Optional[int]
    destination_ip: str
    destination_port: Optional[int]
    protocol: str               # 'TCP', 'UDP', 'ICMP', 'OTHER'
    packet_count: int = 1       # Aggregated packets in this episode
    anomaly_score: float = 0.0  # Optional score for ML (Phase 2)
    description: str = ""
    mitigation_tip: str = ""
    status: str = "NEW"         # 'NEW', 'ACKNOWLEDGED', 'RESOLVED'

    def to_dict(self) -> Dict[str, Any]:
        """Convert the SecurityAlert into a dictionary for JSON/DB."""
        return asdict(self)


class AlertManager:
    """
    Manages generation, suppression, deduplication, and retrieval of security alerts.
    """

    def __init__(
        self,
        cooldown_seconds: float = 30.0,
        max_history_size: int = 5000,
        db_manager: Optional[Any] = None,
    ):
        """
        Initialize the AlertManager.

        Args:
            cooldown_seconds: Window within which recurring events for the same
                              (attack_type, source_ip) are aggregated into a single episode.
            max_history_size: Maximum alerts stored in memory before older alerts roll off.
            db_manager: Optional DatabaseManager instance for persistent SQLite storage.
        """
        self.cooldown_seconds = cooldown_seconds
        self.max_history_size = max_history_size
        self.db_manager = db_manager
        self._lock = threading.Lock()

        self._alert_counter = 0
        self._alert_history: List[SecurityAlert] = []
        # Active episodes: (attack_type, source_ip) -> SecurityAlert
        self._active_episodes: Dict[Tuple[str, str], SecurityAlert] = {}

    def record_alert(
        self,
        attack_type: str,
        severity: str,
        source_ip: str,
        destination_ip: str,
        protocol: str,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        description: str = "",
        mitigation_tip: str = "",
        timestamp: Optional[float] = None,
    ) -> Tuple[SecurityAlert, bool]:
        """
        Record a detected attack candidate, applying deduplication and throttling.

        Returns:
            Tuple of (SecurityAlert, is_new_incident: bool).
            If is_new_incident is False, it was an ongoing attack aggregated into an existing episode.
        """
        now = timestamp or time.time()
        dedup_key = (attack_type, source_ip)

        with self._lock:
            # Check for active existing episode within cooldown window
            if dedup_key in self._active_episodes:
                existing = self._active_episodes[dedup_key]
                if now - existing.timestamp <= self.cooldown_seconds:
                    # Increment packet counter and update timestamp
                    existing.packet_count += 1
                    existing.timestamp = now
                    # Update destination or port if changed
                    if destination_port is not None:
                        existing.destination_port = destination_port
                    if self.db_manager:
                        try:
                            self.db_manager.save_alert(existing)
                        except Exception as ex:
                            logger.error(f"Failed to update alert in database: {ex}")
                    return existing, False

            # Brand new alert episode
            self._alert_counter += 1
            alert = SecurityAlert(
                id=self._alert_counter,
                timestamp=now,
                attack_type=attack_type,
                severity=severity.upper(),
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol.upper(),
                packet_count=1,
                description=description,
                mitigation_tip=mitigation_tip,
                status="NEW",
            )

            # Persist to SQLite if DatabaseManager is active
            if self.db_manager:
                try:
                    db_id = self.db_manager.save_alert(alert)
                    alert.id = db_id
                except Exception as ex:
                    logger.error(f"Failed to persist alert in database: {ex}")

            # Store in active episodes and history
            self._active_episodes[dedup_key] = alert
            self._alert_history.append(alert)

            # Trim history to max size
            if len(self._alert_history) > self.max_history_size:
                self._alert_history.pop(0)

            logger.warning(
                f"[ALERT #{alert.id}] [{alert.severity}] {alert.attack_type} detected from {source_ip} -> {destination_ip}"
            )
            return alert, True

    def get_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve recent alerts in reverse chronological order.
        """
        with self._lock:
            filtered = self._alert_history
            if severity:
                filtered = [a for a in filtered if a.severity == severity.upper()]
            if attack_type:
                filtered = [a for a in filtered if a.attack_type.lower() == attack_type.lower()]

            recent = filtered[-limit:]
            recent.reverse()
            return [a.to_dict() for a in recent]

    def get_alert_counts_by_severity(self) -> Dict[str, int]:
        """
        Return the count of all alerts grouped by severity level.
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        with self._lock:
            for alert in self._alert_history:
                if alert.severity in counts:
                    counts[alert.severity] += 1
                else:
                    counts["LOW"] += 1
        return counts

    def get_total_alert_count(self) -> int:
        """Return total number of alerts recorded."""
        with self._lock:
            return len(self._alert_history)

    def clear(self) -> None:
        """Clear all alerts and active episodes (for tests or reset)."""
        with self._lock:
            self._alert_history.clear()
            self._active_episodes.clear()
            self._alert_counter = 0
