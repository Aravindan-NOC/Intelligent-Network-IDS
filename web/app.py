"""
Flask Application Factory and Master NIDS Pipeline Manager.

Coordinates the background sniffer worker, flow analyzer, rule engine,
and SQLite WAL database manager alongside the Flask web application.
"""

import os
import time
import threading
import logging
from typing import Optional, Dict, Any
from flask import Flask
from flask_cors import CORS

import config
from database.db_manager import DatabaseManager
from core.sniffer import SnifferWorker
from core.packet_parser import parse_packet
from detection.flow_analyzer import FlowAnalyzer
from detection.alert_manager import AlertManager
from detection.rule_engine import RuleEngine
from detection.anomaly_detector import MLAnomalyDetector

logger = logging.getLogger("NIDS.WebApp")


class NIDSSystemManager:
    """
    Central Coordinator managing the lifecycle of the NIDS engine:
    Capture -> Parse -> Analyze -> Detect -> Persist -> Serve.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or config.DATABASE_PATH
        self.db = DatabaseManager(db_path=self.db_path)

        # In-memory sliding window analyzer
        self.flow_analyzer = FlowAnalyzer(
            port_scan_window=config.DETECTION_CONFIG.get("PORT_SCAN_WINDOW_SECONDS", 5.0),
            syn_flood_window=config.DETECTION_CONFIG.get("SYN_FLOOD_WINDOW_SECONDS", 3.0),
            icmp_flood_window=config.DETECTION_CONFIG.get("ICMP_FLOOD_WINDOW_SECONDS", 2.0),
        )

        # Alert manager with SQLite persistence hook
        self.alert_manager = AlertManager(
            cooldown_seconds=config.DETECTION_CONFIG.get("ALERT_COOLDOWN_SECONDS", 30.0),
            db_manager=self.db,
        )

        # Rule-based intrusion detection engine
        self.rule_engine = RuleEngine(
            flow_analyzer=self.flow_analyzer,
            alert_manager=self.alert_manager,
            config=config.DETECTION_CONFIG,
        )

        # ML Anomaly Detector (Isolation Forest)
        self.ml_detector = MLAnomalyDetector(
            alert_manager=self.alert_manager,
            min_flow_packets=8,
            flow_window_seconds=3.0,
        )

        # Sniffer worker (starts on default or configured interface)
        self.sniffer = SnifferWorker(max_queue_size=10000)

        # Background processing worker thread
        self._analysis_thread: Optional[threading.Thread] = None
        self._is_analyzing = False
        self._thread_lock = threading.Lock()

        # Snapshot timing tracker
        self._last_snapshot_time = time.time()
        self._packet_sample_counter = 0

    def start_pipeline(self, interface: Optional[str] = None) -> bool:
        """
        Start both the packet sniffer and the consumer analysis worker thread.
        """
        with self._thread_lock:
            # 1. Start Scapy AsyncSniffer
            if not self.sniffer.is_running:
                success = self.sniffer.start_monitoring(interface=interface)
                if not success:
                    logger.error("Failed to start sniffer worker.")
                    return False

            # 2. Start consumer analysis thread
            if not self._is_analyzing:
                self._is_analyzing = True
                self._analysis_thread = threading.Thread(
                    target=self._analysis_worker_loop,
                    name="NIDS-AnalysisWorker",
                    daemon=True,
                )
                self._analysis_thread.start()
                logger.info("NIDS Analysis consumer worker thread started.")

            return True

    def stop_pipeline(self) -> bool:
        """
        Stop the sniffer and consumer worker thread cleanly.
        """
        with self._thread_lock:
            self._is_analyzing = False
            self.sniffer.stop_monitoring()
            if self._analysis_thread and self._analysis_thread.is_alive():
                self._analysis_thread.join(timeout=2.0)
            logger.info("NIDS pipeline stopped.")
            return True

    def _analysis_worker_loop(self) -> None:
        """
        Continuous consumer loop pulling raw packets from the sniffer queue,
        parsing headers, evaluating threat rules, and persisting metrics.
        """
        while self._is_analyzing:
            try:
                # Retrieve next packet from bounded queue
                pkt = self.sniffer.get_packet(timeout=0.2)
                now = time.time()

                if pkt is not None:
                    # 1. Parse packet headers
                    parsed = parse_packet(pkt)
                    if parsed:
                        # 2. Evaluate against Rule-Based Detection Engine
                        alerts = self.rule_engine.evaluate_packet(parsed)

                        # 3. Evaluate against ML Anomaly Detector (Isolation Forest)
                        ml_alert = self.ml_detector.process_packet(parsed, current_time=now)
                        if ml_alert:
                            alerts.append(ml_alert)

                        # 4. Sample packet forensics: log all alerted packets + 1-in-5 normal packets
                        self._packet_sample_counter += 1
                        if alerts or (self._packet_sample_counter % 5 == 0):
                            try:
                                self.db.save_packet_log(parsed)
                            except Exception as ex:
                                logger.debug(f"Failed to log packet forensic: {ex}")

                # 4. Periodic Traffic Snapshot (every 2.0 seconds)
                if now - self._last_snapshot_time >= 2.0:
                    self._last_snapshot_time = now
                    summary = self.flow_analyzer.get_traffic_summary(current_time=now)
                    dist = summary.get("protocol_distribution", {})
                    try:
                        self.db.save_traffic_snapshot(
                            total_packets=summary.get("total_packets", 0),
                            total_bytes=summary.get("total_bytes", 0),
                            tcp_packets=dist.get("TCP", 0),
                            udp_packets=dist.get("UDP", 0),
                            icmp_packets=dist.get("ICMP", 0) + dist.get("ICMPv6", 0),
                            other_packets=dist.get("OTHER", 0) + dist.get("ARP", 0),
                            packets_per_second=summary.get("current_pps", 0.0),
                            bytes_per_second=summary.get("current_bps", 0.0) / 8.0,
                            timestamp=now,
                        )
                    except Exception as ex:
                        logger.debug(f"Failed to save traffic snapshot: {ex}")

            except Exception as e:
                logger.error(f"Unexpected error in analysis loop: {e}", exc_info=False)
                time.sleep(0.1)

    @property
    def is_running(self) -> bool:
        return self.sniffer.is_running and self._is_analyzing


def create_app(system_manager: Optional[NIDSSystemManager] = None) -> Flask:
    """
    Flask Application Factory.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )

    app.config["SECRET_KEY"] = config.WEB_CONFIG.get("SECRET_KEY", "ids-secret-key-soc")
    CORS(app)

    # Attach central NIDS manager to app context
    app.nids_manager = system_manager or NIDSSystemManager()

    # Register blueprints
    from web.routes.api_routes import api_bp
    from web.routes.view_routes import view_bp

    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(view_bp)

    return app
