"""
REST API Routes for Intelligent NIDS.

Provides JSON endpoints for real-time dashboard telemetry, capture lifecycle,
threat alerts, traffic time-series, forensic logs, and safe simulation triggers.
"""

import io
import csv
import json
import threading
from typing import Dict, Any
from flask import Blueprint, current_app, jsonify, request, Response

from core.network_utils import list_network_interfaces
from tests.test_attack_simulator import (
    simulate_port_scan,
    simulate_syn_flood,
    simulate_icmp_flood,
    simulate_stealth_xmas,
    simulate_suspicious_port,
)

api_bp = Blueprint("api", __name__)


def get_manager():
    """Retrieve NIDSSystemManager from Flask current_app."""
    return current_app.nids_manager


@api_bp.route("/status", methods=["GET"])
def get_system_status():
    """Operational status and sniffer health metrics."""
    mgr = get_manager()
    sniffer_metrics = mgr.sniffer.get_metrics()
    db_status = mgr.db.get_db_status()
    ml_status = mgr.ml_detector.get_status() if hasattr(mgr, "ml_detector") else {"is_loaded": False}

    return jsonify({
        "success": True,
        "is_running": mgr.is_running,
        "active_interface": sniffer_metrics["active_interface"],
        "queue_size": sniffer_metrics["queue_size"],
        "total_captured": sniffer_metrics["total_captured"],
        "total_dequeued": sniffer_metrics["total_dequeued"],
        "total_dropped": sniffer_metrics["total_dropped"],
        "packets_per_second": sniffer_metrics["packets_per_second"],
        "uptime_seconds": sniffer_metrics["uptime_seconds"],
        "database": db_status,
        "ml_engine": ml_status,
    })


@api_bp.route("/capture/start", methods=["POST"])
def start_capture():
    """Start the real-time packet capture and analysis pipeline."""
    mgr = get_manager()
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")

    if mgr.is_running:
        return jsonify({"success": False, "message": "Pipeline is already active."}), 400

    started = mgr.start_pipeline(interface=interface)
    if started:
        return jsonify({
            "success": True,
            "message": f"Capture started on {mgr.sniffer.active_interface}",
            "active_interface": mgr.sniffer.active_interface,
        })
    else:
        return jsonify({
            "success": False,
            "message": "Failed to start capture. Verify Npcap driver and Administrator elevation.",
        }), 500


@api_bp.route("/capture/stop", methods=["POST"])
def stop_capture():
    """Stop the packet capture and analysis pipeline cleanly."""
    mgr = get_manager()
    if not mgr.is_running:
        return jsonify({"success": False, "message": "Pipeline is not running."}), 400

    mgr.stop_pipeline()
    return jsonify({"success": True, "message": "Packet capture and analysis stopped."})


@api_bp.route("/interfaces", methods=["GET"])
def get_interfaces():
    """Enumerate all network interfaces on the system."""
    try:
        ifaces = list_network_interfaces()
        return jsonify({"success": True, "interfaces": ifaces})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/stats/realtime", methods=["GET"])
def get_realtime_stats():
    """Instantaneous traffic velocity and protocol breakdown for SOC gauges."""
    mgr = get_manager()
    summary = mgr.flow_analyzer.get_traffic_summary()
    sniffer_metrics = mgr.sniffer.get_metrics()
    alert_counts = mgr.alert_manager.get_alert_counts_by_severity()

    return jsonify({
        "success": True,
        "is_running": mgr.is_running,
        "current_pps": summary["current_pps"],
        "current_bps": summary["current_bps"],
        "total_packets": summary["total_packets"],
        "total_bytes": summary["total_bytes"],
        "protocol_distribution": summary["protocol_distribution"],
        "active_tracked_hosts": summary["active_tracked_hosts"],
        "queue_size": sniffer_metrics["queue_size"],
        "alerts_severity": alert_counts,
        "total_alerts": mgr.alert_manager.get_total_alert_count(),
    })


@api_bp.route("/stats/history", methods=["GET"])
def get_stats_history():
    """Time-series snapshots for Chart.js line graphs."""
    mgr = get_manager()
    limit = request.args.get("limit", default=60, type=int)
    history = mgr.db.get_traffic_history(limit=limit)
    return jsonify({"success": True, "history": history})


@api_bp.route("/alerts", methods=["GET"])
def get_alerts():
    """Query security alerts with pagination, severity filtering, and keyword search."""
    mgr = get_manager()
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)
    severity = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    status = request.args.get("status")
    search = request.args.get("search")

    alerts = mgr.db.get_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        attack_type=attack_type,
        status=status,
        search=search,
    )
    return jsonify({"success": True, "count": len(alerts), "alerts": alerts})


@api_bp.route("/alerts/summary", methods=["GET"])
def get_alerts_summary():
    """Aggregate threat analytics (severities, top talkers, attack distributions)."""
    mgr = get_manager()
    stats = mgr.db.get_alert_statistics()
    return jsonify({"success": True, "statistics": stats})


@api_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id: int):
    """Change incident status ('NEW' -> 'ACKNOWLEDGED' -> 'RESOLVED')."""
    mgr = get_manager()
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "")

    success = mgr.db.update_alert_status(alert_id, new_status)
    if success:
        return jsonify({"success": True, "message": f"Alert #{alert_id} status updated to {new_status.upper()}"})
    return jsonify({"success": False, "message": "Invalid status or alert ID not found."}), 400


@api_bp.route("/packets", methods=["GET"])
def get_recent_packets():
    """Query recent sampled forensic packet logs."""
    mgr = get_manager()
    limit = request.args.get("limit", default=50, type=int)
    search = request.args.get("search")
    packets = mgr.db.get_recent_packets(limit=limit, search=search)
    return jsonify({"success": True, "count": len(packets), "packets": packets})


@api_bp.route("/simulate", methods=["POST"])
def trigger_simulation():
    """
    Trigger a safe localhost attack simulation from the dashboard UI.
    Runs asynchronously in a background thread so the HTTP request returns immediately.
    """
    data = request.get_json(silent=True) or {}
    attack = data.get("attack", "all").lower()

    def run_sim():
        try:
            if attack in ["portscan", "all"]:
                simulate_port_scan("127.0.0.1", 20, 38)
            if attack in ["synflood", "all"]:
                simulate_syn_flood("127.0.0.1", 80, count=60)
            if attack in ["icmpflood", "all"]:
                simulate_icmp_flood("127.0.0.1", count=50)
            if attack in ["xmas", "all"]:
                simulate_stealth_xmas("127.0.0.1", 80)
            if attack in ["suspicious", "all"]:
                simulate_suspicious_port("127.0.0.1", 4444)
        except Exception as ex:
            print(f"[SIMULATION ERROR] {ex}")

    sim_thread = threading.Thread(target=run_sim, daemon=True)
    sim_thread.start()

    return jsonify({
        "success": True,
        "message": f"Safe attack simulation '{attack}' dispatched to localhost.",
    })


@api_bp.route("/export/alerts", methods=["GET"])
def export_alerts():
    """Export security incident logs as CSV or JSON report."""
    mgr = get_manager()
    export_format = request.args.get("format", default="csv").lower()
    alerts = mgr.db.get_alerts(limit=5000)

    if export_format == "json":
        return Response(
            json.dumps(alerts, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=nids_security_report.json"},
        )

    # Default CSV Export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Alert ID", "Timestamp", "Attack Type", "Severity", "Source IP",
        "Source Port", "Destination IP", "Destination Port", "Protocol",
        "Incident Packets", "Status", "Description", "Mitigation Tip"
    ])

    for a in alerts:
        writer.writerow([
            a.get("id"),
            a.get("timestamp"),
            a.get("attack_type"),
            a.get("severity"),
            a.get("source_ip"),
            a.get("source_port"),
            a.get("destination_ip"),
            a.get("destination_port"),
            a.get("protocol"),
            a.get("packet_count"),
            a.get("status"),
            a.get("description"),
            a.get("mitigation_tip"),
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=nids_security_report.csv"},
    )
