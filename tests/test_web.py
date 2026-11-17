"""
Unit and Integration Tests for Flask Web Application and REST API (web/).
Tests views, API telemetry, alert filtering, status updates, and report exports.
"""

import os
import sys
import tempfile
import shutil
import unittest
from flask import json

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from web.app import NIDSSystemManager, create_app
from database.models import AlertRecord


class TestWebEndpoints(unittest.TestCase):
    """Test suite validating all Flask view and REST API endpoints."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_web.db")

        # Initialize manager with temporary test DB
        self.manager = NIDSSystemManager(db_path=self.db_path)
        self.app = create_app(system_manager=self.manager)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        try:
            self.manager.stop_pipeline()
            shutil.rmtree(self.test_dir)
        except Exception:
            pass

    def test_view_routes(self):
        """Verify all HTML views render successfully (HTTP 200)."""
        routes = ["/", "/alerts", "/packets", "/reports"]
        for route in routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route {route} failed")
            self.assertIn(b"<!DOCTYPE html>", res.data)

    def test_api_status(self):
        """Verify /api/status returns operational metrics and DB health."""
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("is_running", data)
        self.assertIn("queue_size", data)
        self.assertIn("database", data)
        self.assertIn("ml_engine", data)

    def test_api_realtime_stats(self):
        """Verify /api/stats/realtime returns velocity and protocol distribution."""
        res = self.client.get("/api/stats/realtime")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("current_pps", data)
        self.assertIn("protocol_distribution", data)
        self.assertIn("total_packets", data)

    def test_api_alerts_and_summary(self):
        """Verify saving alerts and querying via /api/alerts and /api/alerts/summary."""
        # Insert test alerts directly to DB
        self.manager.db.save_alert(AlertRecord(
            attack_type="Port Scan", severity="HIGH", source_ip="10.0.0.1", destination_port=22
        ))
        self.manager.db.save_alert(AlertRecord(
            attack_type="SYN Flood", severity="CRITICAL", source_ip="10.0.0.2", destination_port=80
        ))

        # Query alerts list
        res_list = self.client.get("/api/alerts")
        self.assertEqual(res_list.status_code, 200)
        list_data = res_list.get_json()
        self.assertEqual(list_data["count"], 2)

        # Query summary
        res_sum = self.client.get("/api/alerts/summary")
        self.assertEqual(res_sum.status_code, 200)
        sum_data = res_sum.get_json()
        self.assertEqual(sum_data["statistics"]["total_alerts"], 2)
        self.assertEqual(sum_data["statistics"]["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(sum_data["statistics"]["severity_counts"]["HIGH"], 1)

    def test_api_update_alert_status(self):
        """Verify /api/alerts/<id>/status updates incident state."""
        row_id = self.manager.db.save_alert(AlertRecord(
            attack_type="ICMP Flood", severity="HIGH", source_ip="1.2.3.4"
        ))

        res = self.client.post(
            f"/api/alerts/{row_id}/status",
            data=json.dumps({"status": "ACKNOWLEDGED"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])

        # Verify DB updated
        alert = self.manager.db.get_alert_by_id(row_id)
        self.assertEqual(alert["status"], "ACKNOWLEDGED")

    def test_api_export_alerts_csv_and_json(self):
        """Verify /api/export/alerts exports valid CSV and JSON attachments."""
        self.manager.db.save_alert(AlertRecord(
            attack_type="Port Scan", severity="HIGH", source_ip="192.168.1.10"
        ))

        # CSV Export
        csv_res = self.client.get("/api/export/alerts?format=csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("text/csv", csv_res.content_type)
        self.assertIn(b"Alert ID,Timestamp,Attack Type", csv_res.data)
        self.assertIn(b"192.168.1.10", csv_res.data)

        # JSON Export
        json_res = self.client.get("/api/export/alerts?format=json")
        self.assertEqual(json_res.status_code, 200)
        self.assertIn("application/json", json_res.content_type)
        json_data = json.loads(json_res.data)
        self.assertEqual(len(json_data), 1)
        self.assertEqual(json_data[0]["source_ip"], "192.168.1.10")

    def test_api_interfaces_list(self):
        """Verify /api/interfaces enumerates network adapters."""
        res = self.client.get("/api/interfaces")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIsInstance(data["interfaces"], list)
        self.assertGreater(len(data["interfaces"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
