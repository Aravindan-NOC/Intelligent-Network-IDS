"""
HTML View Routes for Intelligent NIDS SOC Dashboard.
"""

from flask import Blueprint, render_template

view_bp = Blueprint("views", __name__)


@view_bp.route("/")
def dashboard():
    """Main SOC Security Operations Center Dashboard."""
    return render_template("dashboard.html", active_page="dashboard")


@view_bp.route("/alerts")
def alerts():
    """Security Incident Logs & Investigation View."""
    return render_template("alerts.html", active_page="alerts")


@view_bp.route("/packets")
def packets():
    """Live Packet Inspector Forensics Table."""
    return render_template("packets.html", active_page="packets")


@view_bp.route("/reports")
def reports():
    """Security Reports, Analytics, and Audit Exports."""
    return render_template("reports.html", active_page="reports")
