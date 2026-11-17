"""
Global configuration file for Intelligent Network Intrusion Detection System.
All detection thresholds, paths, and server settings are managed here.
"""

import os

# Project Base Directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database Configuration
DATABASE_PATH = os.path.join(BASE_DIR, "database", "ids_database.db")

# Detection Thresholds (Rule-Based Engine)
DETECTION_CONFIG = {
    # Port Scanning: Max distinct destination ports contacted by a single IP within window
    "PORT_SCAN_THRESHOLD": 15,
    "PORT_SCAN_WINDOW_SECONDS": 5.0,
    
    # SYN Flood: Max SYN packets per second from a host / half-open ratio
    "SYN_FLOOD_PPS_THRESHOLD": 50,
    "SYN_FLOOD_RATIO_THRESHOLD": 0.80,   # 80% or more packets are SYN without ACK
    "SYN_FLOOD_WINDOW_SECONDS": 3.0,
    
    # ICMP Flood: Max ICMP Echo Requests per second
    "ICMP_FLOOD_PPS_THRESHOLD": 40,
    "ICMP_FLOOD_WINDOW_SECONDS": 2.0,
    
    # Alert Throttling: Suppress duplicate alerts for same (attack_type, src_ip) for N seconds
    "ALERT_COOLDOWN_SECONDS": 30.0,
    
    # High-Risk Suspicious Ports (Backdoors, Trojans, Exploit targets)
    "SUSPICIOUS_PORTS": {
        4444: "Metasploit Default Payload Listener",
        31337: "Back Orifice Trojan Port",
        1337: "Common Hacker / Exploit Shell Port",
        6667: "IRC Botnet Command & Control",
        8888: "Suspicious HTTP Alternative / C2 Proxy",
        5555: "Android ADB Remote Debugging Exploit",
    }
}

# Flask Web Server Settings
WEB_CONFIG = {
    "HOST": "127.0.0.1",
    "PORT": 80,
    "FALLBACK_PORT": 5000,
    "DOMAIN": "nids.local",
    "DEBUG": False,
    "SECRET_KEY": "intelligent-nids-security-secret-key-soc-2026",
}

# Terminal SOC Operator Authentication Settings
AUTH_CONFIG = {
    "ENABLED": True,
    "MAX_ATTEMPTS": 3,
    "DEFAULT_USER": "admin_aravindan",
    # SHA-256 cryptographic hash of default password "soc@2026"
    "PASSWORD_HASH": "3e742152399ab18ef5be49ee9e2e3acbcb4bb621f85935565a86cff008a084b9",
    "PASSWORD_HINT": "Aravindan@27",
}

# Safe Testing & Network Boundary Settings
TESTING_CONFIG = {
    "SAFE_HOST": "127.0.0.1",
    "ALLOWED_SUBNETS": ["127.0.0.1/32", "192.168.56.0/24"],  # Localhost & VirtualBox Host-Only
}
