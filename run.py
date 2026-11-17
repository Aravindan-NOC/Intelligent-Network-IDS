"""
Master Application Entry Point for Intelligent NIDS.

Initializes the NIDS Pipeline Manager (Sniffer + Flow Analyzer + Rule Engine + SQLite WAL DB)
and launches the Flask Web Server and SOC Dashboard.
"""

import sys
import os
import argparse
import logging
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config
from core.network_utils import is_admin, check_npcap_installed, get_default_monitoring_interface
from core.auth import authenticate_terminal_user
from web.app import NIDSSystemManager, create_app

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("NIDS.Master")


def print_banner(host: str, port: int, interface: str, is_elevated: bool):
    """Print SOC startup banner."""
    port_str = f":{port}" if port != 80 else ""
    domain = config.WEB_CONFIG.get("DOMAIN", "nids.local")
    print("=" * 72)
    print("   INTELLIGENT NETWORK INTRUSION DETECTION & MONITORING SYSTEM (NIDS)  ")
    print("   B.E. Cyber Security Academic Project - Enterprise SOC Dashboard      ")
    print("=" * 72)
    print(f" [*] Primary SOC URL   : http://{domain}{port_str}")
    print(f" [*] Alternative URL   : http://{host}{port_str}")
    print(f" [*] Security Console  : http://{domain}{port_str}/alerts")
    print(f" [*] Packet Inspector  : http://{domain}{port_str}/packets")
    print(f" [*] Audit Reports     : http://{domain}{port_str}/reports")
    print("-" * 72)
    print(f" [*] Admin Privilege   : {'[YES] Elevated' if is_elevated else '[WARN] Standard User'}")
    print(f" [*] Target Interface  : {interface or 'Auto-Detect / Configured'}")
    print(f" [*] SQLite Database   : {config.DATABASE_PATH} (WAL Mode)")
    print("=" * 72)
    print(" Press Ctrl+C in this terminal to safely stop the server & sniffer.\n")


def main():
    parser = argparse.ArgumentParser(description="Intelligent NIDS - Master Server")
    parser.add_argument("--host", default=config.WEB_CONFIG.get("HOST", "127.0.0.1"), help="Flask Host IP")
    parser.add_argument("--port", type=int, default=config.WEB_CONFIG.get("PORT", 5000), help="Flask Port")
    parser.add_argument("--interface", default=None, help="Target network interface (e.g. 'Wi-Fi', 'loopback')")
    parser.add_argument("--no-autostart", action="store_true", help="Do not automatically start packet sniffer")
    parser.add_argument("--no-auth", action="store_true", help="Bypass terminal authentication (for testing/automation)")

    args = parser.parse_args()

    # 0. Terminal SOC Operator Authentication Check
    auth_enabled = getattr(config, "AUTH_CONFIG", {}).get("ENABLED", True)
    if auth_enabled and not args.no_auth and sys.stdin.isatty():
        authenticated = authenticate_terminal_user(
            max_attempts=getattr(config, "AUTH_CONFIG", {}).get("MAX_ATTEMPTS", 3)
        )
        if not authenticated:
            logger.error("Authentication failed. Aborting startup.")
            sys.exit(1)

    elevated = is_admin()
    if not elevated:
        logger.warning("Application running as Standard User. Live capture requires Administrator elevation.")

    # 1. Initialize central NIDS manager
    manager = NIDSSystemManager(db_path=config.DATABASE_PATH)

    # 2. Determine interface
    target_iface = args.interface or get_default_monitoring_interface() or "loopback"

    # 3. Autostart capture pipeline unless explicitly disabled
    if not args.no_autostart:
        logger.info(f"Auto-starting NIDS capture pipeline on '{target_iface}'...")
        try:
            manager.start_pipeline(interface=target_iface)
        except Exception as e:
            logger.error(f"Failed to autostart capture: {e}")

    # 4. Create Flask web app
    app = create_app(system_manager=manager)

    print_banner(args.host, args.port, manager.sniffer.active_interface or target_iface, elevated)

    # 5. Launch web server
    target_port = args.port
    try:
        app.run(
            host=args.host,
            port=target_port,
            debug=False,
            use_reloader=False,  # Prevent double-starting threads in Werkzeug
        )
    except (PermissionError, OSError) as ex:
        if target_port == 80:
            logger.warning(f"Port 80 requires elevated privileges or is busy ({ex}). Falling back to port 5000...")
            target_port = 5000
            print_banner(args.host, target_port, manager.sniffer.active_interface or target_iface, elevated)
            app.run(
                host=args.host,
                port=target_port,
                debug=False,
                use_reloader=False,
            )
        else:
            raise
    except KeyboardInterrupt:
        logger.info("Shutdown signal received (Ctrl+C).")
    finally:
        logger.info("Stopping NIDS pipeline and releasing network sockets...")
        manager.stop_pipeline()
        logger.info("NIDS Shutdown complete.")


if __name__ == "__main__":
    main()
