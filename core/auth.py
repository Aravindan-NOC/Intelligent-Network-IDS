"""
Terminal Authentication & Access Control Module for Intelligent NIDS.

Provides interactive SOC Operator authentication in PowerShell / Command Prompt
prior to initializing the network packet capture engine and Flask web server.
Uses cryptographic SHA-256 password hashing.
"""

import sys
import getpass
import hashlib
from typing import Optional

import config

DEFAULT_USERNAME = "admin"
# Default password: "soc@2026"
DEFAULT_PASSWORD_HASH = "d546128352303d1491d36cbe7ae07dae556bed41e285a90944723a6cb6031a92"


def hash_password(password: str) -> str:
    """Compute SHA-256 hash of a plaintext password."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, expected_hash: str) -> bool:
    """Securely compare SHA-256 hashes."""
    computed = hash_password(password)
    return computed == expected_hash


def authenticate_terminal_user(
    max_attempts: int = 3,
    expected_username: Optional[str] = None,
    expected_hash: Optional[str] = None,
) -> bool:
    """
    Prompt the user in the terminal for SOC credentials.
    Requires successful authentication before the NIDS engine & Web Dashboard start.

    :param max_attempts: Maximum allowed login tries before access is locked.
    :param expected_username: Authorized username (defaults to config or 'admin').
    :param expected_hash: SHA-256 hash of authorized password.
    :return: True if authentication succeeded, False otherwise.
    """
    auth_cfg = getattr(config, "AUTH_CONFIG", {})
    target_user = expected_username or auth_cfg.get("DEFAULT_USER", DEFAULT_USERNAME)
    target_hash = expected_hash or auth_cfg.get("PASSWORD_HASH", DEFAULT_PASSWORD_HASH)

    print("\n" + "=" * 72)
    print(" 🔒 SOC SECURITY GATEWAY - OPERATOR AUTHENTICATION REQUIRED")
    print("=" * 72)
    print("  Authorized access only. Enter SOC credentials to initialize the")
    print("  Intelligent NIDS Capture Pipeline and SOC Web Monitoring Console.")
    print("-" * 72)

    for attempt in range(1, max_attempts + 1):
        try:
            username = input(f" [?] Attempt {attempt}/{max_attempts} - SOC Username : ").strip()
            # getpass masks the password input on terminal for security
            password = getpass.getpass(f" [?] Attempt {attempt}/{max_attempts} - SOC Password : ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[!] Login cancelled by user. Security abort.")
            print("=" * 72 + "\n")
            return False

        if username.lower() == target_user.lower() and verify_password(password, target_hash):
            print("-" * 72)
            print(" [+] Authentication SUCCESSFUL! Access granted to SOC Administrator.")
            print(" [+] Launching NIDS Packet Engine and Web Security Dashboard...")
            print("=" * 72 + "\n")
            return True
        else:
            remaining = max_attempts - attempt
            if remaining > 0:
                print(f" [-] Invalid username or password! ({remaining} attempt(s) remaining)\n")
            else:
                print(" [-] Invalid username or password!")

    print("-" * 72)
    print(" [!] SECURITY ALERT: Maximum authentication attempts exceeded.")
    print(" [!] Access DENIED. NIDS engine and web server will NOT start.")
    print("=" * 72 + "\n")
    return False
