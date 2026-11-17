"""
Unit Tests for Terminal Authentication Module (core/auth.py).
Tests password hashing, verification, attempt limits, and terminal input mocking.
"""

import os
import sys
import unittest
from unittest.mock import patch

# Ensure project root in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.auth import hash_password, verify_password, authenticate_terminal_user


class TestTerminalAuth(unittest.TestCase):
    """Test suite for terminal authentication logic and hashing."""

    def test_hash_password_consistency(self):
        """Verify SHA-256 hash calculation is deterministic and 64-chars hex."""
        h1 = hash_password("soc@2026")
        h2 = hash_password("soc@2026")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        self.assertEqual(h1, "d546128352303d1491d36cbe7ae07dae556bed41e285a90944723a6cb6031a92")

    def test_verify_password_correct_and_incorrect(self):
        """Verify password verification matches valid string and rejects invalid."""
        expected = hash_password("secret_password_123")
        self.assertTrue(verify_password("secret_password_123", expected))
        self.assertFalse(verify_password("wrong_password", expected))
        self.assertFalse(verify_password("", expected))

    @patch("builtins.input", return_value="admin")
    @patch("getpass.getpass", return_value="soc@2026")
    def test_authenticate_success_first_attempt(self, mock_getpass, mock_input):
        """Verify successful login on first attempt."""
        result = authenticate_terminal_user(max_attempts=3)
        self.assertTrue(result)
        mock_input.assert_called_once()
        mock_getpass.assert_called_once()

    @patch("builtins.input", return_value="ADMIN")
    @patch("getpass.getpass", return_value="soc@2026")
    def test_authenticate_case_insensitive_username(self, mock_getpass, mock_input):
        """Verify username check is case-insensitive."""
        result = authenticate_terminal_user(max_attempts=3)
        self.assertTrue(result)

    @patch("builtins.input", side_effect=["admin", "admin", "admin"])
    @patch("getpass.getpass", side_effect=["wrong1", "wrong2", "wrong3"])
    def test_authenticate_failure_after_max_attempts(self, mock_getpass, mock_input):
        """Verify failed login returns False after 3 wrong attempts."""
        result = authenticate_terminal_user(max_attempts=3)
        self.assertFalse(result)
        self.assertEqual(mock_input.call_count, 3)
        self.assertEqual(mock_getpass.call_count, 3)

    @patch("builtins.input", side_effect=["admin", "admin"])
    @patch("getpass.getpass", side_effect=["wrong_pass", "soc@2026"])
    def test_authenticate_success_on_retry(self, mock_getpass, mock_input):
        """Verify successful login on second attempt after 1 failure."""
        result = authenticate_terminal_user(max_attempts=3)
        self.assertTrue(result)
        self.assertEqual(mock_input.call_count, 2)
        self.assertEqual(mock_getpass.call_count, 2)

    @patch("builtins.input", side_effect=KeyboardInterrupt)
    def test_authenticate_abort_on_interrupt(self, mock_input):
        """Verify graceful abort if user presses Ctrl+C during prompt."""
        result = authenticate_terminal_user(max_attempts=3)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
