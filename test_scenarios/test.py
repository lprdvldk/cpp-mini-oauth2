#!/usr/bin/env python3
"""
Interactive test client for the OAuth2 CLI server.

Provides a menu-driven interface to execute common OAuth2 flows against
a local CLI-based authorization server. Manages access and refresh tokens
across calls for seamless scenario testing.
"""

import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

CLI_SERVER: Path = Path("./build/cli-server")
TMP_DIR: Path = Path("./tmp_tests")
REQUEST_TIMEOUT: int = 10  # seconds

class ServerError(Exception):
    """Raised when the CLI server returns a non-zero exit code."""

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(message)s",
)
logger = logging.getLogger("oauth2-client")

class OAuth2TestClient:
    """
    Interactive client for the OAuth2 CLI server.

    Encapsulates the server interaction logic and token state, providing
    methods for each OAuth2 flow (password, client credentials, refresh, etc.).
    """

    def __init__(self, server_path: Path, temp_dir: Path) -> None:
        """
        Initialise the client.

        Args:
            server_path: Path to the compiled CLI server executable.
            temp_dir: Directory for temporary request/response JSON files.

        Raises:
            FileNotFoundError: If the CLI server executable does not exist.
        """
        self.server_path = server_path
        self.temp_dir = temp_dir
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

        self.temp_dir.mkdir(parents=True, exist_ok=True)

        if not self.server_path.is_file():
            raise FileNotFoundError(
                f"CLI server not found at {self.server_path}. Please build the project first."
            )

    def _run(self, endpoint: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Execute a single request against the CLI server.

        Args:
            endpoint: API endpoint path (e.g. /token, /introspect).
            payload: JSON-serialisable request body.

        Returns:
            Parsed response dictionary, or ``None`` if an error occurred.
        """
        stamp = f"{int(time.time() * 1_000_000)}_{Path(str(id(self))).name}"
        input_file = self.temp_dir / f"req_{stamp}_in.json"
        output_file = self.temp_dir / f"req_{stamp}_out.json"

        try:
            input_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to write request file: %s", exc)
            return None

        logger.info("=== Request to %s ===", endpoint)
        logger.info(json.dumps(payload, indent=2))

        try:
            subprocess.run(
                [str(self.server_path), endpoint, str(input_file), str(output_file)],
                check=True,
                timeout=REQUEST_TIMEOUT,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
        except subprocess.CalledProcessError as exc:
            logger.error("Server returned non-zero exit code: %d", exc.returncode)
            return None
        except subprocess.TimeoutExpired:
            logger.error("Server request timed out after %d seconds.", REQUEST_TIMEOUT)
            return None

        try:
            response_text = output_file.read_text(encoding="utf-8")
            response = json.loads(response_text)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.error("Failed to read response: %s", exc)
            return None

        logger.info("=== Response ===")
        logger.info(json.dumps(response, indent=2))
        return response

    def _ensure_access_token(self) -> bool:
        """Obtain an access token via password grant if none exists."""
        if not self.access_token:
            logger.info("No access token available – obtaining via password grant...")
            self.do_password()
        return bool(self.access_token)

    def do_password(self) -> None:
        """Scenario 1: Password Grant – obtain user tokens."""
        logger.info("--- Password Grant ---")
        payload = {
            "grant_type": "password",
            "username": "alice",
            "password": "password",
            "client_id": "cli-001",
            "client_secret": "secret",
            "scopes": ["payments:read", "payments:write"],
        }
        resp = self._run("/token", payload)
        if resp and "access_token" in resp:
            self.access_token = resp["access_token"]
            self.refresh_token = resp.get("refresh_token")
            logger.info("Obtained access token (first 20 chars): %s...", self.access_token[:20])
            if self.refresh_token:
                logger.info("Obtained refresh token: %s...", self.refresh_token[:20])
        else:
            logger.warning("Failed to obtain tokens.")

    def do_client_credentials(self) -> None:
        """Scenario 2: Client Credentials Grant (machine-to-machine)."""
        logger.info("--- Client Credentials Grant ---")
        payload = {
            "grant_type": "client_credentials",
            "client_id": "cli-001",
            "client_secret": "secret",
            "scopes": ["payments:read"],
        }
        self._run("/token", payload)

    def do_refresh(self) -> None:
        """Scenario 3: Refresh Token Rotation."""
        logger.info("--- Refresh Token Rotation ---")
        if not self.refresh_token:
            logger.info("No refresh token – obtaining one first...")
            self.do_password()
        if not self.refresh_token:
            logger.warning("Still no refresh token. Aborting refresh flow.")
            return

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": "cli-001",
            "client_secret": "secret",
        }
        resp = self._run("/token/refresh", payload)
        if resp and "access_token" in resp:
            self.access_token = resp["access_token"]
            self.refresh_token = resp.get("refresh_token")
            logger.info("Token refresh successful.")
        else:
            logger.warning("Token refresh failed.")

    def do_payments_get(self) -> None:
        """Scenario 4: Access protected resource with GET (payments:read)."""
        logger.info("--- Resource Server GET ---")
        if not self._ensure_access_token():
            return
        self._run("/api/payments", {"access_token": self.access_token, "method": "GET"})

    def do_payments_post(self) -> None:
        """Scenario 5: Access protected resource with POST (payments:write)."""
        logger.info("--- Resource Server POST ---")
        if not self._ensure_access_token():
            return
        self._run("/api/payments", {"access_token": self.access_token, "method": "POST"})

    def do_revoke(self) -> None:
        """Scenario 6: Revoke the current access token."""
        logger.info("--- Revoke Access Token ---")
        if not self._ensure_access_token():
            return
        self._run(
            "/revoke",
            {"token": self.access_token, "token_type_hint": "access_token"},
        )

    def do_introspect(self) -> None:
        """Scenario 7: Introspect the current access token."""
        logger.info("--- Token Introspection ---")
        if not self._ensure_access_token():
            return
        self._run("/introspect", {"token": self.access_token})

    def do_payments_get_revoked(self) -> None:
        """Scenario 8: Attempt access with a revoked token (expect failure)."""
        logger.info("--- Access with Revoked Token ---")
        self.do_revoke()
        if not self.access_token:
            logger.warning("No access token to test.")
            return
        self._run("/api/payments", {"access_token": self.access_token, "method": "GET"})

    def do_all(self) -> None:
        """Run all scenarios in sequence."""
        self.do_password()
        self.do_client_credentials()
        self.do_refresh()
        self.do_payments_get()
        self.do_payments_post()
        self.do_revoke()
        self.do_introspect()
        self.do_payments_get_revoked()


MENU = """
============================================================
               OAuth2 Test Scenarios
============================================================
  1. Password Grant
  2. Client Credentials Grant
  3. Refresh Token Rotation
  4. Resource Server GET (payments:read)
  5. Resource Server POST (payments:write)
  6. Revoke Access Token
  7. Token Introspection
  8. Access with Revoked Token (should fail)
  9. Run ALL scenarios in sequence
  0. Exit
============================================================
"""

def main() -> None:
    """Entry point for the interactive test client."""
    try:
        client = OAuth2TestClient(CLI_SERVER, TMP_DIR)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        sys.exit(1)

    actions = {
        "1": client.do_password,
        "2": client.do_client_credentials,
        "3": client.do_refresh,
        "4": client.do_payments_get,
        "5": client.do_payments_post,
        "6": client.do_revoke,
        "7": client.do_introspect,
        "8": client.do_payments_get_revoked,
        "9": client.do_all,
    }

    while True:
        print(MENU)
        choice = input("Choose an option (0-9): ").strip()

        if choice == "0":
            logger.info("Exiting. Goodbye!")
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            logger.warning("Invalid option. Please enter a number between 0 and 9.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()