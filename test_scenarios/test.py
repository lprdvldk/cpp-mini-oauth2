#!/usr/bin/env python3
"""
Interactive test client for the OAuth2 CLI server.
Runs test scenarios and maintains access/refresh tokens across calls.
"""

import subprocess
import json
import os
import sys
import time

# Path to the compiled CLI server
CLI_SERVER = "./build/cli-server"

# Temporary directory for request/response JSON files
TMP_DIR = "./tmp_tests"

# Global tokens
ACCESS_TOKEN = ""
REFRESH_TOKEN = ""


def setup():
    """Create temporary directory if it doesn't exist."""
    os.makedirs(TMP_DIR, exist_ok=True)
    if not os.path.isfile(CLI_SERVER):
        print(f"Error: {CLI_SERVER} not found. Please build the project first.")
        sys.exit(1)


def run_request(endpoint, input_data):
    """
    Write input_data to a temporary JSON file, run the CLI server,
    read and return the response as a dict.
    """
    timestamp = int(time.time() * 1000)
    input_file = os.path.join(TMP_DIR, f"req_{timestamp}_in.json")
    output_file = os.path.join(TMP_DIR, f"req_{timestamp}_out.json")

    with open(input_file, "w") as f:
        json.dump(input_data, f, indent=2)

    print(f"=== Request to {endpoint} ===")
    print(json.dumps(input_data, indent=2))
    print()

    try:
        subprocess.run([CLI_SERVER, endpoint, input_file, output_file],
                       check=True, capture_output=False)
    except subprocess.CalledProcessError as e:
        print(f"Server returned non-zero exit code: {e.returncode}")
        return None

    try:
        with open(output_file, "r") as f:
            response = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Failed to read response: {e}")
        return None

    print("=== Response ===")
    print(json.dumps(response, indent=2))
    print()
    return response


def do_password():
    """Scenario 1: Password Grant"""
    print("--- Scenario 1: Password Grant ---")
    request = {
        "grant_type": "password",
        "username": "alice",
        "password": "password",
        "client_id": "cli-001",
        "client_secret": "secret",
        "scopes": ["payments:read", "payments:write"]
    }
    response = run_request("/token", request)
    if response and "access_token" in response:
        global ACCESS_TOKEN, REFRESH_TOKEN
        ACCESS_TOKEN = response["access_token"]
        REFRESH_TOKEN = response.get("refresh_token", "")
        print(f"OK. Access token: {ACCESS_TOKEN[:20]}...")
        if REFRESH_TOKEN:
            print(f"OK. Refresh token: {REFRESH_TOKEN[:20]}...")
    else:
        print("WARNING. Failed to obtain tokens.")


def do_client_credentials():
    """Scenario 2: Client Credentials Grant"""
    print("--- Scenario 2: Client Credentials Grant ---")
    request = {
        "grant_type": "client_credentials",
        "client_id": "cli-001",
        "client_secret": "secret",
        "scopes": ["payments:read"]
    }
    run_request("/token", request)


def do_refresh():
    """Scenario 3: Refresh Token Rotation"""
    print("--- Scenario 3: Refresh Token Rotation ---")
    global ACCESS_TOKEN, REFRESH_TOKEN
    if not REFRESH_TOKEN:
        print("No refresh token available. Obtaining via password grant...")
        do_password()
        if not REFRESH_TOKEN:
            print("Cannot proceed with refresh. Aborting.")
            return

    request = {
        "grant_type": "refresh_token",
        "refresh_token": REFRESH_TOKEN,
        "client_id": "cli-001",
        "client_secret": "secret"
    }
    response = run_request("/token/refresh", request)
    if response and "access_token" in response:
        ACCESS_TOKEN = response["access_token"]
        REFRESH_TOKEN = response.get("refresh_token", "")
        print("OK. Refresh successful.")
    else:
        print("WARNING. Refresh failed.")


def do_payments_get():
    """Scenario 4: Resource Server GET (requires payments:read)"""
    print("--- Scenario 4: Resource Server GET ---")
    global ACCESS_TOKEN
    if not ACCESS_TOKEN:
        print("No access token. Obtaining via password grant...")
        do_password()
        if not ACCESS_TOKEN:
            print("Cannot proceed. Aborting.")
            return

    request = {
        "access_token": ACCESS_TOKEN,
        "method": "GET"
    }
    run_request("/api/payments", request)


def do_payments_post():
    """Scenario 5: Resource Server POST (requires payments:write)"""
    print("--- Scenario 5: Resource Server POST ---")
    global ACCESS_TOKEN
    if not ACCESS_TOKEN:
        print("No access token. Obtaining via password grant...")
        do_password()
        if not ACCESS_TOKEN:
            print("Cannot proceed. Aborting.")
            return

    request = {
        "access_token": ACCESS_TOKEN,
        "method": "POST"
    }
    run_request("/api/payments", request)


def do_revoke():
    """Scenario 6: Revoke Access Token"""
    print("--- Scenario 6: Revoke Access Token ---")
    global ACCESS_TOKEN
    if not ACCESS_TOKEN:
        print("No access token. Obtaining via password grant...")
        do_password()
        if not ACCESS_TOKEN:
            print("Cannot proceed. Aborting.")
            return

    request = {
        "token": ACCESS_TOKEN,
        "token_type_hint": "access_token"
    }
    run_request("/revoke", request)


def do_introspect():
    """Scenario 7: Token Introspection"""
    print("--- Scenario 7: Token Introspection ---")
    global ACCESS_TOKEN
    if not ACCESS_TOKEN:
        print("No access token. Obtaining via password grant...")
        do_password()
        if not ACCESS_TOKEN:
            print("Cannot proceed. Aborting.")
            return

    request = {
        "token": ACCESS_TOKEN
    }
    run_request("/introspect", request)


def do_payments_get_revoked():
    """Scenario 8: Access with Revoked Token (should fail)"""
    print("--- Scenario 8: Access with Revoked Token ---")
    do_revoke()
    global ACCESS_TOKEN
    if not ACCESS_TOKEN:
        print("No access token. Aborting.")
        return

    request = {
        "access_token": ACCESS_TOKEN,
        "method": "GET"
    }
    run_request("/api/payments", request)


def do_all():
    """Run all scenarios in sequence."""
    do_password()
    do_client_credentials()
    do_refresh()
    do_payments_get()
    do_payments_post()
    do_revoke()
    do_introspect()
    do_payments_get_revoked()


def print_menu():
    print("=" * 60)
    print("               OAuth2 Test Scenarios")
    print("=" * 60)
    print("  1. Password Grant (obtain tokens)")
    print("  2. Client Credentials Grant")
    print("  3. Refresh Token Rotation")
    print("  4. Resource Server GET (payments:read)")
    print("  5. Resource Server POST (payments:write)")
    print("  6. Revoke Access Token")
    print("  7. Token Introspection")
    print("  8. Access with Revoked Token (should fail)")
    print("  9. Run ALL scenarios in sequence")
    print("  0. Exit")
    print("=" * 60)
    print()

def main():
    setup()
    while True:
        print_menu()
        choice = input("Choose an option (0-9): ").strip()
        if choice == "1":
            do_password()
        elif choice == "2":
            do_client_credentials()
        elif choice == "3":
            do_refresh()
        elif choice == "4":
            do_payments_get()
        elif choice == "5":
            do_payments_post()
        elif choice == "6":
            do_revoke()
        elif choice == "7":
            do_introspect()
        elif choice == "8":
            do_payments_get_revoked()
        elif choice == "9":
            do_all()
        elif choice == "0":
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid option. Please enter a number from 0 to 9.")
        print("="*60)
        print()
        print("\nPress Enter to continue...")
        print()
        input()


if __name__ == "__main__":
    main()