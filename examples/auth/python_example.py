#!/usr/bin/env python3
"""
InferaDB Authentication Example (Python)

This example demonstrates how to:
1. Generate Ed25519 key pairs
2. Register client credentials with the management API
3. Generate JWT tokens
4. Call the InferaDB server with authentication

Requirements:
    pip install requests PyJWT cryptography

Environment Variables:
    MANAGEMENT_API_URL - Management API URL (default: http://localhost:8081)
    SERVER_URL - InferaDB server URL (default: http://localhost:8080)
    USER_EMAIL - User email for login
    USER_PASSWORD - User password for login
"""

import os
import sys
import base64
import uuid
import datetime
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Configuration
MANAGEMENT_API_URL = os.getenv("MANAGEMENT_API_URL", "http://localhost:8081")
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8080")


class InferaDBAuth:
    """InferaDB authentication helper."""

    def __init__(self, management_api_url: str, server_url: str):
        self.management_api_url = management_api_url.rstrip("/")
        self.server_url = server_url.rstrip("/")
        self.session_id = None
        self.user_id = None
        self.org_id = None
        self.vault_id = None
        self.account_id = None
        self.client_id = None
        self.cert_kid = None
        self.private_key = None

    def register_user(self, name: str, email: str, password: str) -> dict:
        """Register a new user and organization."""
        response = requests.post(
            f"{self.management_api_url}/v1/auth/register",
            json={
                "name": name,
                "email": email,
                "password": password,
                "accept_tos": True,
            },
        )
        response.raise_for_status()
        data = response.json()

        self.user_id = data["id"]
        self.org_id = data["organization_id"]

        print(f"✓ User registered: {email}")
        print(f"  User ID: {self.user_id}")
        print(f"  Org ID: {self.org_id}")

        return data

    def login(self, email: str, password: str) -> dict:
        """Login and get session token."""
        response = requests.post(
            f"{self.management_api_url}/v1/auth/login",
            json={"email": email, "password": password},
        )
        response.raise_for_status()
        data = response.json()

        self.session_id = data["session_id"]
        self.user_id = data["user_id"]

        print(f"✓ Logged in: {email}")
        print(f"  Session ID: {self.session_id}")

        # Get organization ID
        user_response = requests.get(
            f"{self.management_api_url}/v1/users/{self.user_id}",
            headers={"Authorization": f"Bearer {self.session_id}"},
        )
        user_response.raise_for_status()
        self.org_id = user_response.json()["organization_id"]

        return data

    def create_vault(self, name: str) -> dict:
        """Create a vault for data isolation."""
        response = requests.post(
            f"{self.management_api_url}/v1/vaults",
            headers={"Authorization": f"Bearer {self.session_id}"},
            json={"name": name, "organization_id": self.org_id},
        )
        response.raise_for_status()
        data = response.json()

        self.vault_id = data["id"]
        self.account_id = data["account_id"]

        print(f"✓ Vault created: {name}")
        print(f"  Vault ID: {self.vault_id}")
        print(f"  Account ID: {self.account_id}")

        return data

    def generate_ed25519_keypair(self) -> tuple:
        """Generate Ed25519 key pair for JWT signing."""
        # Generate private key
        private_key = ed25519.Ed25519PrivateKey.generate()
        self.private_key = private_key

        # Get public key
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes_raw()
        public_key_b64 = base64.b64encode(public_key_bytes).decode()

        print("✓ Ed25519 key pair generated")
        print(f"  Public key (base64): {public_key_b64[:32]}...")

        return private_key, public_key_b64

    def create_client(self, name: str) -> dict:
        """Create client credentials."""
        response = requests.post(
            f"{self.management_api_url}/v1/organizations/{self.org_id}/clients",
            headers={"Authorization": f"Bearer {self.session_id}"},
            json={"name": name},
        )
        response.raise_for_status()
        data = response.json()

        self.client_id = data["id"]

        print(f"✓ Client created: {name}")
        print(f"  Client ID: {self.client_id}")

        return data

    def register_certificate(self, name: str, public_key_b64: str) -> dict:
        """Register Ed25519 public key as a certificate."""
        response = requests.post(
            f"{self.management_api_url}/v1/organizations/{self.org_id}/clients/{self.client_id}/certificates",
            headers={"Authorization": f"Bearer {self.session_id}"},
            json={"name": name, "public_key": public_key_b64},
        )
        response.raise_for_status()
        data = response.json()

        self.cert_kid = data["kid"]

        print(f"✓ Certificate registered: {name}")
        print(f"  Certificate ID: {data['id']}")
        print(f"  KID: {self.cert_kid}")

        return data

    def generate_jwt(self, scopes: list = None, ttl_minutes: int = 5) -> str:
        """Generate JWT token for server authentication."""
        if not self.private_key:
            raise ValueError("Private key not set. Call generate_ed25519_keypair() first.")

        if scopes is None:
            scopes = ["read", "write"]

        now = datetime.datetime.now(datetime.timezone.utc)
        claims = {
            "iss": f"{self.management_api_url}/v1",
            "sub": f"client:{self.client_id}",
            "aud": self.server_url,
            "exp": int((now + datetime.timedelta(minutes=ttl_minutes)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": str(uuid.uuid4()),
            "vault": self.vault_id,
            "account": self.account_id,
            "scope": " ".join(scopes),
        }

        # Sign with Ed25519 private key
        token = jwt.encode(
            claims, self.private_key, algorithm="EdDSA", headers={"kid": self.cert_kid}
        )

        print(f"✓ JWT generated (expires in {ttl_minutes} minutes)")
        print(f"  Scopes: {', '.join(scopes)}")

        return token

    def call_server(self, token: str, endpoint: str, method: str = "POST", data: dict = None):
        """Make authenticated request to InferaDB server."""
        url = f"{self.server_url}{endpoint}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        response = requests.request(method, url, headers=headers, json=data)

        print(f"✓ Server call: {method} {endpoint}")
        print(f"  Status: {response.status_code}")

        return response


def main():
    """Main example flow."""
    print("=" * 60)
    print("InferaDB Authentication Example (Python)")
    print("=" * 60)
    print()

    # Initialize auth helper
    auth = InferaDBAuth(MANAGEMENT_API_URL, SERVER_URL)

    # Get user credentials from environment or prompt
    email = os.getenv("USER_EMAIL") or input("Email: ")
    password = os.getenv("USER_PASSWORD") or input("Password: ")

    # Option 1: Register new user (uncomment if needed)
    # auth.register_user("Test User", email, password)

    # Option 2: Login with existing user
    try:
        auth.login(email, password)
    except requests.HTTPError as e:
        if e.response.status_code == 401:
            print("Login failed. Registering new user...")
            auth.register_user("Test User", email, password)
            auth.login(email, password)
        else:
            raise

    # Create vault
    vault_name = f"Example Vault {uuid.uuid4().hex[:8]}"
    auth.create_vault(vault_name)

    # Generate Ed25519 key pair
    private_key, public_key_b64 = auth.generate_ed25519_keypair()

    # Create client
    client_name = f"Example Client {uuid.uuid4().hex[:8]}"
    auth.create_client(client_name)

    # Register certificate
    cert_name = f"Example Certificate {uuid.uuid4().hex[:8]}"
    auth.register_certificate(cert_name, public_key_b64)

    print()
    print("=" * 60)
    print("Authentication Setup Complete!")
    print("=" * 60)
    print()

    # Generate JWT
    token = auth.generate_jwt(scopes=["read", "write"], ttl_minutes=5)

    print()
    print("JWT Token (first 100 chars):")
    print(token[:100] + "...")
    print()

    # Example: Evaluate permission
    print("=" * 60)
    print("Example: Evaluate Permission")
    print("=" * 60)
    print()

    evaluation_data = {
        "evaluations": [
            {"subject": "user:alice", "resource": "document:readme", "permission": "viewer"}
        ]
    }

    try:
        response = auth.call_server(token, "/v1/evaluate", "POST", evaluation_data)
        print(f"Response: {response.json()}")
    except requests.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}")

    print()

    # Example: Write relationship
    print("=" * 60)
    print("Example: Write Relationship")
    print("=" * 60)
    print()

    write_data = {
        "relationships": [
            {"resource": "document:readme", "relation": "viewer", "subject": "user:alice"}
        ]
    }

    try:
        response = auth.call_server(token, "/v1/relationships/write", "POST", write_data)
        print(f"Response: {response.json() if response.status_code == 200 else response.text}")
    except requests.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}")

    print()
    print("=" * 60)
    print("Example Complete!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
