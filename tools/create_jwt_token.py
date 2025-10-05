#!/usr/bin/env python3
"""
Key Pair Generation for Cordra Private Key Authentication Testing

This script generates a key pair for testing Cordra private key authentication.
It outputs both the public key (for storing in Cordra) and the private key (for use in test scripts).
"""

import json
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import sys

def _int_to_base64url(n: int) -> str:
    """Converts an integer to a Base64URL-encoded string."""
    # The number of bytes must be minimal, so we calculate the bit length
    length = (n.bit_length() + 7) // 8
    # Convert the integer to bytes in big-endian order
    n_bytes = n.to_bytes(length, "big")
    # Base64URL encode and remove padding
    return base64.urlsafe_b64encode(n_bytes).decode("ascii").rstrip("=")

def generate_key_pair():
    """Generate RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    # Get public key components
    public_numbers = public_key.public_numbers()
    private_numbers = private_key.private_numbers()

    # Create JWK format public key, encoding numbers as Base64URL
    public_jwk = {
        "kty": "RSA",
        "n": _int_to_base64url(public_numbers.n),
        "e": _int_to_base64url(public_numbers.e),
    }

    # Create sample private key in JWK format (for testing)
    # In production, you'd load this from secure storage
    private_jwk = {
        "kty": "RSA",
        "n": _int_to_base64url(public_numbers.n),
        "e": _int_to_base64url(public_numbers.e),
        "d": _int_to_base64url(private_numbers.d),
        "p": _int_to_base64url(private_numbers.p),
        "q": _int_to_base64url(private_numbers.q),
    }

    # Remove None values
    private_jwk = {k: v for k, v in private_jwk.items() if v is not None}

    return public_jwk, private_jwk, private_key


def create_sample_jwt(user_id, private_key):
    """Create a sample JWT for testing."""
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": user_id,
        "sub": user_id,
        "exp": int(time.time()) + 3600,
        # "jti": str(uuid.uuid4()),
        # "aud": "test/cordra",
    }

    # Base64url encode
    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )

    # Data to sign
    to_sign = f"{header_b64}.{payload_b64}".encode("utf-8")

    # Sign the data
    signature = private_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())

    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def main():
    """Generate key pair and sample JWT for testing."""
    print("Cordra JWT Authentication Setup Helper")
    print("=" * 40)
    print()
    print("This script will generate a public/private key pair and a signed JWT")
    print("for testing public key authentication with Cordra.")
    print()

    # --- Step 1: Explain Schema Requirements ---
    print("STEP 1: Verify Your Cordra 'User' Schema")
    print("-" * 40)
    print("Before you begin, ensure the 'User' type schema in your Cordra instance")
    print("is configured to support public key authentication.")
    print("The schema must have a 'publicKey' property with type 'object' and a")
    print("special 'cordra' annotation.")
    print()
    print("Example 'publicKey' property in your User schema:")
    print("```json")
    print(
        json.dumps(
            {
                "publicKey": {
                    "type": "object",
                    "format": "json",
                    "title": "Public Key",
                    "description": "User's public key in JWK format for authentication.",
                    "cordra": {"auth": "publicKey"},
                }
            },
            indent=2,
        )
    )
    print("```")
    print()
    input("Press Enter to continue when your schema is ready...")
    print()

    # --- Step 2: Get Username ---
    print("STEP 2: Specify User")
    print("-" * 40)
    user_id = input(
        "Enter the username or handle of the Cordra user (e.g., test_user): "
    )
    if not user_id:
        print("Username cannot be empty. Exiting.")
        sys.exit(1)
    print()

    # --- Step 3: Generate and Display Keys/Token ---
    print("STEP 3: Generate and Configure Keys")
    print("-" * 40)
    print(f"Generating keys and a JWT for user: '{user_id}'...")
    print()

    # Generate key pair
    public_key, _, private_key = generate_key_pair()

    print("✅ Generation Complete. Please follow the steps below.")
    print()
    print("-" * 40)
    print("📋 ACTION 1: UPDATE CORDRA USER OBJECT")
    print("-" * 40)
    print(f"Edit the user object for '{user_id}' in Cordra and paste the")
    print("following JSON into the 'publicKey' field.")
    print()
    print("--- COPY PUBLIC KEY BELOW ---")
    print(json.dumps(public_key, indent=2))
    print("--- END PUBLIC KEY ---")
    print()
    print("-" * 40)
    print("🎫 ACTION 2: USE THIS JWT FOR AUTHENTICATION")
    print("-" * 40)
    print("Copy the following token and use it in your client application.")
    print()
    sample_jwt = create_sample_jwt(user_id, private_key)
    print("--- COPY JWT TOKEN BELOW ---")
    print(sample_jwt)
    print("--- END JWT TOKEN ---")
    print()


if __name__ == "__main__":
    main()
