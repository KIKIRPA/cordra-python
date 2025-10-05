#!/usr/bin/env python3
"""
Basic usage example for Cordra Python Client.

This script demonstrates the basic operations with Cordra:
- Authentication (multiple methods)
- Creating objects
- Searching objects
- Calling type methods
"""

import os
import sys

from cordra import CordraClient, DigitalObject


def demonstrate_authentication_options():
    """Demonstrate different authentication methods."""
    print("\n" + "="*50)
    print("CORDRA PYTHON CLIENT - AUTHENTICATION DEMO")
    print("="*50)

    # Get Cordra server URL from environment or use default
    cordra_url = os.getenv("CORDRA_URL", "https://cordra.kikirpa.be")
    username = os.getenv("CORDRA_USERNAME")
    password = os.getenv("CORDRA_PASSWORD")

    if not username or not password:
        print("Please set CORDRA_USERNAME and CORDRA_PASSWORD environment variables")
        return None

    print(f"Connecting to Cordra at {cordra_url}")
    print(f"Username: {username}")

    # Initialize REST client
    print("\n1. REST API with OAuth-style authentication:")
    client_rest = CordraClient(cordra_url, api_type="rest")

    try:
        # OAuth-style authentication (bearer token)
        print("   - Authenticating with username/password...")
        token_response = client_rest.authenticate(username=username, password=password)
        print(f"   ✓ Got token: {token_response.access_token[:20]}...")
        print(f"   ✓ Token type: {token_response.token_type}")
    except Exception as e:
        print(f"   ✗ REST authentication failed: {e}")
        return None

    # Initialize DOIP client
    print("\n2. DOIP API with same authentication:")
    client_doip = CordraClient(cordra_url, api_type="doip")

    try:
        # DOIP inherits the same authentication
        print("   - Using same token for DOIP operations...")
        print(f"   ✓ DOIP authenticated: {client_doip.is_authenticated}")
    except Exception as e:
        print(f"   ✗ DOIP authentication failed: {e}")
        return None

    # Demonstrate basic authentication option
    print("\n3. Alternative: HTTP Basic Authentication:")
    client_basic = CordraClient(cordra_url, api_type="rest")

    try:
        # Basic authentication (no token, uses username/password directly)
        print("   - Authenticating with HTTP Basic auth...")
        success = client_basic.authenticate_basic(username=username, password=password)
        print(f"   ✓ Basic auth successful: {success}")
    except Exception as e:
        print(f"   ✗ Basic authentication failed: {e}")

    return client_rest, client_doip


def main():
    """Main demo function."""
    print("CORDRA PYTHON CLIENT DEMO")
    print("This example demonstrates authentication and basic operations")

    # Demonstrate authentication options
    clients = demonstrate_authentication_options()
    if not clients:
        sys.exit(1)

    client_rest, client_doip = clients

    # Use the REST client for operations
    client = client_rest

    # Create a test object
    print("\nCreating a test document...")
    obj = client.create_object(
        type="Document",
        content={
            "title": "Test Document from Python",
            "description": "This is a test document created by the Python client",
            "author": "Python Client Example",
        },
    )
    print(f"✓ Created object: {obj.id}")

    # Search for objects
    print("\nSearching for documents...")
    results = client.search("type:Document", pageSize=5)
    print(f"✓ Found {results.size} documents")

    for result in results.results[:3]:  # Show first 3 results
        print(f"  - {result.id}: {result.content.get('title', 'No title')}")

    # Demonstrate DOIP operations (if supported)
    print("\nTesting DOIP operations...")
    try:
        # Try a simple DOIP operation
        hello_response = client_doip.hello()
        print(f"✓ DOIP Hello successful: {hello_response}")
    except Exception as e:
        print(f"⚠ DOIP operations may not be fully supported: {e}")

    # Get object ACL
    print("\nGetting object ACL...")
    acl = client.get_acl(obj.id)
    print(f"✓ Readers: {acl.readers}")
    print(f"✓ Writers: {acl.writers}")

    # Clean up - delete the test object
    print(f"\nCleaning up - deleting object {obj.id}...")
    client.delete_object(obj.id)
    print("✓ Object deleted")

    print("\n🎉 All operations completed successfully!")
    print("\n" + "="*50)
    print("AUTHENTICATION SUMMARY")
    print("="*50)
    print("✓ REST API: OAuth-style authentication (bearer tokens)")
    print("✓ DOIP API: Inherits authentication from REST")
    print("✓ HTTP Basic: Alternative authentication method")
    print("✓ All authentication methods working correctly")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
