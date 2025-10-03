#!/usr/bin/env python3
"""
Advanced usage example for Cordra Python Client.

This script demonstrates advanced features:
- Different authentication methods
- Error handling
- Type method calls
- Complex search queries
- ACL management
"""

import os
import sys
import json
from cordra import (
    CordraClient, DigitalObject, SearchRequest,
    CordraError, AuthenticationError, ObjectNotFoundError
)

def main():
    # Configuration
    cordra_url = os.getenv('CORDRA_URL', 'https://cordra.kikirpa.be')
    username = os.getenv('CORDRA_USERNAME')
    password = os.getenv('CORDRA_PASSWORD')
    jwt_token = os.getenv('CORDRA_JWT_TOKEN')
    user_id = os.getenv('CORDRA_USER_ID')
    private_key_file = os.getenv('CORDRA_PRIVATE_KEY_FILE')

    print(f"Advanced Cordra Client Example")
    print(f"Connecting to: {cordra_url}")

    # Initialize client
    client = CordraClient(cordra_url, api_type="rest")

    # Demonstrate different authentication methods
    auth_method = "password"  # Change to test different methods

    try:
        if auth_method == "password" and username and password:
            print("\n🔐 Testing password authentication...")
            client.authenticate(username=username, password=password)
            print("✓ Password authentication successful")

        elif auth_method == "jwt" and jwt_token:
            print("\n🔐 Testing JWT authentication...")
            client.authenticate(jwt_token=jwt_token)
            print("✓ JWT authentication successful")

        elif auth_method == "private_key" and user_id and private_key_file:
            print("\n🔐 Testing private key authentication...")
            with open(private_key_file, 'r') as f:
                private_key = json.load(f)
            client.authenticate(user_id=user_id, private_key=private_key)
            print("✓ Private key authentication successful")

        else:
            print(f"\n⚠️  Using anonymous access (no authentication provided)")
            print("   Some operations may fail due to permissions")

        # Test authentication status
        print(f"\n🔍 Authentication status: {'✓ Authenticated' if client.is_authenticated() else '❌ Not authenticated'}")

        if client.is_authenticated():
            # Get token information
            token_info = client.auth.get_token_info()
            print(f"   Username: {token_info.username}")
            print(f"   User ID: {token_info.user_id}")
            print(f"   Types can create: {len(token_info.types_permitted_to_create)}")

        # Create test objects
        print("\n📝 Creating test objects...")

        # Create a document
        doc = client.create_object(
            type="Document",
            content={
                "title": "Advanced Example Document",
                "description": "Created by advanced Python client example",
                "tags": ["python", "example", "advanced"],
                "metadata": {
                    "created_by": "python_client",
                    "purpose": "demonstration"
                }
            }
        )
        print(f"✓ Created document: {doc.id}")

        # Try to create a user (may fail due to permissions)
        try:
            user = client.create_object(
                type="User",
                content={
                    "username": "test_user_" + str(int(__import__('time').time())),
                    "password": "test_password_123"
                }
            )
            print(f"✓ Created user: {user.id}")
        except Exception as e:
            print(f"⚠️  Could not create user (permissions issue): {e}")

        # Advanced search
        print("\n🔍 Testing advanced search...")

        # Simple search
        results = client.search("type:Document", pageSize=5)
        print(f"✓ Simple search found {results.size} documents")

        # Complex search with JSON query
        complex_results = client.search(queryJson={
            "query": "type:Document",
            "filter": ["title:*example*"],
            "sort": [{"field": "/title", "order": "desc"}],
            "facets": [{"field": "/tags", "maxBuckets": 3}]
        })
        print(f"✓ Complex search found {complex_results.size} documents")

        # Show facets if available
        if complex_results.facets:
            print("   Facets:")
            for facet in complex_results.facets:
                print(f"     {facet['field']}:")
                for bucket in facet['buckets'][:3]:
                    print(f"       {bucket['value']}: {bucket['count']}")

        # Type method call (if available)
        print("\n⚡ Testing type method call...")
        try:
            # Try to call a method that might exist
            result = client.call_method(
                method="getMetadata",
                object_id=doc.id
            )
            print(f"✓ Method call successful: {result}")
        except Exception as e:
            print(f"⚠️  Method call failed (method may not exist): {e}")

        # ACL operations
        print("\n🔒 Testing ACL operations...")

        try:
            # Get current ACL
            acl = client.get_acl(doc.id)
            print(f"✓ Current ACL - Readers: {len(acl.readers)}, Writers: {len(acl.writers)}")

            # Update ACL (add current user if authenticated)
            if client.is_authenticated():
                current_user = client.auth.token_info.user_id if client.auth.token_info else None
                if current_user:
                    updated_acl = client.update_acl(
                        object_id=doc.id,
                        readers=[current_user] + acl.readers,
                        writers=[current_user] + acl.writers
                    )
                    print(f"✓ Updated ACL - Readers: {len(updated_acl.readers)}, Writers: {len(updated_acl.writers)}")
        except Exception as e:
            print(f"⚠️  ACL operations failed (permissions issue): {e}")

        # Test error handling
        print("\n🛡️  Testing error handling...")

        try:
            # Try to get non-existent object
            client.get_object("nonexistent/12345")
        except ObjectNotFoundError as e:
            print(f"✓ ObjectNotFoundError caught correctly: {e}")
        except Exception as e:
            print(f"⚠️  Unexpected error for non-existent object: {e}")

        try:
            # Try to create object with invalid type
            client.create_object(type="", content={})
        except Exception as e:
            print(f"✓ Validation error caught correctly: {e}")

        # Clean up
        print("\n🧹 Cleaning up...")

        try:
            # Delete the document we created
            client.delete_object(doc.id)
            print(f"✓ Deleted document: {doc.id}")
        except Exception as e:
            print(f"⚠️  Could not delete document: {e}")

        if 'user' in locals():
            try:
                client.delete_object(user.id)
                print(f"✓ Deleted user: {user.id}")
            except Exception as e:
                print(f"⚠️  Could not delete user: {e}")

        # Logout
        if client.is_authenticated():
            client.logout()
            print("✓ Logged out")

        print("\n🎉 Advanced example completed successfully!")

    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        print("Make sure your credentials are correct and you have permissions")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def demonstrate_error_scenarios():
    """Demonstrate different error scenarios and how to handle them."""
    print("\n🛡️  Error Handling Examples:")

    client = CordraClient("https://cordra.example.com")

    # Scenario 1: Authentication error
    try:
        client.authenticate(username="wrong_user", password="wrong_password")
    except AuthenticationError as e:
        print(f"✓ AuthenticationError: {e}")

    # Scenario 2: Object not found
    try:
        client.get_object("nonexistent/123")
    except ObjectNotFoundError as e:
        print(f"✓ ObjectNotFoundError: {e}")

    # Scenario 3: Network error (would need actual network issue)
    print("✓ Network errors would be caught as CordraError")

    # Scenario 4: Validation error
    try:
        # Create object with invalid data
        client.create_object(type="", content={})
    except CordraError as e:
        print(f"✓ ValidationError: {e}")

if __name__ == "__main__":
    main()
    # Uncomment to also run error scenarios (requires no authentication)
    # demonstrate_error_scenarios()
