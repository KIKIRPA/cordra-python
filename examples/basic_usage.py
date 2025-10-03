#!/usr/bin/env python3
"""
Basic usage example for Cordra Python Client.

This script demonstrates the basic operations with Cordra:
- Authentication
- Creating objects
- Searching objects
- Calling type methods
"""

import os
import sys

from cordra import CordraClient, DigitalObject


def main():
    # Get Cordra server URL from environment or use default
    cordra_url = os.getenv("CORDRA_URL", "https://cordra.kikirpa.be")
    username = os.getenv("CORDRA_USERNAME")
    password = os.getenv("CORDRA_PASSWORD")

    if not username or not password:
        print("Please set CORDRA_USERNAME and CORDRA_PASSWORD environment variables")
        sys.exit(1)

    print(f"Connecting to Cordra at {cordra_url}")

    try:
        # Initialize client
        client = CordraClient(cordra_url, api_type="rest")

        # Authenticate
        print("Authenticating...")
        client.authenticate(username=username, password=password)
        print("✓ Authentication successful")

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

        # Call a type method (if available)
        print("\nTrying to call a type method...")
        try:
            # This would call a method named 'getWordCount' on the Document type
            # Uncomment if you have such a method defined in your Cordra schema
            # result = client.call_method(
            #     method="getWordCount",
            #     object_id=obj.id
            # )
            # print(f"✓ Word count: {result}")

            print(
                "  (No type method called - uncomment code above if you have custom methods)"
            )

        except Exception as e:
            print(f"  (Type method call failed: {e})")

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

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
