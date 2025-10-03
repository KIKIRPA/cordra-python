#!/usr/bin/env python3
"""
DOIP API and Batch Operations Example.

This script demonstrates using the DOIP API for:
- Batch object creation
- Version management
- Relationship queries
- Service operations
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

    print(f"Connecting to Cordra DOIP API at {cordra_url}")

    try:
        # Initialize DOIP client
        client = CordraClient(cordra_url, api_type="doip")

        # Authenticate
        print("Authenticating...")
        client.authenticate(username=username, password=password)
        print("✓ Authentication successful")

        # Get service information
        print("\nGetting service information...")
        info = client.hello()
        print(f"✓ Cordra version: {info['attributes']['cordraVersion']['number']}")
        print(f"✓ Protocol: {info['attributes']['protocol']}")

        # List available operations
        print("\nListing available operations...")
        operations = client.list_operations()
        print(f"✓ Available operations: {len(operations)}")
        for op in operations[:5]:  # Show first 5
            print(f"  - {op}")
        if len(operations) > 5:
            print(f"  ... and {len(operations) - 5} more")

        # Create multiple objects for batch upload
        print("\nCreating objects for batch upload...")
        objects = []
        for i in range(3):
            obj = DigitalObject(
                type="Document",
                content={
                    "title": f"Batch Document {i+1}",
                    "description": f"This is document {i+1} created in batch",
                    "category": "batch_example",
                    "index": i,
                },
            )
            objects.append(obj)

        # Batch upload (DOIP API only)
        print(f"\nUploading {len(objects)} objects in batch...")
        batch_result = client.batch_upload(
            objects,
            failFast=False,  # Continue on errors
            parallel=True,  # Process in parallel
        )

        print(f"✓ Batch upload completed: {batch_result.success}")
        print(f"✓ Results: {len(batch_result.results)}")

        # Get the first successfully created object
        if batch_result.results and batch_result.results[0].response_code == 200:
            first_obj_id = batch_result.results[0].response["id"]
            print(f"\nWorking with first created object: {first_obj_id}")

            # Get object details
            obj = client.get_object(first_obj_id)
            print(f"✓ Retrieved object: {obj.content['title']}")

            # Publish a version
            print("\nPublishing a version...")
            try:
                version = client.publish_version(
                    object_id=first_obj_id,
                    version_id=f"v1.0.{obj.content['index']}",
                    clonePayloads=False,
                )
                print(f"✓ Published version: {version.id}")
            except Exception as e:
                print(f"  (Version publishing not available or failed: {e})")

            # Get versions
            print("\nGetting object versions...")
            try:
                versions = client.get_versions(first_obj_id)
                print(f"✓ Found {len(versions)} versions")
                for version in versions:
                    print(f"  - {version.id} (published: {version.published_on})")
            except Exception as e:
                print(f"  (Version management not available: {e})")

            # Get relationships
            print("\nGetting object relationships...")
            try:
                relationships = client.get_relationships(first_obj_id)
                print(
                    f"✓ Found {len(relationships.get('results', {}))} related objects"
                )

                for obj_id, obj_data in list(relationships.get("results", {}).items())[
                    :3
                ]:
                    print(f"  - Related: {obj_id}")
            except Exception as e:
                print(f"  (Relationship queries not available: {e})")

        # Clean up - delete created objects
        print("\nCleaning up...")
        for result in batch_result.results:
            if result.response_code == 200:
                obj_id = result.response["id"]
                try:
                    client.delete_object(obj_id)
                    print(f"✓ Deleted object: {obj_id}")
                except Exception as e:
                    print(f"  (Failed to delete {obj_id}: {e})")

        print("\n🎉 All DOIP operations completed successfully!")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
