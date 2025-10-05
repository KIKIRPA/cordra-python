# Cordra Python Client

A comprehensive Python library for interacting with Cordra digital object repositories via both REST API and DOIP API.

[![Python Version](https://img.shields.io/pypi/pyversions/cordra-python)](https://pypi.org/project/cordra-python/)
[![License](https://img.shields.io/pypi/l/cordra-python)](https://opensource.org/licenses/MIT)
[![PyPI Version](https://img.shields.io/pypi/v/cordra-python)](https://pypi.org/project/cordra-python/)

## ⚠️ Important Notice

**This package is developed and maintained by the Royal Institute for Cultural Heritage (KIK-IRPA) and is not affiliated with or endorsed by the Corporation for National Research Initiatives (CNRI), the developers of Cordra.**

**This package has been developed for and tested on Cordra version 2.5.2. While it may work with other versions, compatibility is not guaranteed.**

## Features

- **Dual API Support**: Choose between REST API or DOIP API based on your needs
- **Complete Authentication**: Support for password, JWT and private key authentication
- **Type Method Support**: Call custom JavaScript methods on objects and types
- **Batch Operations**: Upload multiple objects efficiently
- **Version Management**: Create and manage object versions
- **Relationship Queries**: Navigate object relationships
- **Comprehensive Error Handling**: Detailed exceptions for different error types
- **Type Hints**: Full type annotations for better IDE support

## Installation

```bash
pip install cordra-python
```

## Quick Start

```python
from cordra import CordraClient

# Initialize client
client = CordraClient("https://cordra.example.com")

# Authenticate
client.authenticate(username="your_username", password="your_password")

# Create an object
obj = client.create_object(
    type="Document",
    content={
        "title": "My Document",
        "description": "A sample document"
    }
)

# Search for objects
results = client.search("type:Document")

# Call a type method
result = client.call_method(
    method="extractName",
    object_id=obj.id
)
```

## API Selection

The client supports two APIs:

### REST API (Default)
- Uses standard HTTP methods (GET, POST, PUT, DELETE)
- RESTful resource URLs
- JSON payloads
- Good for web applications and general use

### DOIP API
- RPC-style API using POST operations
- Operation-based approach
- More efficient for batch operations
- Better for programmatic access

```python
# Use REST API (default)
client = CordraClient("https://cordra.example.com", api_type="rest")

# Use DOIP API
client = CordraClient("https://cordra.example.com", api_type="doip")
```

## Authentication

The library provides comprehensive authentication support for both REST and DOIP APIs with multiple authentication methods and standardized response formats.

### Authentication Methods

#### Password Authentication (OAuth-style)
Authenticate using username and password to obtain a bearer token:

```python
# Basic usage
client.authenticate(username="user", password="password")

# With detailed response
response = client.authenticate(username="user", password="password")
print(f"Active: {response.active}")
print(f"Username: {response.username}")
print(f"User ID: {response.user_id}")
print(f"Token: {response.access_token}")
```

#### JWT Token Authentication
Authenticate using an existing JWT token from an OAuth2/OIDC provider:

```python
# Basic usage
client.authenticate(jwt_token="eyJ0eXAi...")

# With detailed response
response = client.authenticate(jwt_token="eyJ0eXAi...")
print(f"Active: {response.active}")
print(f"Username: {response.username}")
```

#### Private Key Authentication
Authenticate using a self-signed JWT. The public key must be stored in the cordra user object.
The library can create a JWT token for you, if you provide it with the user's handle and a private key in JWK format.

```python
private_key = {
    "kty": "RSA",
    "n": "your_modulus...",
    "e": "AQAB",
    "d": "your_private_exponent...",
    "p": "your_prime_factor_1...",
    "q": "your_prime_factor_2...",
}

# Basic usage
client.authenticate(user_id="user_id", private_key=private_key)

# With detailed response
response = client.authenticate(user_id="user_id", private_key=private_key)
print(f"Active: {response.active}")
```

**Important Notes:**

1. **Public Key Storage**: Before using private key authentication, you must store the corresponding public key in Cordra:
   - As a JWK in a Cordra user object with schema attribute `"auth": "publicKey"`
   - Or in an HS_PUBKEY value on a Handle record

2. **JWT Creation**: The library can create a token for you, as shown in the example above. For a demo on how to create a public key and a token based on the private key, see `/tools/create_jwt_token.py`

3. **Required Claims**: `iss` (issuer), `exp` (expiration)
4. **Optional Claims**: `jti` (JWT ID), `aud` (audience), `sub` (subject)
5. **Security**: This method is more secure than passwords as no secrets are exchanged

#### HTTP Basic Authentication
Authenticate using HTTP Basic authentication (no token):

```python
# Basic usage - stores credentials for subsequent requests
client.authenticate_basic(username="user", password="password")

# With response information
response = client.authenticate_basic(username="user", password="password")
print(f"Active: {response.active}")
print(f"Username: {response.username}")
```

### Standardized Response Format

All authentication methods return an `AuthenticationResponse` object with the following structure:

```python
{
    "active": bool,                    # Whether authentication was successful
    "username": str | None,           # Username of authenticated user
    "userId": str | None,             # User ID of authenticated user
    "typesPermittedToCreate": [...],  # Types user can create (when full=True)
    "groupIds": [...],                # Groups user belongs to (when full=True)
    "access_token": str | None,       # Bearer token (for token-based auth)
    "token_type": "Bearer"            # Token type (always "Bearer")
}
```

### Session Management

#### Checking Authentication Status
Keep sessions alive and get up-to-date user information:

```python
# Check current authentication (REST API only)
info = client.check_credentials()
print(f"Active: {info.active}")
print(f"Username: {info.username}")

# Get full user information including permissions
info = client.check_credentials(full=True)
print(f"Types can create: {info.types_permitted_to_create}")
print(f"Groups: {info.group_ids}")
```

#### Token Management
Manage authentication tokens:

```python
# Introspect current token
info = client.introspect_token()
print(f"Token active: {info.active}")
print(f"Username: {info.username}")

# Introspect with full information
info = client.introspect_token(full=True)
print(f"Permissions: {info.types_permitted_to_create}")

# Revoke current token
result = client.logout()
print(f"Logged out: {not result.active}")
```

### API-Specific Differences

#### REST API Authentication
- **Basic Auth**: Uses `/check-credentials` endpoint
- **Token Auth**: Uses `/auth/token`, `/auth/introspect`, `/auth/revoke` endpoints
- **Session Management**: `check_credentials()` method available

#### DOIP API Authentication
- **Basic Auth**: Uses `0.DOIP/Op.Hello` operation via `/doip` endpoint
- **Token Auth**: Uses DOIP-specific endpoints via `/doip` endpoint (`20.DOIP/Op.Auth.Token`, `20.DOIP/Op.Auth.Introspect`, `20.DOIP/Op.Auth.Revoke`)
- **Session Management**: `check_credentials()` method **not available** (use `introspect_token()` instead)

### Error Handling

Authentication failures raise `AuthenticationError`:

```python
from cordra import AuthenticationError

try:
    client.authenticate(username="wrong", password="wrong")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
```

### Advanced Configuration

#### Custom Authentication Parameters
All authentication methods support additional parameters:

```python
# Get full user information during authentication
response = client.authenticate(
    username="user",
    password="password",
    full=True  # Include types and groups
)

# Introspect with full information
info = client.introspect_token(full=True)

# Check credentials with full information
info = client.check_credentials(full=True)
```

#### Authentication State
Check authentication status:

```python
# Check if client is authenticated
if client.is_authenticated():
    print("Client is authenticated")
else:
    print("Client is not authenticated")

# Get current authentication method
if client.auth.token:
    print("Using token authentication")
elif client.auth.username and client.auth.password:
    print("Using basic authentication")
else:
    print("Not authenticated")
```

### Examples by API Type

#### REST API Example
```python
from cordra import CordraClient

# Initialize REST client
client = CordraClient("https://cordra.example.com", api_type="rest")

# Authenticate with password
response = client.authenticate(username="user", password="password")
print(f"Authenticated as: {response.username}")

# Check session and get permissions
info = client.check_credentials(full=True)
print(f"Can create: {info.types_permitted_to_create}")

# Use the client for operations
obj = client.create_object(type="Document", content={"title": "Test"})

# Logout
client.logout()
```

#### DOIP API Example
```python
from cordra import CordraClient

# Initialize DOIP client
client = CordraClient("https://cordra.example.com", api_type="doip")

# Authenticate with password (uses DOIP-specific endpoints)
response = client.authenticate(username="user", password="password")
print(f"Authenticated as: {response.username}")

# DOIP uses token introspection instead of check_credentials
info = client.introspect_token(full=True)
print(f"Can create: {info.types_permitted_to_create}")

# Use the client for operations
obj = client.create_object(type="Document", content={"title": "Test"})

# Logout
client.logout()
```

### Authentication Flow Summary

1. **Choose API type** (REST or DOIP)
2. **Authenticate** using preferred method
3. **Check session** (REST only) or **introspect token** (both APIs)
4. **Perform operations** with authenticated client
5. **Logout** to clear authentication state

For detailed API reference, see the :doc:`authentication` documentation.

## Working with Objects

### Creating Objects
```python
# Create a simple object
obj = client.create_object(
    type="Document",
    content={"title": "My Document", "author": "John Doe"}
)

# Create with additional parameters
obj = client.create_object(
    type="Document",
    content={"title": "My Document"},
    suffix="custom_suffix",
    handle="20.5000.EXAMPLE/123456789"
)
```

**Supported Parameters:**
- `type`: Object type (e.g., "Document") **[Required]**
- `dryRun`: Validate without saving (REST only)
- `suffix`: Custom object ID suffix (REST only)
- `handle`: Specific handle for object (REST only)
- `full`: Return full object details (REST only)

**Returns:** `DigitalObject` instance with the created object's ID and metadata

### Retrieving Objects

```python
# Get object by ID
obj = client.get_object("test/123")

# Get specific payload element
obj = client.get_object("test/123", element="payload")

# Get with filters
obj = client.get_object("test/123", filter=["type:Document"])
```

**Supported Parameters:**
- `jsonPointer` (REST): JSON pointer to specific object element
- `element` (DOIP): Name of payload to retrieve
- `filter` (REST): Filter queries for object properties
- `payload` (REST): Specific payload to retrieve
- `pretty` (REST): Pretty-print JSON response
- `text` (REST): Return response as plain text
- `disposition` (REST): Content disposition for downloads
- `full` (REST): Return full object details

**Returns:** `DigitalObject` instance containing the retrieved object data

### Updating Objects
```python
# Update object content
updated_obj = client.update_object(
    object_id="test/123",
    content={"title": "Updated Title", "status": "published"}
)

# Dry run (validate without saving)
updated_obj = client.update_object(
    object_id="test/123",
    content={"title": "Updated Title"},
    dryRun=True
)
```

**Supported Parameters:**
- `dryRun`: Validate without saving (REST only)
- `type`: Override object type (REST only)
- `payloadToDelete`: Payloads to remove (REST only)
- `jsonPointer`: JSON pointer for partial updates (REST only)
- `full`: Return full object details (REST only)

**Returns:** `DigitalObject` instance with updated object data and metadata

### Deleting Objects
```python
# Delete object
success = client.delete_object("test/123")

# Delete with JSON pointer
success = client.delete_object("test/123", jsonPointer="/content/draft")
```

**Supported Parameters:**
- `jsonPointer`: JSON pointer to specific element to delete (REST only)

**Returns:** `bool` - `True` if deletion was successful


## Search Operations

### Simple Search
```python
# Search with query string
results = client.search("type:Document AND /title:test*")

# Get only object IDs
results = client.search("type:Document", ids=True)

# Paginated search
results = client.search("type:Document", pageNum=1, pageSize=10)
```

**Supported Parameters (REST API):**
- `query`: Search query string **[Required]**
- `ids`: Return only object IDs (boolean)
- `pageNum`: Page number (0-based, default: 0)
- `pageSize`: Results per page
- `sortFields`: Array of sort field objects
- `full`: Return full object details (boolean)
- `filter`: Array of filter strings
- `filterQueries`: Array of filter query strings
- `facets`: Array of facet field objects

**Returns:** `SearchResponse` instance with results, facets, and pagination info

### Advanced Search
```python
# Complex search with JSON query
results = client.search(queryJson={
    "query": "title:test",
    "filter": ["type:Document"],
    "sort": [{"field": "/title", "order": "asc"}],
    "facets": [{"field": "/author", "maxBuckets": 5}]
})

# Search with POST request
results = client.search(
    query="type:Document",
    sortFields=[{"name": "/title", "reverse": False}],
    facets=[{"field": "/author", "maxBuckets": 10}]
)
```

**Supported Parameters:**
- `query`: Search query string
- `queryJson`: Advanced JSON query object
- `ids`: Return only object IDs (boolean)
- `pageNum`: Page number (0-based, default: 0)
- `pageSize`: Results per page
- `sortFields`: Array of sort field objects
- `filterQueries`: Array of filter query strings
- `facets`: Array of facet field objects

**DOIP API Parameters:**
- `query`: Search query string **[Required]**
- `pageNum`: Page number (0-based, default: 0)
- `pageSize`: Results per page (default: -1 for all, 0 for metadata only)
- `sortFields`: Comma-separated sort specifications (e.g., "field ASC,field DESC")
- `type`: Return type ("id" or "full", default: "full")
- `facets`: JSON array of facet field objects
- `filterQueries`: JSON array of filter query strings

**Returns:** `SearchResponse` instance with results, facets, and pagination info
**Note:** When `ids=True`, results contain only object IDs as strings. When `type="id"` in DOIP, results are object ID strings.


## Type Methods

Cordra allows you to define custom JavaScript methods for object types. You can call these methods:

### Instance Methods
```python
# Call method on specific object
result = client.call_method(
    method="extractName",
    object_id="test/123",
    params={"format": "uppercase"}
)
```

### Static Methods
```python
# Call method on object type
result = client.call_method(
    method="countObjects",
    type="Document",
    params={"filter": "status:published"}
)
```

### Service Methods

```python
# Call service-level method
result = client.call_method(
    method="getSystemStats",
    object_id="service"
)
```

**Supported Parameters:**
- `objectId`: Object ID for instance methods (e.g., 'test/abc')
- `type`: Object type for static methods (e.g., 'Document')
- `method`: Method name to invoke **[Required]**
- `params`: JSON parameters for method call (URL encoded for GET)
- `attributes`: Request attributes as JSON object

**Returns:** Method response (varies by method implementation)

**Note:** Type method calls are not directly supported in DOIP API.


## Batch Operations

### Batch Upload (REST & DOIP APIs)

Both REST and DOIP APIs support efficient batch upload operations with automatic create/update logic.

#### REST API Batch Upload
```python
from cordra import DigitalObject

# Create multiple objects (may be mix of new and existing)
objects = [
    DigitalObject(type="Document", content={"title": "New Document"}),
    DigitalObject(id="existing/123", type="Document", content={"title": "Updated Document"})
]

# Upload in batch - server handles create vs update automatically
result = client.batch_upload(objects)

# With options
result = client.batch_upload(objects, failFast=True, parallel=False)
```

#### DOIP API Batch Upload
```python
# Switch to DOIP API for batch operations
client = CordraClient("https://cordra.example.com", api_type="doip")

# Upload with DOIP-specific options
result = client.batch_upload(objects, format="ndjson")
```

**Key Features:**
- **Automatic Create/Update**: Server handles object existence logic
- **Multiple Formats**: Supports JSON array, search results, and NDJSON
- **Flexible Processing**: Configurable parallel processing and error handling
- **Payload Support**: Handle file uploads with base64 encoding

**Returns:** `BatchUploadResponse` instance with success status and results for each object


## Version Management

### Publishing Versions
```python
# Publish a new version
version = client.publish_version(
    object_id="test/123",
    version_id="v2.0",
    clonePayloads=True
)
```

**Supported Parameters:**
- `versionId`: New version ID for the copy
- `clonePayloads`: Clone object payloads (boolean)

**Returns:** `VersionInfo` instance with details about the published version

### Getting Versions
```python
# Get all versions of an object
versions = client.get_versions("test/123")

for version in versions:
    print(f"Version {version.id}: {version.published_on}")
```

**Returns:** `List[VersionInfo]` - List of version information for the object


## Relationship Queries

```python
# Get objects related to this object
relationships = client.get_relationships("test/123")

# Get only outbound relationships
relationships = client.get_relationships("test/123", outboundOnly=True)

# Access related objects
for obj_id, obj_data in relationships.get('results', {}).items():
    print(f"Related: {obj_id}")
```

**Supported Parameters:**
- `outboundOnly`: Return only outbound relationships (default: false)

**Returns:** `dict` with keys: `nodes` (list of related object IDs), `edges` (relationship connections), `results` (detailed object data)


## Access Control

### Getting ACL
```python
# Get access control list
acl = client.get_acl("test/123")

print(f"Readers: {acl.readers}")
print(f"Writers: {acl.writers}")
```

**Returns:** `AclInfo` instance with readers and writers lists

### Updating ACL
```python
# Update access control
acl = client.update_acl(
    object_id="test/123",
    readers=["user1", "user2"],
    writers=["user1"]
)
```

**Returns:** `AclInfo` instance with updated readers and writers lists

**Note:** ACL operations use request body parameters rather than query parameters.


## Password Management

```python
# Change current user's password
client.change_password("new_password123")
```

**Returns:** `bool` - `True` if password change was successful

**Note:** Password management uses request body parameters rather than query parameters.

## Utility Operations

### Service Information

```python
# Get service information
info = client.hello()

print(f"Cordra version: {info['attributes']['cordraVersion']['number']}")
```

**Returns:** `dict` containing service information including version, protocol, and public key

### List Operations

```python
# List available operations
operations = client.list_operations()

for op in operations:
    print(f"Available: {op}")
```

**Returns:** `List[str]` - List of available operation identifiers

**Supported Parameters:**
- `full`: Include additional user information (REST: GET, DOIP: POST /20.DOIP/Op.Auth.Introspect)

## Error Handling

The library provides detailed exception classes that map to specific HTTP status codes returned by Cordra. When an API call fails, the appropriate exception is raised based on the response status code.

### HTTP Status Code Mapping

The library automatically converts HTTP responses to appropriate exceptions:

| HTTP Status | Exception Class | Description |
|-------------|-----------------|-------------|
| **200 OK** | *(Success)* | Request processed successfully |
| **400 Bad Request** | `ValidationError` | Request validation failed (schema errors, invalid parameters) |
| **401 Unauthorized** | `AuthenticationError` | Authentication failed or missing (user not authenticated) |
| **403 Forbidden** | `AuthorizationError` | Authenticated user lacks permission for the operation |
| **404 Not Found** | `ObjectNotFoundError` | Requested object or resource does not exist |
| **409 Conflict** | `CordraError` | Handle already in use (REST API only) |
| **500 Internal Server Error** | `ServerError` | Unexpected server error (check server logs) |

### Exception Hierarchy

```python
from cordra import (
    CordraError,           # Base exception for all Cordra errors
    AuthenticationError,   # 401 Unauthorized
    AuthorizationError,    # 403 Forbidden
    ObjectNotFoundError,   # 404 Not Found
    ValidationError,       # 400 Bad Request
    ServerError           # 500 Internal Server Error
)

try:
    obj = client.get_object("nonexistent/123")
except ObjectNotFoundError as e:
    print(f"Object not found: {e}")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except AuthorizationError as e:
    print(f"Insufficient permissions: {e}")
except ValidationError as e:
    print(f"Request validation failed: {e}")
except ServerError as e:
    print(f"Server error: {e}")
except CordraError as e:
    print(f"Cordra error: {e}")
```

### Cordra Status Codes vs HTTP Status Codes

Cordra uses both DOIP status codes and HTTP status codes. The library primarily handles HTTP status codes, but some operations may return Cordra-specific status information:

- **DOIP Status Codes**: Used in DOIP API responses (e.g., `0.DOIP/Status.001` for success)
- **HTTP Status Codes**: Standard HTTP codes used by REST API
- **Library Behavior**: Converts HTTP codes to appropriate exceptions regardless of API type

### Error Response Details

All exceptions include:
- **Status code**: The HTTP status code that caused the exception
- **Response data**: Parsed JSON response containing error details
- **Error message**: Human-readable error description

```python
try:
    client.create_object(type="InvalidType", content={})
except ValidationError as e:
    print(f"Status: {e.status_code}")        # 400
    print(f"Error: {e.response_data}")       # {'error': 'Schema validation failed'}
    print(f"Message: {str(e)}")              # Human-readable message
```

### Common Error Scenarios

- **Schema Validation**: `ValidationError` when creating/updating objects with invalid data
- **Permission Denied**: `AuthorizationError` when user lacks required permissions
- **Object Missing**: `ObjectNotFoundError` when requesting non-existent objects
- **Authentication Required**: `AuthenticationError` for operations requiring login
- **Server Issues**: `ServerError` for unexpected server-side problems

## Advanced Configuration

```python
# Custom timeout and SSL settings
client = CordraClient(
    base_url="https://cordra.example.com",
    api_type="rest",
    verify_ssl=False,  # Skip SSL verification
    timeout=60        # 60 second timeout
)
```

## Logging

Enable debug logging to see HTTP requests:

```python
import logging
import requests

# Enable HTTP request logging
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

# Or enable only for cordra client
logging.getLogger("cordra").setLevel(logging.DEBUG)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
