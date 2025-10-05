Authentication
==============

The Cordra Python Client provides comprehensive authentication support for both REST and DOIP APIs with multiple authentication methods and standardized response formats.

Overview
--------

The authentication system supports:

- **Multiple Authentication Methods**: Password, JWT tokens, private keys, and HTTP Basic authentication
- **Dual API Support**: Seamless authentication for both REST and DOIP APIs
- **Standardized Responses**: Consistent response format across all authentication methods
- **Session Management**: Token introspection, revocation, and session validation
- **API-Specific Features**: Different capabilities based on API type (REST vs DOIP)

Authentication Methods
----------------------

Password Authentication (OAuth-style)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authenticate using username and password to obtain a bearer token:

.. code-block:: python

   # Basic usage
   response = client.authenticate(username="user", password="password")

   # With detailed response
   response = client.authenticate(username="user", password="password")
   print(f"Active: {response.active}")
   print(f"Username: {response.username}")
   print(f"User ID: {response.user_id}")
   print(f"Token: {response.access_token}")

Authenticate using an existing JWT token. This token can be either:

* An ID token from a third-party OAuth2/OIDC provider (e.g., Google, ORCiD), if your Cordra instance is configured to trust that provider.
* A self-signed JWT created using a private key, where the corresponding public key is stored in a Cordra user object.

.. code-block:: python

   # Authenticate with a token from an OIDC provider or a self-signed token
   client.authenticate(jwt_token="eyJ0eXAi...")

   # With detailed response
   response = client.authenticate(jwt_token="eyJ0eXAi...")
   print(f"Active: {response.active}")
   print(f"Username: {response.username}")

Using a Self-Signed JWT (Private Key Authentication)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For self-signed JWTs, the public key must be stored in the Cordra user object.
The library provides a convenience method to create and use a JWT token internally if you provide it with the user's handle and a private key in JWK format.

.. code-block:: python

   private_key = {
       "kty": "RSA",
       "n": "your_modulus...",
       "e": "AQAB",
       "d": "your_private_exponent...",
       "p": "your_prime_factor_1...",
       "q": "your_prime_factor_2..."
   }

   # The client will create a short-lived JWT, sign it, and use it for authentication
   response = client.authenticate(user_id="user_id", private_key=private_key)
   print(f"Active: {response.active}")

**Important Notes:**

1. **Public Key Storage**: For self-signed JWT authentication, you must store the corresponding public key in Cordra:
   - As a JWK in a Cordra user object with the schema attribute ``"auth": "publicKey"``
   - Or in an ``HS_PUBKEY`` value on a Handle record

2. **Creating Keys and Tokens**: For a practical example of how to generate a compliant public/private key pair and a self-signed JWT, please see the helper script included in this project: ``/tools/create_jwt_token.py``.

3. **Required Claims**: All JWTs must contain ``iss`` (issuer) and ``exp`` (expiration) claims.
4. **Security**: JWT-based authentication is more secure than passwords as no secrets are exchanged.

HTTP Basic Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~

Authenticate using HTTP Basic authentication (no token):

.. code-block:: python

   # Basic usage - stores credentials for subsequent requests
   response = client.authenticate_basic(username="user", password="password")

   # With response information
   response = client.authenticate_basic(username="user", password="password")
   print(f"Active: {response.active}")
   print(f"Username: {response.username}")

Standardized Response Format
----------------------------

All authentication methods return an ``AuthenticationResponse`` object with the following structure:

.. code-block:: python

   {
       "active": bool,                    # Whether authentication was successful
       "username": str | None,           # Username of authenticated user
       "userId": str | None,             # User ID of authenticated user
       "typesPermittedToCreate": [...],  # Types user can create (when full=True)
       "groupIds": [...],                # Groups user belongs to (when full=True)
       "access_token": str | None,       # Bearer token (for token-based auth)
       "token_type": "Bearer"            # Token type (always "Bearer")
   }

Session Management
------------------

Checking Authentication Status
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Keep sessions alive and get up-to-date user information:

.. code-block:: python

   # Check current authentication (REST API only)
   info = client.check_credentials()
   print(f"Active: {info.active}")
   print(f"Username: {info.username}")

   # Get full user information including permissions
   info = client.check_credentials(full=True)
   print(f"Types can create: {info.types_permitted_to_create}")
   print(f"Groups: {info.group_ids}")

Token Management
~~~~~~~~~~~~~~~~

Manage authentication tokens:

.. code-block:: python

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

API-Specific Differences
------------------------

REST API Authentication
~~~~~~~~~~~~~~~~~~~~~~~

- **Basic Auth**: Uses ``/check-credentials`` endpoint
- **Token Auth**: Uses ``/auth/token``, ``/auth/introspect``, ``/auth/revoke`` endpoints
- **Session Management**: ``check_credentials()`` method available

DOIP API Authentication
~~~~~~~~~~~~~~~~~~~~~~~

- **Basic Auth**: Uses ``0.DOIP/Op.Hello`` operation
- **Token Auth**: Uses same REST endpoints (inherits authentication from REST)
- **Session Management**: ``check_credentials()`` method **not available**

Error Handling
--------------

Authentication failures raise ``AuthenticationError``:

.. code-block:: python

   from cordra import AuthenticationError

   try:
      client.authenticate(username="wrong", password="wrong")
   except AuthenticationError as e:
      print(f"Authentication failed: {e}")

Advanced Configuration
----------------------

Custom Authentication Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All authentication methods support additional parameters:

.. code-block:: python

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

Authentication State
~~~~~~~~~~~~~~~~~~~~

Check authentication status:

.. code-block:: python

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

Examples by API Type
--------------------

REST API Example
~~~~~~~~~~~~~~~~

.. code-block:: python

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

DOIP API Example
~~~~~~~~~~~~~~~~

.. code-block:: python

   from cordra import CordraClient

   # Initialize DOIP client
   client = CordraClient("https://cordra.example.com", api_type="doip")

   # Authenticate with password (uses same REST endpoints)
   response = client.authenticate(username="user", password="password")
   print(f"Authenticated as: {response.username}")

   # DOIP doesn't support check_credentials, but token introspection works
   info = client.introspect_token(full=True)
   print(f"Can create: {info.types_permitted_to_create}")

   # Use the client for operations
   obj = client.create_object(type="Document", content={"title": "Test"})

   # Logout
   client.logout()

Authentication Flow Summary
---------------------------

1. **Choose API type** (REST or DOIP)
2. **Authenticate** using preferred method
3. **Check session** (REST only) or **introspect token** (both APIs)
4. **Perform operations** with authenticated client
5. **Logout** to clear authentication state

Technical Details
-----------------

Endpoint Mapping
~~~~~~~~~~~~~~~~

**REST API Endpoints:**

- ``POST /auth/token`` - OAuth-style authentication
- ``GET /check-credentials`` - Basic authentication validation
- ``POST /auth/introspect`` - Token introspection
- ``POST /auth/revoke`` - Token revocation

**DOIP API Endpoints:**

- ``POST /0.DOIP/Op.Hello`` - Basic authentication
- ``POST /20.DOIP/Op.Auth.Introspect`` - Token introspection
- ``POST /20.DOIP/Op.Auth.Revoke`` - Token revocation

Response Object
~~~~~~~~~~~~~~~

.. autoclass:: cordra.models.AuthenticationResponse
   :members:
   :undoc-members:
   :show-inheritance:

Client Methods
~~~~~~~~~~~~~~

Authentication-related client methods:

.. automethod:: cordra.client.CordraClient.authenticate
.. automethod:: cordra.client.CordraClient.authenticate_basic
.. automethod:: cordra.client.CordraClient.check_credentials
.. automethod:: cordra.client.CordraClient.introspect_token
.. automethod:: cordra.client.CordraClient.logout

Authentication Manager Classes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: cordra.auth.AuthenticationManager
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: cordra.auth.RestAuthenticationManager
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: cordra.auth.DoipAuthenticationManager
   :members:
   :undoc-members:
   :show-inheritance:
