Error Handling
==============

The Cordra Python Client provides comprehensive error handling with detailed exception classes that map to specific HTTP status codes returned by Cordra.

HTTP Status Code Mapping
------------------------

The library automatically converts HTTP responses to appropriate exceptions:

.. list-table:: HTTP Status Code Mapping
   :header-rows: 1
   :widths: 10 20 70

   * - HTTP Status
     - Exception Class
     - Description
   * - **200 OK**
     - *(Success)*
     - Request processed successfully
   * - **400 Bad Request**
     - ``ValidationError``
     - Request validation failed (schema errors, invalid parameters)
   * - **401 Unauthorized**
     - ``AuthenticationError``
     - Authentication failed or missing (user not authenticated)
   * - **403 Forbidden**
     - ``AuthorizationError``
     - Authenticated user lacks permission for the operation
   * - **404 Not Found**
     - ``ObjectNotFoundError``
     - Requested object or resource does not exist
   * - **409 Conflict**
     - ``CordraError``
     - Handle already in use (REST API only)
   * - **500 Internal Server Error**
     - ``ServerError``
     - Unexpected server error (check server logs)

Exception Hierarchy
-------------------

.. code-block:: python

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

Error Response Details
----------------------

All exceptions include:

- **Status code**: The HTTP status code that caused the exception
- **Response data**: Parsed JSON response containing error details
- **Error message**: Human-readable error description

.. code-block:: python

   try:
       client.create_object(type="InvalidType", content={})
   except ValidationError as e:
       print(f"Status: {e.status_code}")        # 400
       print(f"Error: {e.response_data}")       # {'error': 'Schema validation failed'}
       print(f"Message: {str(e)}")              # Human-readable message

Common Error Scenarios
----------------------

Schema Validation
~~~~~~~~~~~~~~~~~

``ValidationError`` when creating/updating objects with invalid data:

.. code-block:: python

   try:
       # Missing required 'type' field
       client.create_object(content={"title": "Test"})
   except ValidationError as e:
       print(f"Schema validation failed: {e}")

Permission Denied
~~~~~~~~~~~~~~~~

``AuthorizationError`` when user lacks required permissions:

.. code-block:: python

   try:
       # User doesn't have permission to create this type
       client.create_object(type="RestrictedType", content={})
   except AuthorizationError as e:
       print(f"Insufficient permissions: {e}")

Object Missing
~~~~~~~~~~~~~

``ObjectNotFoundError`` when requesting non-existent objects:

.. code-block:: python

   try:
       client.get_object("nonexistent/12345")
   except ObjectNotFoundError as e:
       print(f"Object not found: {e}")

Authentication Required
~~~~~~~~~~~~~~~~~~~~~~~

``AuthenticationError`` for operations requiring login:

.. code-block:: python

   try:
       # Operation requires authentication
       client.create_object(type="Document", content={})
   except AuthenticationError as e:
       print(f"Authentication required: {e}")

Server Issues
~~~~~~~~~~~~

``ServerError`` for unexpected server-side problems:

.. code-block:: python

   try:
       client.search("type:Document")
   except ServerError as e:
       print(f"Server error - check server logs: {e}")

Cordra Status Codes vs HTTP Status Codes
-----------------------------------------

Cordra uses both DOIP status codes and HTTP status codes. The library primarily handles HTTP status codes, but some operations may return Cordra-specific status information:

- **DOIP Status Codes**: Used in DOIP API responses (e.g., ``0.DOIP/Status.001`` for success)
- **HTTP Status Codes**: Standard HTTP codes used by REST API
- **Library Behavior**: Converts HTTP codes to appropriate exceptions regardless of API type

Best Practices
--------------

Exception Handling Patterns
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   def safe_operation(client, object_id):
       try:
           obj = client.get_object(object_id)
           return obj
       except ObjectNotFoundError:
           print(f"Object {object_id} not found")
           return None
       except AuthenticationError:
           print("Please authenticate first")
           return None
       except AuthorizationError:
           print("Insufficient permissions")
           return None
       except (ValidationError, ServerError) as e:
           print(f"Operation failed: {e}")
           return None

Logging Errors
~~~~~~~~~~~~~~

.. code-block:: python

   import logging

   logger = logging.getLogger(__name__)

   try:
       obj = client.create_object(type="Document", content={})
   except Exception as e:
       logger.error(f"Failed to create object: {e}", exc_info=True)
       raise

Custom Error Handling
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   class DocumentService:
       def __init__(self, client):
           self.client = client

       def create_document(self, title, content):
           try:
               return self.client.create_object(
                   type="Document",
                   content={"title": title, **content}
               )
           except ValidationError as e:
               # Handle validation errors specifically
               if "title" in str(e):
                   raise ValueError("Document title is required")
               raise
           except AuthorizationError:
               raise PermissionError("Cannot create documents")
