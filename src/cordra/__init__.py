"""
Cordra Python Client Library

A comprehensive Python library for interacting with Cordra digital object repositories
via both REST API and DOIP API.

Classes:
    CordraClient: Main client supporting both REST and DOIP APIs
    CordraRestClient: REST API implementation
    CordraDoipClient: DOIP API implementation

Example:
    >>> from cordra import CordraClient
    >>>
    >>> # Initialize client
    >>> client = CordraClient("https://cordra.example.com")
    >>>
    >>> # Authenticate
    >>> client.authenticate(username="user", password="pass")
    >>>
    >>> # Create object
    >>> obj = client.create_object(type="Document", content={"title": "My Document"})
    >>>
    >>> # Search objects
    >>> results = client.search("type:Document")
    >>>
    >>> # Call type method
    >>> result = client.call_method(object_id=obj["id"], method="myCustomMethod")
"""

from .client import CordraClient, CordraRestClient, CordraDoipClient
from .auth import AuthenticationManager, TokenResponse
from .models import DigitalObject, SearchRequest, SearchResponse
from .exceptions import CordraError, AuthenticationError, ObjectNotFoundError

__version__ = "0.1.0"
__all__ = [
    "CordraClient",
    "CordraRestClient",
    "CordraDoipClient",
    "AuthenticationManager",
    "TokenResponse",
    "DigitalObject",
    "SearchRequest",
    "SearchResponse",
    "CordraError",
    "AuthenticationError",
    "ObjectNotFoundError",
]
