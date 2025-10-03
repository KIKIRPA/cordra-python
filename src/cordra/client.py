"""
Cordra Python Client - Main Client Implementation

Provides CordraClient class that supports both REST and DOIP APIs.
"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

from .auth import AuthenticationManager
from .exceptions import CordraError, handle_http_error
from .models import (
    AclInfo,
    BatchUploadResponse,
    DigitalObject,
    MethodCallRequest,
    SearchRequest,
    SearchResponse,
    TokenResponse,
    VersionInfo,
)


class CordraClient:
    """
    Main Cordra client that supports both REST and DOIP APIs.

    This class provides a unified interface for interacting with Cordra
    digital object repositories using either the REST API or DOIP API.

    Args:
        base_url: Base URL of the Cordra server
        api_type: API type to use ('rest' or 'doip', default: 'rest')
        verify_ssl: Whether to verify SSL certificates (default: True)
        timeout: Request timeout in seconds (default: 30)

    Example:
        >>> client = CordraClient("https://cordra.example.com")
        >>> client.authenticate(username="user", password="pass")
        >>> obj = client.create_object(type="Document", content={"title": "Test"})
        >>> results = client.search("type:Document")
    """

    def __init__(
        self,
        base_url: str,
        api_type: str = "rest",
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_type = api_type.lower()
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Initialize authentication manager
        self.auth = AuthenticationManager(self)

        # Initialize appropriate client implementation
        if self.api_type == "rest":
            self._impl = CordraRestClient(self)
        elif self.api_type == "doip":
            self._impl = CordraDoipClient(self)
        else:
            raise ValueError(f"Invalid api_type: {api_type}. Must be 'rest' or 'doip'")

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Make HTTP request with proper error handling."""
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))

        # Add authentication headers if available
        if self.auth.token:
            auth_headers = {"Authorization": f"Bearer {self.auth.token}"}
            if headers:
                headers.update(auth_headers)
            else:
                headers = auth_headers

        # Default headers
        if not headers:
            headers = {}
        headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                data=data,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
                **kwargs,
            )

            # Handle HTTP errors
            if not response.ok:
                try:
                    response_data = response.json()
                except json.JSONDecodeError:
                    response_data = None
                handle_http_error(response, response_data)

            # Return JSON response
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"content": response.text}

        except requests.exceptions.RequestException as e:
            raise CordraError(f"Request failed: {str(e)}")

    # Authentication methods
    def authenticate(self, **kwargs) -> TokenResponse:
        """
        Authenticate with the Cordra server.

        Args:
            **kwargs: Authentication parameters
                - username, password: For password authentication
                - jwt_token: For JWT bearer authentication
                - user_id, private_key: For private key authentication

        Returns:
            TokenResponse with authentication information

        Example:
            >>> client.authenticate(username="user", password="pass")
            >>> client.authenticate(jwt_token="eyJ0eXAi...")
        """
        return self.auth.authenticate(**kwargs)

    def is_authenticated(self) -> bool:
        """Check if client is currently authenticated."""
        return self.auth.is_authenticated

    def logout(self):
        """Logout and clear authentication."""
        if self.auth.token:
            self.auth.revoke_token()
        self.auth.clear_authentication()

    # Object management methods
    def get_object(self, object_id: str, **kwargs) -> DigitalObject:
        """
        Retrieve a digital object by ID.

        Args:
            object_id: Object identifier
            **kwargs: Additional parameters (jsonPointer, filter, etc.)

        Returns:
            DigitalObject instance

        Example:
            >>> obj = client.get_object("test/123")
        """
        return self._impl.get_object(object_id, **kwargs)

    def create_object(
        self, type: str, content: Dict[str, Any], **kwargs
    ) -> DigitalObject:
        """
        Create a new digital object.

        Args:
            type: Object type (e.g., "Document")
            content: Object content
            **kwargs: Additional parameters (suffix, handle, etc.)

        Returns:
            DigitalObject instance

        Example:
            >>> obj = client.create_object("Document", {"title": "My Document"})
        """
        return self._impl.create_object(type, content, **kwargs)

    def update_object(
        self, object_id: str, content: Dict[str, Any], **kwargs
    ) -> DigitalObject:
        """
        Update an existing digital object.

        Args:
            object_id: Object identifier
            content: Updated object content
            **kwargs: Additional parameters (type, dryRun, etc.)

        Returns:
            DigitalObject instance

        Example:
            >>> obj = client.update_object("test/123", {"title": "Updated Title"})
        """
        return self._impl.update_object(object_id, content, **kwargs)

    def delete_object(self, object_id: str, **kwargs) -> bool:
        """
        Delete a digital object.

        Args:
            object_id: Object identifier
            **kwargs: Additional parameters (jsonPointer)

        Returns:
            True if successfully deleted

        Example:
            >>> client.delete_object("test/123")
        """
        return self._impl.delete_object(object_id, **kwargs)

    # Search methods
    def search(self, query: str = None, **kwargs) -> SearchResponse:
        """
        Search for digital objects.

        Args:
            query: Search query string
            **kwargs: Additional search parameters (pageNum, pageSize, etc.)

        Returns:
            SearchResponse instance

        Example:
            >>> results = client.search("type:Document")
            >>> results = client.search(queryJson={"query": "title:test"})
        """
        return self._impl.search(query, **kwargs)

    # ACL methods
    def get_acl(self, object_id: str) -> AclInfo:
        """
        Get access control list for an object.

        Args:
            object_id: Object identifier

        Returns:
            AclInfo instance

        Example:
            >>> acl = client.get_acl("test/123")
        """
        return self._impl.get_acl(object_id)

    def update_acl(
        self, object_id: str, readers: List[str] = None, writers: List[str] = None
    ) -> AclInfo:
        """
        Update access control list for an object.

        Args:
            object_id: Object identifier
            readers: List of reader user/group IDs
            writers: List of writer user/group IDs

        Returns:
            AclInfo instance

        Example:
            >>> acl = client.update_acl(
            ...     "test/123", readers=["user1"], writers=["user1", "user2"]
            ... )
        """
        return self._impl.update_acl(object_id, readers, writers)

    # Type method calls
    def call_method(
        self,
        method: str,
        object_id: str = None,
        type: str = None,
        params: Dict[str, Any] = None,
        attributes: Dict[str, Any] = None,
        **kwargs,
    ) -> Any:
        """
        Call a type method on an object or type.

        Args:
            method: Method name to call
            object_id: Object ID for instance methods
            type: Object type for static methods
            params: Method parameters
            attributes: Request attributes
            **kwargs: Additional parameters

        Returns:
            Method response (varies by method)

        Example:
            >>> result = client.call_method("extractName", object_id="test/123")
            >>> result = client.call_method("countObjects", type="Document")
        """
        return self._impl.call_method(
            method, object_id, type, params, attributes, **kwargs
        )

    # Password management
    def change_password(self, new_password: str) -> bool:
        """
        Change the current user's password.

        Args:
            new_password: New password

        Returns:
            True if successfully changed

        Example:
            >>> client.change_password("new_password123")
        """
        return self._impl.change_password(new_password)

    # Batch operations
    def batch_upload(
        self, objects: List[DigitalObject], **kwargs
    ) -> BatchUploadResponse:
        """
        Upload multiple objects in a batch.

        Args:
            objects: List of DigitalObject instances to upload
            **kwargs: Additional parameters (format, failFast, etc.)

        Returns:
            BatchUploadResponse instance

        Example:
            >>> objects = [DigitalObject(type="Document", content={"title": "Doc 1"})]
            >>> result = client.batch_upload(objects)
        """
        return self._impl.batch_upload(objects, **kwargs)

    # Version management
    def publish_version(
        self, object_id: str, version_id: str = None, **kwargs
    ) -> VersionInfo:
        """
        Publish a new version of an object.

        Args:
            object_id: Object identifier
            version_id: New version ID (optional)
            **kwargs: Additional parameters (clonePayloads)

        Returns:
            VersionInfo instance

        Example:
            >>> version = client.publish_version("test/123", version_id="v2")
        """
        return self._impl.publish_version(object_id, version_id, **kwargs)

    def get_versions(self, object_id: str) -> List[VersionInfo]:
        """
        Get all versions of an object.

        Args:
            object_id: Object identifier

        Returns:
            List of VersionInfo instances

        Example:
            >>> versions = client.get_versions("test/123")
        """
        return self._impl.get_versions(object_id)

    # Relationship queries
    def get_relationships(self, object_id: str, **kwargs) -> Dict[str, Any]:
        """
        Get objects related to the specified object.

        Args:
            object_id: Object identifier
            **kwargs: Additional parameters (outboundOnly)

        Returns:
            Dictionary with nodes, edges, and related objects

        Example:
            >>> relationships = client.get_relationships("test/123")
        """
        return self._impl.get_relationships(object_id, **kwargs)

    # Utility methods
    def hello(self) -> Dict[str, Any]:
        """
        Get service information (hello operation).

        Returns:
            Service information dictionary

        Example:
            >>> info = client.hello()
        """
        return self._impl.hello()

    def list_operations(self, target_id: str = "service") -> List[str]:
        """
        List available operations for a target.

        Args:
            target_id: Target identifier (default: "service")

        Returns:
            List of available operation identifiers

        Example:
            >>> ops = client.list_operations()
        """
        return self._impl.list_operations(target_id)


class CordraRestClient:
    """REST API implementation for Cordra."""

    def __init__(self, client: CordraClient):
        self.client = client

    def get_object(self, object_id: str, **kwargs) -> DigitalObject:
        """Get object via REST API."""
        params = {}
        if "jsonPointer" in kwargs:
            params["jsonPointer"] = kwargs["jsonPointer"]
        if "filter" in kwargs:
            params["filter"] = kwargs["filter"]
        if "payload" in kwargs:
            params["payload"] = kwargs["payload"]
        if "pretty" in kwargs:
            params["pretty"] = kwargs["pretty"]
        if "text" in kwargs:
            params["text"] = kwargs["text"]
        if "disposition" in kwargs:
            params["disposition"] = kwargs["disposition"]
        if "full" in kwargs:
            params["full"] = kwargs["full"]

        response = self.client._make_request(
            method="GET", endpoint=f"/objects/{object_id}", params=params
        )

        return DigitalObject.from_dict(response)

    def create_object(
        self, type: str, content: Dict[str, Any], **kwargs
    ) -> DigitalObject:
        """Create object via REST API."""
        params = {"type": type}
        if "dryRun" in kwargs:
            params["dryRun"] = kwargs["dryRun"]
        if "suffix" in kwargs:
            params["suffix"] = kwargs["suffix"]
        if "handle" in kwargs:
            params["handle"] = kwargs["handle"]
        if "full" in kwargs:
            params["full"] = kwargs["full"]

        obj = DigitalObject(type=type, content=content)
        response = self.client._make_request(
            method="POST", endpoint="/objects", params=params, json_data=obj.to_dict()
        )

        return DigitalObject.from_dict(response)

    def update_object(
        self, object_id: str, content: Dict[str, Any], **kwargs
    ) -> DigitalObject:
        """Update object via REST API."""
        params = {}
        if "dryRun" in kwargs:
            params["dryRun"] = kwargs["dryRun"]
        if "type" in kwargs:
            params["type"] = kwargs["type"]
        if "payloadToDelete" in kwargs:
            params["payloadToDelete"] = kwargs["payloadToDelete"]
        if "jsonPointer" in kwargs:
            params["jsonPointer"] = kwargs["jsonPointer"]
        if "full" in kwargs:
            params["full"] = kwargs["full"]

        obj = DigitalObject(
            id=object_id, type="", content=content
        )  # Type not needed for update
        response = self.client._make_request(
            method="PUT",
            endpoint=f"/objects/{object_id}",
            params=params,
            json_data=obj.to_dict(),
        )

        return DigitalObject.from_dict(response)

    def delete_object(self, object_id: str, **kwargs) -> bool:
        """Delete object via REST API."""
        params = {}
        if "jsonPointer" in kwargs:
            params["jsonPointer"] = kwargs["jsonPointer"]

        self.client._make_request(
            method="DELETE", endpoint=f"/objects/{object_id}", params=params
        )
        return True

    def search(self, query: str = None, **kwargs) -> SearchResponse:
        """Search via REST API."""
        if query:
            # Use GET method for simple queries
            params = {"query": query}
            if "ids" in kwargs:
                params["ids"] = kwargs["ids"]
            if "pageNum" in kwargs:
                params["pageNum"] = kwargs["pageNum"]
            if "pageSize" in kwargs:
                params["pageSize"] = kwargs["pageSize"]
            if "sortFields" in kwargs:
                params["sortFields"] = kwargs["sortFields"]
            if "full" in kwargs:
                params["full"] = kwargs["full"]
            if "filter" in kwargs:
                params["filter"] = kwargs["filter"]
            if "filterQueries" in kwargs:
                params["filterQueries"] = kwargs["filterQueries"]
            if "facets" in kwargs:
                params["facets"] = kwargs["facets"]

            response = self.client._make_request(
                method="GET", endpoint="/search", params=params
            )
        else:
            # Use POST method for complex queries
            search_request = SearchRequest(
                query=kwargs.get("query", ""),
                query_json=kwargs.get("queryJson"),
                ids=kwargs.get("ids", False),
                page_num=kwargs.get("pageNum", 0),
                page_size=kwargs.get("pageSize"),
                sort_fields=kwargs.get("sortFields"),
                filter_queries=kwargs.get("filterQueries"),
                facets=kwargs.get("facets"),
            )

            response = self.client._make_request(
                method="POST", endpoint="/search", json_data=search_request.to_dict()
            )

        return SearchResponse.from_dict(response)

    def get_acl(self, object_id: str) -> AclInfo:
        """Get ACL via REST API."""
        response = self.client._make_request(
            method="GET", endpoint=f"/acls/{object_id}"
        )
        return AclInfo.from_dict(response)

    def update_acl(
        self, object_id: str, readers: List[str] = None, writers: List[str] = None
    ) -> AclInfo:
        """Update ACL via REST API."""
        acl_data = {}
        if readers is not None:
            acl_data["readers"] = readers
        if writers is not None:
            acl_data["writers"] = writers

        response = self.client._make_request(
            method="PUT", endpoint=f"/acls/{object_id}", json_data=acl_data
        )
        return AclInfo.from_dict(response)

    def call_method(
        self,
        method: str,
        object_id: str = None,
        type: str = None,
        params: Dict[str, Any] = None,
        attributes: Dict[str, Any] = None,
        **kwargs,
    ) -> Any:
        """Call method via REST API."""
        request_params = {"method": method}

        if object_id:
            request_params["objectId"] = object_id
        elif type:
            request_params["type"] = type
        else:
            raise ValueError("Either object_id or type must be specified")

        if attributes:
            request_params["attributes"] = json.dumps(attributes)

        # Use POST for method calls with parameters
        if params:
            request_data = MethodCallRequest(params=params, attributes=attributes or {})
            response = self.client._make_request(
                method="POST",
                endpoint="/call",
                params=request_params,
                json_data=request_data.to_dict(),
            )
        else:
            # Use GET for simple method calls
            if attributes:
                request_params["attributes"] = json.dumps(attributes)

            response = self.client._make_request(
                method="GET", endpoint="/call", params=request_params
            )

        return response

    def change_password(self, new_password: str) -> bool:
        """Change password via REST API."""
        self.client._make_request(
            method="PUT", endpoint="/users/this/password", data=new_password
        )
        return True

    def batch_upload(
        self, objects: List[DigitalObject], **kwargs
    ) -> BatchUploadResponse:
        """Batch upload via REST API (not directly supported, use individual
        creates)."""
        raise NotImplementedError("Batch upload not available in REST API")

    def publish_version(
        self, object_id: str, version_id: str = None, **kwargs
    ) -> VersionInfo:
        """Publish version via REST API (not directly supported)."""
        raise NotImplementedError("Version publishing not available in REST API")

    def get_versions(self, object_id: str) -> List[VersionInfo]:
        """Get versions via REST API (not directly supported)."""
        raise NotImplementedError("Version management not available in REST API")

    def get_relationships(self, object_id: str, **kwargs) -> Dict[str, Any]:
        """Get relationships via REST API (not directly supported)."""
        raise NotImplementedError("Relationships not available in REST API")

    def hello(self) -> Dict[str, Any]:
        """Hello via REST API (not available)."""
        raise NotImplementedError("Hello operation not available in REST API")

    def list_operations(self, target_id: str = "service") -> List[str]:
        """List operations via REST API (not available)."""
        raise NotImplementedError("List operations not available in REST API")


class CordraDoipClient:
    """DOIP API implementation for Cordra."""

    def __init__(self, client: CordraClient):
        self.client = client

    def get_object(self, object_id: str, **kwargs) -> DigitalObject:
        """Get object via DOIP API."""
        params = {"targetId": object_id}
        if "element" in kwargs:
            params["attributes.element"] = kwargs["element"]

        response = self.client._make_request(
            method="POST", endpoint="/0.DOIP/Op.Retrieve", params=params
        )

        return DigitalObject.from_dict(response)

    def create_object(
        self, type: str, content: Dict[str, Any], **kwargs
    ) -> DigitalObject:
        """Create object via DOIP API."""
        obj = DigitalObject(type=type, content=content)
        params = {"targetId": "service"}

        response = self.client._make_request(
            method="POST",
            endpoint="/0.DOIP/Op.Create",
            params=params,
            json_data=obj.to_dict(),
        )

        return DigitalObject.from_dict(response)

    def update_object(
        self, object_id: str, content: Dict[str, Any], **kwargs
    ) -> DigitalObject:
        """Update object via DOIP API."""
        obj = DigitalObject(id=object_id, type="", content=content)
        params = {"targetId": object_id}

        response = self.client._make_request(
            method="POST",
            endpoint="/0.DOIP/Op.Update",
            params=params,
            json_data=obj.to_dict(),
        )

        return DigitalObject.from_dict(response)

    def delete_object(self, object_id: str, **kwargs) -> bool:
        """Delete object via DOIP API."""
        params = {"targetId": object_id}

        self.client._make_request(
            method="POST", endpoint="/0.DOIP/Op.Delete", params=params
        )
        return True

    def search(self, query: str = None, **kwargs) -> SearchResponse:
        """Search via DOIP API."""
        params = {"targetId": "service", "query": query or kwargs.get("query", "")}

        if "pageNum" in kwargs:
            params["pageNum"] = kwargs["pageNum"]
        if "pageSize" in kwargs:
            params["pageSize"] = kwargs["pageSize"]
        if "sortFields" in kwargs:
            params["sortFields"] = kwargs["sortFields"]
        if "type" in kwargs:
            params["type"] = kwargs["type"]
        if "facets" in kwargs:
            params["facets"] = json.dumps(kwargs["facets"])
        if "filterQueries" in kwargs:
            params["filterQueries"] = json.dumps(kwargs["filterQueries"])

        response = self.client._make_request(
            method="POST", endpoint="/0.DOIP/Op.Search", params=params
        )

        # Convert DOIP search response to SearchResponse format
        results = []
        for item in response.get("results", []):
            if isinstance(item, dict):
                results.append(DigitalObject.from_dict(item))

        return SearchResponse(
            size=response.get("size", 0),
            page_num=response.get("pageNum", 0),
            page_size=response.get("pageSize", 0),
            results=results,
            facets=response.get("facets", []),
        )

    def get_acl(self, object_id: str) -> AclInfo:
        """Get ACL via DOIP API (not directly supported)."""
        raise NotImplementedError("ACL operations not available in DOIP API")

    def update_acl(
        self, object_id: str, readers: List[str] = None, writers: List[str] = None
    ) -> AclInfo:
        """Update ACL via DOIP API (not directly supported)."""
        raise NotImplementedError("ACL operations not available in DOIP API")

    def call_method(
        self,
        method: str,
        object_id: str = None,
        type: str = None,
        params: Dict[str, Any] = None,
        attributes: Dict[str, Any] = None,
        **kwargs,
    ) -> Any:
        """Call method via DOIP API (not directly supported)."""
        raise NotImplementedError("Type method calls not available in DOIP API")

    def change_password(self, new_password: str) -> bool:
        """Change password via DOIP API."""
        params = {"targetId": "service"}

        self.client._make_request(
            method="POST",
            endpoint="/20.DOIP/Op.ChangePassword",
            params=params,
            json_data={"password": new_password},
        )
        return True

    def batch_upload(
        self, objects: List[DigitalObject], **kwargs
    ) -> BatchUploadResponse:
        """Batch upload via DOIP API."""
        params = {"targetId": "service"}

        if "format" in kwargs:
            params["format"] = kwargs["format"]
        if "failFast" in kwargs:
            params["failFast"] = kwargs["failFast"]
        if "parallel" in kwargs:
            params["parallel"] = kwargs["parallel"]

        # Convert objects to DOIP format
        objects_data = [obj.to_dict() for obj in objects]

        response = self.client._make_request(
            method="POST",
            endpoint="/20.DOIP/Op.BatchUpload",
            params=params,
            json_data=objects_data,
        )

        return BatchUploadResponse.from_dict(response)

    def publish_version(
        self, object_id: str, version_id: str = None, **kwargs
    ) -> VersionInfo:
        """Publish version via DOIP API."""
        params = {"targetId": object_id}

        if version_id:
            params["versionId"] = version_id
        if "clonePayloads" in kwargs:
            params["clonePayloads"] = kwargs["clonePayloads"]

        response = self.client._make_request(
            method="POST", endpoint="/20.DOIP/Op.Versions.Publish", params=params
        )

        return VersionInfo.from_dict(response)

    def get_versions(self, object_id: str) -> List[VersionInfo]:
        """Get versions via DOIP API."""
        params = {"targetId": object_id}

        response = self.client._make_request(
            method="POST", endpoint="/20.DOIP/Op.Versions.Get", params=params
        )

        versions = []
        for item in response:
            versions.append(VersionInfo.from_dict(item))

        return versions

    def get_relationships(self, object_id: str, **kwargs) -> Dict[str, Any]:
        """Get relationships via DOIP API."""
        params = {"targetId": object_id}

        if "outboundOnly" in kwargs:
            params["outboundOnly"] = kwargs["outboundOnly"]

        response = self.client._make_request(
            method="POST", endpoint="/20.DOIP/Op.Relationships.Get", params=params
        )

        return response

    def hello(self) -> Dict[str, Any]:
        """Hello via DOIP API."""
        params = {"targetId": "service"}

        response = self.client._make_request(
            method="POST", endpoint="/0.DOIP/Op.Hello", params=params
        )

        return response

    def list_operations(self, target_id: str = "service") -> List[str]:
        """List operations via DOIP API."""
        params = {"targetId": target_id}

        response = self.client._make_request(
            method="POST", endpoint="/0.DOIP/Op.ListOperations", params=params
        )

        return response
