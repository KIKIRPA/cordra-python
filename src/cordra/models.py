"""
Cordra Python Client - Data Models

Data classes for Cordra objects, requests, and responses.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DigitalObject:
    """Represents a Cordra digital object."""

    id: Optional[str] = None
    type: str = ""
    content: Dict[str, Any] = field(default_factory=dict)
    acl: Optional[Dict[str, List[str]]] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if not self.type:
            raise ValueError("Object type is required")

    @classmethod
    def from_dict(cls, data: dict) -> "DigitalObject":
        """Create DigitalObject from API response."""
        return cls(
            id=data.get("id"),
            type=data.get("type", ""),
            content=data.get("content", {}),
            acl=data.get("acl"),
            metadata=data.get("metadata"),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        result = {"type": self.type, "content": self.content}
        if self.id:
            result["id"] = self.id
        if self.acl is not None:
            result["acl"] = self.acl
        if self.metadata is not None:
            result["metadata"] = self.metadata
        return result


@dataclass
class SearchRequest:
    """Search request parameters."""

    query: str = ""
    query_json: Optional[Dict[str, Any]] = None
    ids: bool = False
    page_num: int = 0
    page_size: Optional[int] = None
    sort_fields: Optional[List[Dict[str, Any]]] = None
    filter_queries: Optional[List[str]] = None
    facets: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        result: Dict[str, Any] = {}
        if self.query:
            result["query"] = self.query
        if self.query_json:
            result["queryJson"] = self.query_json
        if self.ids:
            result["ids"] = self.ids
        if self.page_num != 0:
            result["pageNum"] = self.page_num
        if self.page_size is not None:
            result["pageSize"] = self.page_size
        if self.sort_fields:
            result["sortFields"] = self.sort_fields
        if self.filter_queries:
            result["filterQueries"] = self.filter_queries
        if self.facets:
            result["facets"] = self.facets
        return result


@dataclass
class SearchResponse:
    """Search response data."""

    size: int = 0
    page_num: int = 0
    page_size: int = 0
    results: List[DigitalObject] = field(default_factory=list)
    facets: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "SearchResponse":
        """Create SearchResponse from API response."""
        results = []
        for item in data.get("results", []):
            if isinstance(item, dict):
                results.append(DigitalObject.from_dict(item))

        return cls(
            size=data.get("size", 0),
            page_num=data.get("pageNum", 0),
            page_size=data.get("pageSize", 0),
            results=results,
            facets=data.get("facets", []),
        )


@dataclass
class TokenRequest:
    """Authentication token request."""

    grant_type: str = "password"
    username: Optional[str] = None
    password: Optional[str] = None
    assertion: Optional[str] = None  # JWT token
    user_id: Optional[str] = None  # For private key auth
    private_key: Optional[Dict[str, Any]] = None  # RSA JWK

    def __post_init__(self) -> None:
        if self.grant_type == "password" and not (self.username and self.password):
            raise ValueError("Username and password required for password grant")
        elif (
            self.grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer"
            and not self.assertion
        ):
            raise ValueError("JWT assertion required for JWT bearer grant")

    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        result: Dict[str, Any] = {"grant_type": self.grant_type}
        if self.username:
            result["username"] = self.username
        if self.password:
            result["password"] = self.password
        if self.assertion:
            result["assertion"] = self.assertion
        if self.user_id:
            result["userId"] = self.user_id
        if self.private_key:
            result["privateKey"] = self.private_key
        return result


@dataclass
class TokenResponse:
    """Authentication token response."""

    access_token: str = ""
    token_type: str = "Bearer"
    active: bool = False
    username: Optional[str] = None
    user_id: Optional[str] = None
    types_permitted_to_create: List[str] = field(default_factory=list)
    group_ids: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "TokenResponse":
        """Create TokenResponse from API response."""
        return cls(
            access_token=data.get("access_token", ""),
            token_type=data.get("token_type", "Bearer"),
            active=data.get("active", False),
            username=data.get("username"),
            user_id=data.get("userId"),
            types_permitted_to_create=data.get("typesPermittedToCreate", []),
            group_ids=data.get("groupIds", []),
        )


@dataclass
class AclInfo:
    """Access Control List information."""

    readers: List[str] = field(default_factory=list)
    writers: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "AclInfo":
        """Create AclInfo from API response."""
        return cls(readers=data.get("readers", []), writers=data.get("writers", []))

    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {"readers": self.readers, "writers": self.writers}


@dataclass
class MethodCallRequest:
    """Request for calling type methods."""

    params: Dict[str, Any] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        return {"params": self.params, "attributes": self.attributes}


@dataclass
class BatchUploadResult:
    """Result of a single batch upload operation."""

    position: int = 0
    response_code: int = 0
    response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BatchUploadResponse:
    """Response from batch upload operation."""

    results: List[BatchUploadResult] = field(default_factory=list)
    success: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "BatchUploadResponse":
        """Create BatchUploadResponse from API response."""
        results = []
        for item in data.get("results", []):
            if isinstance(item, dict):
                results.append(
                    BatchUploadResult(
                        position=item.get("position", 0),
                        response_code=item.get("responseCode", 0),
                        response=item.get("response", {}),
                    )
                )

        return cls(results=results, success=data.get("success", False))


@dataclass
class VersionInfo:
    """Information about a published version."""

    id: str = ""
    type: str = ""
    version_of: str = ""
    published_by: str = ""
    published_on: int = 0
    is_tip: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "VersionInfo":
        """Create VersionInfo from API response."""
        return cls(
            id=data.get("id", ""),
            type=data.get("type", ""),
            version_of=data.get("versionOf", ""),
            published_by=data.get("publishedBy", ""),
            published_on=data.get("publishedOn", 0),
            is_tip=data.get("isTip", False),
        )


@dataclass
class AuthenticationResponse:
    """Standardized response for all authentication-related operations."""

    active: bool = False
    username: Optional[str] = None
    user_id: Optional[str] = None
    types_permitted_to_create: List[str] = field(default_factory=list)
    group_ids: List[str] = field(default_factory=list)
    access_token: Optional[str] = None
    token_type: str = "Bearer"

    @classmethod
    def from_dict(cls, data: dict) -> "AuthenticationResponse":
        """Create AuthenticationResponse from API response."""
        return cls(
            active=data.get("active", False),
            username=data.get("username"),
            user_id=data.get("userId"),
            types_permitted_to_create=data.get("typesPermittedToCreate", []),
            group_ids=data.get("groupIds", []),
            access_token=data.get("access_token"),
            token_type=data.get("token_type", "Bearer"),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for API requests."""
        result = {
            "active": self.active,
            "username": self.username,
            "userId": self.user_id,
            "typesPermittedToCreate": self.types_permitted_to_create,
            "groupIds": self.group_ids,
        }
        if self.access_token:
            result["access_token"] = self.access_token
            result["token_type"] = self.token_type
        return result
