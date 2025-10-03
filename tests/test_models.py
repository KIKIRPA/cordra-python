"""
Tests for cordra.models module.
"""

import pytest
from cordra.models import DigitalObject, SearchRequest, TokenResponse, AclInfo


class TestDigitalObject:
    """Test DigitalObject model."""

    def test_create_minimal_object(self):
        """Test creating a minimal DigitalObject."""
        obj = DigitalObject(type="Document", content={"title": "Test"})
        assert obj.type == "Document"
        assert obj.content == {"title": "Test"}
        assert obj.id is None

    def test_create_complete_object(self):
        """Test creating a complete DigitalObject."""
        obj = DigitalObject(
            id="test/123",
            type="Document",
            content={"title": "Test"},
            acl={"readers": ["user1"], "writers": ["user1"]},
            metadata={"createdOn": 1234567890}
        )
        assert obj.id == "test/123"
        assert obj.type == "Document"
        assert obj.content == {"title": "Test"}
        assert obj.acl == {"readers": ["user1"], "writers": ["user1"]}
        assert obj.metadata == {"createdOn": 1234567890}

    def test_invalid_type_raises_error(self):
        """Test that empty type raises ValueError."""
        with pytest.raises(ValueError, match="Object type is required"):
            DigitalObject(type="", content={})

    def test_to_dict_includes_required_fields(self):
        """Test to_dict method includes required fields."""
        obj = DigitalObject(type="Document", content={"title": "Test"})
        data = obj.to_dict()
        assert data["type"] == "Document"
        assert data["content"] == {"title": "Test"}

    def test_to_dict_includes_optional_fields(self):
        """Test to_dict method includes optional fields when present."""
        obj = DigitalObject(
            id="test/123",
            type="Document",
            content={"title": "Test"},
            acl={"readers": ["user1"]}
        )
        data = obj.to_dict()
        assert data["id"] == "test/123"
        assert data["acl"] == {"readers": ["user1"]}

    def test_from_dict_creates_object(self):
        """Test from_dict class method creates proper object."""
        data = {
            "id": "test/123",
            "type": "Document",
            "content": {"title": "Test"},
            "acl": {"readers": ["user1"]},
            "metadata": {"createdOn": 1234567890}
        }
        obj = DigitalObject.from_dict(data)
        assert obj.id == "test/123"
        assert obj.type == "Document"
        assert obj.content == {"title": "Test"}
        assert obj.acl == {"readers": ["user1"]}
        assert obj.metadata == {"createdOn": 1234567890}


class TestSearchRequest:
    """Test SearchRequest model."""

    def test_create_minimal_request(self):
        """Test creating a minimal SearchRequest."""
        req = SearchRequest(query="test query")
        assert req.query == "test query"
        assert req.page_num == 0
        assert req.ids is False

    def test_create_complete_request(self):
        """Test creating a complete SearchRequest."""
        req = SearchRequest(
            query="test query",
            query_json={"query": "title:test"},
            ids=True,
            page_num=1,
            page_size=10,
            sort_fields=[{"name": "title", "reverse": False}],
            filter_queries=["type:Document"],
            facets=[{"field": "author"}]
        )
        assert req.query == "test query"
        assert req.query_json == {"query": "title:test"}
        assert req.ids is True
        assert req.page_num == 1
        assert req.page_size == 10
        assert req.sort_fields == [{"name": "title", "reverse": False}]
        assert req.filter_queries == ["type:Document"]
        assert req.facets == [{"field": "author"}]

    def test_to_dict_includes_non_default_values(self):
        """Test to_dict only includes non-default values."""
        req = SearchRequest(query="test", page_num=1, page_size=10)
        data = req.to_dict()
        assert data["query"] == "test"
        assert data["pageNum"] == 1
        assert data["pageSize"] == 10
        assert "ids" not in data  # Default False not included
        assert "queryJson" not in data  # None not included


class TestTokenResponse:
    """Test TokenResponse model."""

    def test_create_minimal_response(self):
        """Test creating a minimal TokenResponse."""
        resp = TokenResponse(access_token="test_token")
        assert resp.access_token == "test_token"
        assert resp.token_type == "Bearer"
        assert resp.active is False

    def test_create_complete_response(self):
        """Test creating a complete TokenResponse."""
        resp = TokenResponse(
            access_token="test_token",
            token_type="Bearer",
            active=True,
            username="testuser",
            user_id="test/123",
            types_permitted_to_create=["Document", "User"],
            group_ids=["group1", "group2"]
        )
        assert resp.access_token == "test_token"
        assert resp.token_type == "Bearer"
        assert resp.active is True
        assert resp.username == "testuser"
        assert resp.user_id == "test/123"
        assert resp.types_permitted_to_create == ["Document", "User"]
        assert resp.group_ids == ["group1", "group2"]

    def test_from_dict_creates_response(self):
        """Test from_dict creates proper response."""
        data = {
            "access_token": "test_token",
            "token_type": "Bearer",
            "active": True,
            "username": "testuser",
            "userId": "test/123",
            "typesPermittedToCreate": ["Document"],
            "groupIds": ["group1"]
        }
        resp = TokenResponse.from_dict(data)
        assert resp.access_token == "test_token"
        assert resp.token_type == "Bearer"
        assert resp.active is True
        assert resp.username == "testuser"
        assert resp.user_id == "test/123"
        assert resp.types_permitted_to_create == ["Document"]
        assert resp.group_ids == ["group1"]


class TestAclInfo:
    """Test AclInfo model."""

    def test_create_empty_acl(self):
        """Test creating empty AclInfo."""
        acl = AclInfo()
        assert acl.readers == []
        assert acl.writers == []

    def test_create_acl_with_users(self):
        """Test creating AclInfo with users."""
        acl = AclInfo(readers=["user1", "user2"], writers=["user1"])
        assert acl.readers == ["user1", "user2"]
        assert acl.writers == ["user1"]

    def test_from_dict_creates_acl(self):
        """Test from_dict creates proper ACL."""
        data = {"readers": ["user1"], "writers": ["user1", "user2"]}
        acl = AclInfo.from_dict(data)
        assert acl.readers == ["user1"]
        assert acl.writers == ["user1", "user2"]

    def test_to_dict_returns_acl_data(self):
        """Test to_dict returns proper ACL data."""
        acl = AclInfo(readers=["user1"], writers=["user1", "user2"])
        data = acl.to_dict()
        assert data == {"readers": ["user1"], "writers": ["user1", "user2"]}
