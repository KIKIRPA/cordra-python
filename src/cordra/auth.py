"""
Cordra Python Client - Authentication Management

Handles authentication for both REST and DOIP APIs with various authentication methods.
"""

import base64
import json
from typing import Any, Optional, Union

from .exceptions import AuthenticationError, ConfigurationError
from .models import AuthenticationResponse, TokenRequest


class BaseAuthenticationManager:
    """
    Base class for authentication managers.

    Handles common authentication state and provides interface for API-specific
    implementations.
    """

    def __init__(self, client: Any) -> None:
        """
        Initialize authentication manager.

        Args:
            client: Cordra client instance for making API calls
        """
        self.client = client
        self._token: Optional[str] = None
        self._username: Optional[str] = None
        self._password: Optional[str] = None

    @property
    def token(self) -> Optional[str]:
        """Current access token."""
        return self._token

    @property
    def username(self) -> Optional[str]:
        """Current username for basic authentication."""
        return self._username

    @property
    def password(self) -> Optional[str]:
        """Current password for basic authentication."""
        return self._password

    @property
    def is_authenticated(self) -> bool:
        """Check if currently authenticated."""
        return self._token is not None or (
            self._username is not None and self._password is not None
        )

    def _get_basic_auth_header(self) -> str:
        """Get basic authentication header."""
        if not self._username or not self._password:
            raise AuthenticationError("Basic authentication credentials not set")
        credentials = f"{self._username}:{self._password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def _get_bearer_auth_header(self) -> str:
        """Get bearer token authentication header."""
        if not self._token:
            raise AuthenticationError("No access token available")
        return f"Bearer {self._token}"

    def clear_authentication(self) -> None:
        """Clear all authentication information."""
        self._token = None
        self._username = None
        self._password = None


class RestAuthenticationManager(BaseAuthenticationManager):
    """
    Authentication manager for REST API.

    Supports:
    - HTTP Basic authentication
    - OAuth-style password authentication (bearer tokens)
    - JWT bearer token authentication
    - Private key authentication (creates JWT from private key)
    """

    def authenticate_basic(
        self, username: str, password: str
    ) -> AuthenticationResponse:
        """
        Authenticate using HTTP Basic authentication.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        # For REST API, basic auth is validated on each request
        # We store credentials and let the server validate them
        self._username = username
        self._password = password
        self._token = None  # Clear any existing token

        # Test the credentials and get user information
        try:
            response = self.client._make_request(
                method="GET", endpoint="/check-credentials"
            )
            auth_response = AuthenticationResponse.from_dict(response)
            auth_response.active = True  # If we got here, authentication was successful
            return auth_response
        except Exception:
            # Clear credentials if authentication failed
            self._username = None
            self._password = None
            raise AuthenticationError("Basic authentication failed")

    def authenticate_password(
        self, username: str, password: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Authenticate using username and password to get bearer token.

        Args:
            username: Username for authentication
            password: Password for authentication
            full: Include additional user information

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        token_request = TokenRequest(
            grant_type="password", username=username, password=password
        )

        params = {}
        if full:
            params["full"] = "true"

        response = self.client._make_request(
            method="POST",
            endpoint="/auth/token",
            params=params,
            json_data=token_request.to_dict(),
        )

        auth_response = AuthenticationResponse.from_dict(response)

        # Store token and clear basic auth credentials
        self._token = auth_response.access_token
        self._username = None
        self._password = None

        return auth_response

    def authenticate_jwt(
        self, jwt_token: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Authenticate using JWT bearer token.

        Args:
            jwt_token: JWT token string
            full: Include additional user information

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        token_request = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=jwt_token,
        )

        params = {}
        if full:
            params["full"] = "true"

        response = self.client._make_request(
            method="POST",
            endpoint="/auth/token",
            params=params,
            json_data=token_request.to_dict(),
        )

        auth_response = AuthenticationResponse.from_dict(response)

        # Store token and clear basic auth credentials
        self._token = auth_response.access_token
        self._username = None
        self._password = None

        return auth_response

    def introspect_token(
        self, token: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Introspect a token using REST API.

        Args:
            token: Token to introspect
            full: Include additional user information

        Returns:
            AuthenticationResponse with token information

        Raises:
            AuthenticationError: If introspection fails
        """
        params = {}
        if full:
            params["full"] = "true"

        response = self.client._make_request(
            method="POST",
            endpoint="/auth/introspect",
            params=params,
            json_data={"token": token},
        )

        return AuthenticationResponse.from_dict(response)

    def revoke_token(self, token: str) -> AuthenticationResponse:
        """
        Revoke a token using REST API.

        Args:
            token: Token to revoke

        Returns:
            AuthenticationResponse indicating revocation status

        Raises:
            AuthenticationError: If revocation fails
        """
        response = self.client._make_request(
            method="POST", endpoint="/auth/revoke", json_data={"token": token}
        )

        # Return a standardized response indicating revocation
        return AuthenticationResponse(active=response.get("active", False) is False)


class DoipAuthenticationManager(BaseAuthenticationManager):
    """
    Authentication manager for DOIP API.

    Supports:
    - HTTP Basic authentication (using DOIP Hello operation)
    - OAuth-style password authentication (bearer tokens)
    - JWT bearer token authentication
    - Private key authentication (creates JWT from private key)
    """

    def authenticate_basic(
        self, username: str, password: str
    ) -> AuthenticationResponse:
        """
        Authenticate using HTTP Basic authentication via DOIP.

        For DOIP API, basic authentication is handled via HTTP Authorization header
        and validated on authenticated requests.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        # For DOIP API, basic auth is handled via HTTP Authorization header
        # Set credentials - they'll be used for all subsequent requests
        self._username = username
        self._password = password
        self._token = None  # Clear any existing token

        # Test the credentials by making an authenticated request
        # The _make_request method will automatically add the Authorization header
        try:
            # Try to get service information - this should work if auth is valid
            params = {"operationId": "0.DOIP/Op.Hello", "targetId": "service"}

            _ = self.client._make_request(
                method="POST", endpoint="/doip", params=params
            )
            # If we get here without authentication error, basic auth is working
            auth_response = AuthenticationResponse(active=True, username=username)
            return auth_response
        except AuthenticationError:
            # Clear credentials if authentication failed
            self._username = None
            self._password = None
            raise
        except Exception:
            # Clear credentials if authentication failed
            self._username = None
            self._password = None
            raise

    def authenticate_password(
        self, username: str, password: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Authenticate using username and password to get bearer token for DOIP.

        Args:
            username: Username for authentication
            password: Password for authentication
            full: Include additional user information

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        # DOIP uses /doip endpoint with operationId parameter
        params = {"operationId": "20.DOIP/Op.Auth.Token", "targetId": "service"}

        # Add attributes for full information if requested
        if full:
            params["attributes"] = json.dumps({"full": True})

        token_request = {
            "grant_type": "password",
            "username": username,
            "password": password,
        }

        response = self.client._make_request(
            method="POST", endpoint="/doip", params=params, json_data=token_request
        )

        auth_response = AuthenticationResponse.from_dict(response)

        # Store token and clear basic auth credentials
        self._token = auth_response.access_token
        self._username = None
        self._password = None

        return auth_response

    def authenticate_jwt(
        self, jwt_token: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Authenticate using JWT bearer token for DOIP.

        Args:
            jwt_token: JWT token string
            full: Include additional user information

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        # DOIP uses /doip endpoint with operationId parameter
        params = {"operationId": "20.DOIP/Op.Auth.Token", "targetId": "service"}

        # Add attributes for full information if requested
        if full:
            params["attributes"] = json.dumps({"full": True})

        token_request = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_token,
        }

        response = self.client._make_request(
            method="POST", endpoint="/doip", params=params, json_data=token_request
        )

        auth_response = AuthenticationResponse.from_dict(response)

        # Store token and clear basic auth credentials
        self._token = auth_response.access_token
        self._username = None
        self._password = None

        return auth_response

    def introspect_token(
        self, token: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Introspect a token using DOIP API.

        Args:
            token: Token to introspect
            full: Include additional user information

        Returns:
            AuthenticationResponse with token information

        Raises:
            AuthenticationError: If introspection fails
        """
        # DOIP API uses /doip endpoint with query parameters
        params = {"operationId": "20.DOIP/Op.Auth.Introspect", "targetId": "service"}

        # Add attributes for full information if requested
        if full:
            params["attributes"] = json.dumps({"full": True})

        response = self.client._make_request(
            method="POST", endpoint="/doip", params=params, json_data={"token": token}
        )
        return AuthenticationResponse.from_dict(response)

    def revoke_token(self, token: str) -> AuthenticationResponse:
        """
        Revoke a token using DOIP API.

        Args:
            token: Token to revoke

        Returns:
            AuthenticationResponse indicating revocation status

        Raises:
            AuthenticationError: If revocation fails
        """
        # DOIP API uses /doip endpoint with query parameters
        params = {"operationId": "20.DOIP/Op.Auth.Revoke", "targetId": "service"}

        response = self.client._make_request(
            method="POST", endpoint="/doip", params=params, json_data={"token": token}
        )

        # Return a standardized response indicating revocation
        return AuthenticationResponse(active=response.get("active", False) is False)


class AuthenticationManager:
    """
    Unified authentication manager that routes to API-specific implementations.

    This class provides backward compatibility while delegating to the appropriate
    API-specific authentication manager based on the client's api_type.
    """

    def __init__(self, client: Any) -> None:
        """
        Initialize authentication manager.

        Args:
            client: Cordra client instance for making API calls
        """
        self.client = client
        self._rest_auth = RestAuthenticationManager(client)
        self._doip_auth = DoipAuthenticationManager(client)

    def _get_api_manager(
        self,
    ) -> Union[RestAuthenticationManager, DoipAuthenticationManager]:
        """Get the appropriate authentication manager based on client's api_type."""
        if self.client.api_type == "rest":
            return self._rest_auth
        elif self.client.api_type == "doip":
            return self._doip_auth
        else:
            raise ConfigurationError(f"Invalid api_type: {self.client.api_type}")

    @property
    def token(self) -> Optional[str]:
        """Current access token."""
        return self._get_api_manager().token

    @property
    def username(self) -> Optional[str]:
        """Current username for basic authentication."""
        return self._get_api_manager().username

    @property
    def password(self) -> Optional[str]:
        """Current password for basic authentication."""
        return self._get_api_manager().password

    @property
    def is_authenticated(self) -> bool:
        """Check if currently authenticated."""
        return self._get_api_manager().is_authenticated

    def authenticate_basic(
        self, username: str, password: str
    ) -> AuthenticationResponse:
        """
        Authenticate using HTTP Basic authentication.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        return self._get_api_manager().authenticate_basic(username, password)

    def authenticate_password(
        self, username: str, password: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Authenticate using username and password to get bearer token.

        Args:
            username: Username for authentication
            password: Password for authentication
            full: Include additional user information

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        return self._get_api_manager().authenticate_password(username, password, full)

    def authenticate_jwt(
        self, jwt_token: str, full: bool = False
    ) -> AuthenticationResponse:
        """
        Authenticate using JWT bearer token.

        Args:
            jwt_token: JWT token string
            full: Include additional user information

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
        """
        return self._get_api_manager().authenticate_jwt(jwt_token, full)

    def authenticate(self, **kwargs: Any) -> AuthenticationResponse:
        """
        Authenticate using various methods based on provided parameters.

        This method routes to the appropriate API-specific authentication method
        based on the client's api_type.

        Args:
            **kwargs: Authentication parameters
                - username, password: For password authentication (bearer token)
                - jwt_token: For JWT bearer authentication
                - full: Include additional user information (optional, default: False)

        Returns:
            AuthenticationResponse with authentication information

        Raises:
            AuthenticationError: If authentication fails
            ConfigurationError: If invalid parameters provided
        """
        api_manager = self._get_api_manager()
        full = kwargs.pop("full", False)

        if "username" in kwargs and "password" in kwargs:
            # Check if this is basic auth or password auth
            # If no other auth method is specified, assume password auth for token
            return api_manager.authenticate_password(
                kwargs["username"], kwargs["password"], full
            )
        elif "jwt_token" in kwargs:
            return api_manager.authenticate_jwt(kwargs["jwt_token"], full)
        else:
            raise ConfigurationError(
                "Invalid authentication parameters. Provide either "
                "(username, password) for password auth, or jwt_token for JWT auth"
            )

    def introspect_token(
        self, token: Optional[str] = None, full: bool = False
    ) -> AuthenticationResponse:
        """
        Introspect an authentication token.

        Args:
            token: Token to introspect (uses current token if not specified)
            full: Include additional user information

        Returns:
            AuthenticationResponse with token information

        Raises:
            AuthenticationError: If introspection fails or no token available
        """
        api_manager = self._get_api_manager()
        token_to_introspect = token or api_manager.token

        if not token_to_introspect:
            raise AuthenticationError("No token to introspect")

        return api_manager.introspect_token(token_to_introspect, full)

    def revoke_token(self, token: Optional[str] = None) -> AuthenticationResponse:
        """
        Revoke an authentication token.

        Args:
            token: Token to revoke (uses current token if not specified)

        Returns:
            AuthenticationResponse indicating revocation status

        Raises:
            AuthenticationError: If revocation fails or no token-based auth
        """
        api_manager = self._get_api_manager()
        if not api_manager.token:
            raise AuthenticationError("No token to revoke")

        token_to_revoke = token or api_manager.token

        response = api_manager.revoke_token(token_to_revoke)

        # Clear current token after successful revocation
        if not response.active:
            api_manager._token = None

        return response

    def clear_authentication(self) -> None:
        """Clear all authentication information."""
        self._rest_auth.clear_authentication()
        self._doip_auth.clear_authentication()

    # Backward compatibility methods
    def authenticate_with_password(
        self, username: str, password: str
    ) -> AuthenticationResponse:
        """Legacy method - use authenticate() instead."""
        return self.authenticate_password(username, password)

    def authenticate_with_jwt(self, jwt_token: str) -> AuthenticationResponse:
        """Legacy method - use authenticate() instead."""
        return self.authenticate_jwt(jwt_token)
