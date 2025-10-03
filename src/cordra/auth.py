"""
Cordra Python Client - Authentication Management

Handles authentication token management and various authentication methods.
"""

import time
from typing import Optional, Dict, Any
from .models import TokenRequest, TokenResponse
from .exceptions import AuthenticationError, ConfigurationError


class AuthenticationManager:
    """
    Manages authentication tokens and handles different authentication methods.

    Supports:
    - Password authentication
    - JWT bearer tokens
    - Private key authentication (RSA JWK format)
    """

    def __init__(self, client):
        """
        Initialize authentication manager.

        Args:
            client: Cordra client instance for making API calls
        """
        self.client = client
        self._token: Optional[str] = None
        self._token_expires_at: Optional[float] = None
        self._token_info: Optional[TokenResponse] = None

    @property
    def token(self) -> Optional[str]:
        """Current access token."""
        return self._token

    @property
    def token_info(self) -> Optional[TokenResponse]:
        """Current token information."""
        return self._token_info

    @property
    def is_authenticated(self) -> bool:
        """Check if currently authenticated."""
        return self._token is not None and not self._is_token_expired()

    def _is_token_expired(self) -> bool:
        """Check if the current token is expired."""
        if not self._token_expires_at:
            return False
        return time.time() >= self._token_expires_at

    def authenticate_with_password(self, username: str, password: str) -> TokenResponse:
        """
        Authenticate using username and password.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            TokenResponse with token information

        Raises:
            AuthenticationError: If authentication fails
        """
        token_request = TokenRequest(
            grant_type="password", username=username, password=password
        )

        response = self.client._make_request(
            method="POST", endpoint="/auth/token", json_data=token_request.to_dict()
        )

        token_response = TokenResponse.from_dict(response)
        self._set_token(token_response)

        return token_response

    def authenticate_with_jwt(self, jwt_token: str) -> TokenResponse:
        """
        Authenticate using JWT bearer token.

        Args:
            jwt_token: JWT token string

        Returns:
            TokenResponse with token information

        Raises:
            AuthenticationError: If authentication fails
        """
        token_request = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=jwt_token,
        )

        response = self.client._make_request(
            method="POST", endpoint="/auth/token", json_data=token_request.to_dict()
        )

        token_response = TokenResponse.from_dict(response)
        self._set_token(token_response)

        return token_response

    def authenticate_with_private_key(
        self, user_id: str, private_key: Dict[str, Any]
    ) -> TokenResponse:
        """
        Authenticate using RSA private key.

        Args:
            user_id: User identifier
            private_key: RSA private key in JWK format

        Returns:
            TokenResponse with token information

        Raises:
            AuthenticationError: If authentication fails
        """
        token_request = TokenRequest(
            grant_type="password",  # Private key auth uses password grant type
            user_id=user_id,
            private_key=private_key,
        )

        response = self.client._make_request(
            method="POST", endpoint="/auth/token", json_data=token_request.to_dict()
        )

        token_response = TokenResponse.from_dict(response)
        self._set_token(token_response)

        return token_response

    def authenticate(self, **kwargs) -> TokenResponse:
        """
        Authenticate using various methods based on provided parameters.

        Args:
            **kwargs: Authentication parameters
                - username, password: For password authentication
                - jwt_token: For JWT bearer authentication
                - user_id, private_key: For private key authentication

        Returns:
            TokenResponse with token information

        Raises:
            AuthenticationError: If authentication fails
            ConfigurationError: If invalid parameters provided
        """
        if "username" in kwargs and "password" in kwargs:
            return self.authenticate_with_password(
                kwargs["username"], kwargs["password"]
            )
        elif "jwt_token" in kwargs:
            return self.authenticate_with_jwt(kwargs["jwt_token"])
        elif "user_id" in kwargs and "private_key" in kwargs:
            return self.authenticate_with_private_key(
                kwargs["user_id"], kwargs["private_key"]
            )
        else:
            raise ConfigurationError(
                "Invalid authentication parameters. Provide either "
                "(username, password) or jwt_token or (user_id, private_key)"
            )

    def _set_token(self, token_response: TokenResponse):
        """Set authentication token and related information."""
        self._token = token_response.access_token
        self._token_info = token_response

        # Tokens are valid for 30 minutes from last use, but we set a conservative expiry
        # The actual expiry is managed by the server and refreshed on each use
        self._token_expires_at = time.time() + (30 * 60)  # 30 minutes

    def refresh_token(self) -> TokenResponse:
        """
        Refresh the current authentication token.

        Returns:
            TokenResponse with refreshed token information

        Raises:
            AuthenticationError: If refresh fails or no token exists
        """
        if not self._token_info:
            raise AuthenticationError("No existing token to refresh")

        # Use the current token to get a new one (introspection)
        response = self.client._make_request(
            method="POST", endpoint="/auth/introspect", json_data={"token": self._token}
        )

        # If introspection succeeds, the token is still valid
        # In practice, Cordra handles token refresh automatically
        refreshed_info = TokenResponse.from_dict(response)
        self._set_token(refreshed_info)

        return refreshed_info

    def revoke_token(self, token: Optional[str] = None) -> bool:
        """
        Revoke an authentication token.

        Args:
            token: Token to revoke (uses current token if not specified)

        Returns:
            True if successfully revoked

        Raises:
            AuthenticationError: If revocation fails
        """
        token_to_revoke = token or self._token
        if not token_to_revoke:
            raise AuthenticationError("No token to revoke")

        response = self.client._make_request(
            method="POST", endpoint="/auth/revoke", json_data={"token": token_to_revoke}
        )

        # Clear current token
        self._token = None
        self._token_info = None
        self._token_expires_at = None

        return response.get("active", False) == False

    def get_token_info(self) -> TokenResponse:
        """
        Get information about the current token.

        Returns:
            TokenResponse with current token information

        Raises:
            AuthenticationError: If no token exists or introspection fails
        """
        if not self._token:
            raise AuthenticationError("No active token")

        response = self.client._make_request(
            method="POST", endpoint="/auth/introspect", json_data={"token": self._token}
        )

        self._token_info = TokenResponse.from_dict(response)
        return self._token_info

    def ensure_authenticated(self):
        """Ensure client is authenticated, refreshing token if necessary."""
        if not self.is_authenticated:
            if self._token_info:
                # Try to refresh existing token
                try:
                    self.refresh_token()
                except AuthenticationError:
                    # Refresh failed, need new authentication
                    raise AuthenticationError(
                        "Token expired and could not be refreshed"
                    )
            else:
                raise AuthenticationError("Not authenticated")

    def clear_authentication(self):
        """Clear all authentication information."""
        self._token = None
        self._token_info = None
        self._token_expires_at = None
