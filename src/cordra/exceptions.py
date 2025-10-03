"""
Cordra Python Client - Exception Classes

Custom exceptions for handling Cordra API errors and edge cases.
"""


class CordraError(Exception):
    """Base exception for all Cordra-related errors."""

    def __init__(self, message: str, status_code: int = None, response_data: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data or {}


class AuthenticationError(CordraError):
    """Raised when authentication fails."""
    pass


class AuthorizationError(CordraError):
    """Raised when authorization fails (insufficient permissions)."""
    pass


class ObjectNotFoundError(CordraError):
    """Raised when a requested object is not found."""
    pass


class ValidationError(CordraError):
    """Raised when request validation fails."""
    pass


class ServerError(CordraError):
    """Raised when the server returns a 5xx error."""
    pass


class NetworkError(CordraError):
    """Raised when there are network connectivity issues."""
    pass


class ConfigurationError(CordraError):
    """Raised when there's a configuration issue."""
    pass


def handle_http_error(response, response_data: dict = None):
    """
    Convert HTTP error responses to appropriate Cordra exceptions.

    Args:
        response: HTTP response object with status_code attribute
        response_data: Parsed JSON response data

    Raises:
        Appropriate CordraError subclass based on HTTP status code
    """
    status_code = response.status_code
    message = response_data.get('message', f'HTTP {status_code}') if response_data else f'HTTP {status_code}'

    if status_code == 401:
        raise AuthenticationError(message, status_code, response_data)
    elif status_code == 403:
        raise AuthorizationError(message, status_code, response_data)
    elif status_code == 404:
        raise ObjectNotFoundError(message, status_code, response_data)
    elif status_code == 400:
        raise ValidationError(message, status_code, response_data)
    elif 500 <= status_code < 600:
        raise ServerError(message, status_code, response_data)
    else:
        raise CordraError(message, status_code, response_data)
