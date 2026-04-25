class DarkMatterError(Exception):
    """Base exception for all DarkMatter SDK errors."""

class AuthError(DarkMatterError):
    """Raised when authentication fails (invalid or missing API key)."""

class NotFoundError(DarkMatterError):
    """Raised when a context ID is not found."""
