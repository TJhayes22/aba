"""Session management for ABA."""

from typing import Optional


class Session:
    """Represents a user's session state."""

    def __init__(self):
        self.username: Optional[str] = None
        self.role: Optional[str] = None
        self.is_authenticated: bool = False

    def reset(self):
        """Clear all session fields back to defaults."""
        self.username = None
        self.role = None
        self.is_authenticated = False
