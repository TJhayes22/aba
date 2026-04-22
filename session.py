"""Session management for ABA."""


class Session:
    """Represents a user's session state."""

    def __init__(self):
        self.username: str | None = None
        self.role: str | None = None
        self.is_authenticated: bool = False

    def reset(self):
        """Clear all session fields back to defaults."""
        self.username = None
        self.role = None
        self.is_authenticated = False
