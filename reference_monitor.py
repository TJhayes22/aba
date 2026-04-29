"""Reference monitor for access control in ABA."""

from typing import Optional

# Action constants
HELP = "HELP"
LOGIN = "LOGIN"
LOGOUT = "LOGOUT"
CHANGE_PW = "CHANGE_PW"
ADD_USER = "ADD_USER"
DELETE_USER = "DELETE_USER"
VIEW_LOG = "VIEW_LOG"
ADD_RECORD = "ADD_RECORD"
GET_RECORD = "GET_RECORD"
EDIT_RECORD = "EDIT_RECORD"
DELETE_RECORD = "DELETE_RECORD"
IMPORT = "IMPORT"
EXPORT = "EXPORT"


def check_access(session, action: str, obj: Optional[dict] = None) -> bool:
    """Check if a session has access to perform an action.
    
    Args:
        session: The user's session object.
        action: The action to check (use constants defined above).
        obj: Optional object dict with owner field for ownership checks.
        
    Returns:
        True if access granted, False otherwise.
    """
    # Rule 1: HELP always returns True
    if action == HELP:
        return True
    
    # Rule 2: LOGIN always returns True
    if action == LOGIN:
        return True
    
    # Rule 3: Any other action requires authentication
    if not session.is_authenticated:
        return False
    
    # Rule 4: Admin-only actions
    if action in [ADD_USER, DELETE_USER, VIEW_LOG]:
        return session.role == "admin"
    
    # Rule 5: Ownership checks for record operations
    if action in [GET_RECORD, EDIT_RECORD, DELETE_RECORD]:
        if obj is None:
            return False
        owner = obj.get("owner")
        if owner != session.username and session.role != "admin":
            return False
        return True
    
    # Rule 6: All other authenticated actions
    return True
