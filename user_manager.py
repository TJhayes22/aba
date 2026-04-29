"""User management for ABA."""

import storage
from reference_monitor import check_access, ADD_USER, DELETE_USER


APPROVED_ROLES = ["user", "admin"]
MAX_USERNAME_LEN = 16


def add_user(session, username: str) -> tuple[bool, str]:
    """Add a new user to the system (ADU command).
    
    Args:
        session: The session of the person adding the user (admin only).
        username: The username for the new user.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access (admin only)
    if not check_access(session, ADD_USER):
        return (False, "Admin not authorized")
    
    # Validate username: alphanumeric, 1-16 chars
    if not username or len(username) > MAX_USERNAME_LEN:
        return (False, "Invalid userID")
    
    if not username.isalnum():
        return (False, "Invalid userID")
    
    # Check username not already taken
    users = storage.load_users()
    if username in users:
        return (False, "Account already exists")
    
    # Add user (role defaults to "user", password created on first login)
    users[username] = {
        "role": "user",
        "password_hash": ""
    }
    storage.save_users(users)
    
    return (True, "OK")


def delete_user(session, username: str) -> tuple[bool, str]:
    """Delete a user from the system (DEU command).
    
    Args:
        session: The session of the person deleting the user (admin only).
        username: The username of the user to delete.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access (admin only)
    if not check_access(session, DELETE_USER):
        return (False, "Admin not authorized")
    
    # Validate username format
    if not username or len(username) > MAX_USERNAME_LEN:
        return (False, "Invalid userID")
    
    if not username.isalnum():
        return (False, "Invalid userID")
    
    # Load users and check target exists
    users = storage.load_users()
    if username not in users:
        return (False, "Account does not exist")
    
    # Delete user and all associated records
    del users[username]
    storage.save_users(users)
    
    # Delete all records owned by user
    records = storage.load_records()
    user_records = [rid for rid, r in records.items() if r.get("owner") == username]
    for rid in user_records:
        del records[rid]
    storage.save_records(records)
    
    return (True, "OK")


def list_users(session) -> str:
    """List all user accounts (LSU command).
    
    Args:
        session: The session of the admin user.
        
    Returns:
        String with list of all users, one per line.
    """
    users = storage.load_users()
    user_list = sorted(users.keys())
    return "\n".join(user_list)


def display_audit_log(session, target_user: str = None) -> str:
    """Display audit log entries (DAL command).
    
    Args:
        session: The session of the admin user.
        target_user: Optional specific user to filter for.
        
    Returns:
        String with audit log entries.
    """
    import storage
    
    # Validate target user if specified
    if target_user:
        users = storage.load_users()
        if target_user not in users:
            return "Account does not exist"
    
    # Get audit log
    audit_entries = storage.read_audit_log()
    
    # Filter by user if specified
    if target_user:
        filtered = [entry for entry in audit_entries if f"actor={target_user}" in entry or f"userID={target_user}" in entry]
        audit_entries = filtered
    
    if not audit_entries:
        return "OK"
    
    return "\n".join(audit_entries)

