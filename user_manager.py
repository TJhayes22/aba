"""User management for ABA."""

import storage
from security import hash_password, check_password_strength, validate_field
from reference_monitor import check_access


APPROVED_ROLES = ["user", "admin"]
MAX_USERNAME_LEN = 32


def add_user(session, new_username: str, initial_password: str, 
             role: str = "user") -> tuple[bool, str]:
    """Add a new user to the system.
    
    Args:
        session: The session of the person adding the user.
        new_username: The username for the new user.
        initial_password: The initial password for the new user.
        role: The role for the new user (default "user").
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access
    if not check_access(session, "ADD_USER"):
        return (False, "Access denied.")
    
    # Validate username: non-empty, max length, alphanumeric+underscore only
    if not validate_field(new_username, MAX_USERNAME_LEN, pattern=r"^[a-zA-Z0-9_]+$"):
        return (False, "Invalid username format.")
    
    # Check username not already taken
    users = storage.load_users()
    if new_username in users:
        return (False, "Username already exists.")
    
    # Check role is valid
    if role not in APPROVED_ROLES:
        return (False, "Invalid role.")
    
    # Check password strength
    if not check_password_strength(initial_password):
        return (False, "Password does not meet strength requirements.")
    
    # Add user
    users[new_username] = {
        "password_hash": hash_password(initial_password),
        "role": role
    }
    storage.save_users(users)
    
    return (True, "User added.")


def delete_user(session, target_username: str) -> tuple[bool, str]:
    """Delete a user from the system.
    
    Args:
        session: The session of the person deleting the user.
        target_username: The username of the user to delete.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access
    if not check_access(session, "DELETE_USER"):
        return (False, "Access denied.")
    
    # Reject deleting protected admin account
    if target_username == "admin":
        return (False, "Cannot delete the admin account.")
    
    # Load users and check target exists
    users = storage.load_users()
    if target_username not in users:
        return (False, "User not found.")
    
    # Delete user
    del users[target_username]
    storage.save_users(users)
    
    return (True, "User deleted.")
