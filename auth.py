"""Authentication for ABA."""

import time
import storage
from security import hash_password, verify_password, check_password_strength
from reference_monitor import check_access


# Module-level state for lockout handling
_failed_attempts: dict[str, int] = {}
_lockout_until: dict[str, float] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def login(username: str, password: str, session) -> tuple[bool, str]:
    """Authenticate a user and start a session.
    
    Args:
        username: The username to authenticate.
        password: The plaintext password.
        session: The session object to populate on success.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Rule 1: Reject empty credentials
    if not username or not password:
        return (False, "Invalid input.")
    
    current_time = time.time()
    
    # Rule 2: Check lockout
    if username in _lockout_until:
        if current_time < _lockout_until[username]:
            return (False, "Account locked. Try again later.")
        else:
            del _lockout_until[username]
            _failed_attempts[username] = 0
    
    # Rule 3: Clear expired lockouts (already done above)
    
    # Rule 4: Load users and check if username exists
    users = storage.load_users()
    if username not in users:
        _failed_attempts[username] = _failed_attempts.get(username, 0) + 1
        return (False, "Invalid credentials.")
    
    user = users[username]
    
    # Rule 5: Verify password
    if not verify_password(password, user["password_hash"]):
        _failed_attempts[username] = _failed_attempts.get(username, 0) + 1
        
        if _failed_attempts[username] >= MAX_ATTEMPTS:
            _lockout_until[username] = current_time + LOCKOUT_SECONDS
            return (False, "Account locked due to too many failed attempts.")
        
        return (False, "Invalid credentials.")
    
    # Success: clear attempts and set session
    _failed_attempts[username] = 0
    if username in _lockout_until:
        del _lockout_until[username]
    
    session.username = username
    session.role = user["role"]
    session.is_authenticated = True
    
    return (True, "Login successful.")


def logout(session) -> tuple[bool, str]:
    """End a user's session.
    
    Args:
        session: The session object to terminate.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    if not session.is_authenticated:
        return (False, "Not logged in.")
    
    session.reset()
    return (True, "Logged out.")


def change_password(session, current_pw: str, new_pw: str) -> tuple[bool, str]:
    """Change the current user's password.
    
    Args:
        session: The session object.
        current_pw: The current password to verify.
        new_pw: The new password to set.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access
    if not check_access(session, "CHANGE_PW"):
        return (False, "Not logged in.")
    
    # Load users
    users = storage.load_users()
    if session.username not in users:
        return (False, "User not found.")
    
    user = users[session.username]
    
    # Verify current password
    if not verify_password(current_pw, user["password_hash"]):
        return (False, "Current password incorrect.")
    
    # Check new password strength
    if not check_password_strength(new_pw):
        return (False, "Password does not meet strength requirements.")
    
    # Update password
    user["password_hash"] = hash_password(new_pw)
    storage.save_users(users)
    
    return (True, "Password changed successfully.")
