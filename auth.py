"""Authentication for ABA per COMP 365 spec."""

import storage
from security import hash_password, verify_password, check_password_strength


def login(username: str, is_first_time: bool, session) -> tuple[bool, str]:
    """Handle login (LIN command).
    
    For first-time logins, prompts user to create password.
    For existing accounts, requires password verification.
    
    Args:
        username: The userID to authenticate.
        is_first_time: Whether this is the first login for this account.
        session: The session object to populate on success.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check if active login already exists
    if session.is_authenticated:
        return (False, "An account is currently active; logout before proceeding")
    
    # Load users
    users = storage.load_users()
    
    # Check if username exists
    if username not in users:
        return (False, "Invalid credentials")
    
    user = users[username]
    
    # If first time, prompt for password creation
    if is_first_time or not user.get("password_hash"):
        print("This is the first time the account is being used. You must create a new password. Passwords may contain 1-24 upper- or lower-case letters or numbers. Choose an uncommon password that would be difficult to guess.")
        password1 = input("Enter your password: ")
        password2 = input("Reenter the same password: ")
        
        # Spec order: Check passwords match first
        if password1 != password2:
            return (False, "Passwords do not match")
        
        # Spec order: Check password format (letters and numbers only, 1-24 chars)
        if not password1 or len(password1) > 24 or not password1.isalnum():
            return (False, "Password contains illegal characters")
        
        # Spec order: Check password strength (not too easy)
        if not check_password_strength(password1):
            return (False, "Password is too easy to guess")
        
        # Hash and save password
        user["password_hash"] = hash_password(password1)
        storage.save_users(users)
    else:
        # Existing account - prompt for password
        print("Enter your password: ", end="")
        password = input()
        
        # Verify password
        if not verify_password(password, user["password_hash"]):
            return (False, "Invalid credentials")
    
    # Success: set session
    session.username = username
    session.role = user["role"]
    session.is_authenticated = True
    
    return (True, "OK")


def logout(session) -> tuple[bool, str]:
    """End a user's session (LOU command).
    
    Args:
        session: The session object to terminate.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    if not session.is_authenticated:
        return (False, "No active login session")
    
    session.reset()
    return (True, "OK")


def change_password(session, current_pw: str) -> tuple[bool, str]:
    """Change the current user's password (CHP command).
    
    Args:
        session: The session object.
        current_pw: The current password to verify.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check active session
    if not session.is_authenticated:
        return (False, "No active login session")
    
    # Load users
    users = storage.load_users()
    if session.username not in users:
        return (False, "No active login session")
    
    user = users[session.username]
    
    # Verify current password
    if not verify_password(current_pw, user["password_hash"]):
        return (False, "Invalid credentials")
    
    # Prompt for new password
    print("Create a new password. Passwords may contain up to 24 upper- or lower-case letters or numbers. Choose an uncommon password that would be difficult to guess.")
    new_pw1 = input("Enter your password: ")
    new_pw2 = input("Reenter the same password: ")
    
    # Spec order: Check if passwords match
    if new_pw1 != new_pw2:
        return (False, "Passwords do not match")
    
    # Spec order: Check password format
    if not new_pw1 or len(new_pw1) > 24 or not new_pw1.isalnum():
        return (False, "Password contains illegal characters")
    
    # Spec order: Check password strength
    if not check_password_strength(new_pw1):
        return (False, "Password is too easy to guess")
    
    # Update password
    user["password_hash"] = hash_password(new_pw1)
    storage.save_users(users)
    
    return (True, "OK")
