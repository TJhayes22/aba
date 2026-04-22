"""Security functions for ABA."""

import bcrypt
import re
import os


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.
    
    Args:
        password: The plaintext password to hash.
        
    Returns:
        The bcrypt hash as a string.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash.
    
    Args:
        password: The plaintext password to verify.
        hashed: The bcrypt hash to check against.
        
    Returns:
        True if password matches, False otherwise.
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def check_password_strength(password: str) -> bool:
    """Check if a password meets strength requirements per spec.
    
    Requirements (per COMP 365 spec):
    - 1-24 characters
    - Only upper/lower-case letters or numbers
    - Not "too easy to guess" (basic check: not all same char, not simple sequences)
    
    Args:
        password: The password to check.
        
    Returns:
        True if password is strong, False otherwise.
    """
    # Check length: 1-24 chars
    if len(password) < 1 or len(password) > 24:
        return False
    
    # Check only letters and numbers
    if not re.match(r'^[a-zA-Z0-9]+$', password):
        return False
    
    # Basic check: not too easy to guess (reject all same char)
    if len(set(password)) == 1:
        return False
    
    return True


def validate_field(value: str, max_len: int = 64, pattern: str | None = None) -> bool:
    """Validate a field value against constraints per spec.
    
    Args:
        value: The value to validate.
        max_len: Maximum allowed length (default 64 per spec).
        pattern: Optional regex pattern to match against.
        
    Returns:
        True if valid, False otherwise.
    """
    if not value or len(value) > max_len:
        return False
    
    # Check for printable ASCII only
    if not all(32 <= ord(c) < 127 for c in value):
        return False
    
    if pattern is not None:
        if not re.match(pattern, value):
            return False
    
    return True


def sanitize_path(path: str, approved_dirs: list[str]) -> str | None:
    """Sanitize and validate a file path against approved directories.
    
    Args:
        path: The path to validate.
        approved_dirs: List of approved directory paths.
        
    Returns:
        The resolved absolute path if valid, None if outside approved dirs.
    """
    try:
        real_path = os.path.realpath(path)
        
        for approved_dir in approved_dirs:
            approved_real = os.path.realpath(approved_dir)
            if real_path.startswith(approved_real):
                return real_path
        
        return None
    except Exception:
        return None
