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
    """Check if a password meets strength requirements.
    
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!@#$%^&*)
    
    Args:
        password: The password to check.
        
    Returns:
        True if password is strong, False otherwise.
    """
    if len(password) < 8:
        return False
    
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*]', password))
    
    return has_upper and has_lower and has_digit and has_special


def validate_field(value: str, max_len: int, pattern: str | None = None) -> bool:
    """Validate a field value against constraints.
    
    Args:
        value: The value to validate.
        max_len: Maximum allowed length.
        pattern: Optional regex pattern to match against.
        
    Returns:
        True if valid, False otherwise.
    """
    if not value or len(value) > max_len:
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
