"""Storage operations for ABA."""

import os
import json


DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
RECORDS_FILE = os.path.join(DATA_DIR, "records.json")
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit.log")


def _ensure_data_dir():
    """Ensure the data directory exists with proper permissions."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)


def _ensure_users_seeded():
    """Create default admin user if users.json doesn't exist.
    
    Per COMP 365 spec: admin user exists on first run with no password set.
    Admin must create password on first login attempt (LIN admin).
    """
    if not os.path.exists(USERS_FILE):
        users = {
            "admin": {
                "password_hash": "",  # No password set initially
                "role": "admin"
            }
        }
        save_users(users)


def load_users() -> dict:
    """Load users from users.json.
    
    Returns:
        Dictionary of users, or empty dict if file missing.
    """
    _ensure_data_dir()
    
    if not os.path.exists(USERS_FILE):
        _ensure_users_seeded()
        return load_users()
    
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_users(users: dict):
    """Save users to users.json.
    
    Args:
        users: Dictionary of users to save.
    """
    _ensure_data_dir()
    
    try:
        with open(USERS_FILE, "w", encoding='utf-8') as f:
            json.dump(users, f, indent=2)
        os.chmod(USERS_FILE, 0o600)
    except Exception:
        pass


def load_records() -> dict:
    """Load records from records.json.
    
    Returns:
        Dictionary of records, or empty dict if file missing.
    """
    _ensure_data_dir()
    
    if not os.path.exists(RECORDS_FILE):
        return {}
    
    try:
        with open(RECORDS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_records(records: dict):
    """Save records to records.json.
    
    Args:
        records: Dictionary of records to save.
    """
    _ensure_data_dir()
    
    try:
        with open(RECORDS_FILE, "w", encoding='utf-8') as f:
            json.dump(records, f, indent=2)
        os.chmod(RECORDS_FILE, 0o600)
    except Exception:
        pass


def append_audit(entry: str):
    """Append an entry to the audit log.
    
    Args:
        entry: The audit log entry to append.
    """
    _ensure_data_dir()
    
    try:
        with open(AUDIT_LOG_FILE, "a", encoding='utf-8') as f:
            f.write(entry + '\n')
        os.chmod(AUDIT_LOG_FILE, 0o600)
    except Exception:
        pass


def read_audit_log() -> list[str]:
    """Read all entries from the audit log.
    
    Returns:
        List of audit log entries, or empty list if file missing.
    """
    _ensure_data_dir()
    
    if not os.path.exists(AUDIT_LOG_FILE):
        return []
    
    try:
        with open(AUDIT_LOG_FILE, 'r') as f:
            return [line.rstrip('\n') for line in f.readlines()]
    except Exception:
        return []
