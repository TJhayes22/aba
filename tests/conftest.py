"""Shared pytest fixtures for ABA test suite."""

import pytest
import sys
import os
from pathlib import Path

# Add parent directory to path so we can import ABA modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from session import Session
from storage import save_users, save_records
from security import hash_password
import storage


@pytest.fixture
def fresh_session():
    """Return a new Session() instance with no user logged in."""
    return Session()


@pytest.fixture
def admin_session():
    """Return a Session with admin user logged in."""
    session = Session()
    session.username = "admin"
    session.role = "admin"
    session.is_authenticated = True
    return session


@pytest.fixture
def user_session():
    """Return a Session with alice (user) logged in."""
    session = Session()
    session.username = "alice"
    session.role = "user"
    session.is_authenticated = True
    return session


@pytest.fixture
def bob_session():
    """Return a Session with bob (user) logged in."""
    session = Session()
    session.username = "bob"
    session.role = "user"
    session.is_authenticated = True
    return session


@pytest.fixture
def tmp_data_dir(tmp_path, monkeypatch):
    """
    Monkeypatch storage.py's DATA_DIR to a temporary directory.
    Ensures tests never touch the real data/ folder.
    """
    temp_dir = tmp_path / "data"
    temp_dir.mkdir()
    
    # Monkeypatch all storage constants
    monkeypatch.setattr(storage, "DATA_DIR", str(temp_dir))
    monkeypatch.setattr(storage, "USERS_FILE", str(temp_dir / "users.json"))
    monkeypatch.setattr(storage, "RECORDS_FILE", str(temp_dir / "records.json"))
    monkeypatch.setattr(storage, "AUDIT_LOG_FILE", str(temp_dir / "audit.log"))
    
    yield temp_dir


@pytest.fixture
def seeded_users(tmp_data_dir):
    """
    Create and save seeded users: alice, bob, admin.
    Returns the users dict.
    """
    users = {
        "alice": {
            "password_hash": hash_password("Alice@1234"),
            "role": "user"
        },
        "bob": {
            "password_hash": hash_password("Bob@1234"),
            "role": "user"
        },
        "admin": {
            "password_hash": hash_password("Admin@1234"),
            "role": "admin"
        }
    }
    save_users(users)
    return users


@pytest.fixture
def seeded_records(tmp_data_dir, user_session):
    """
    Create and save seeded records: 
    - 2 records owned by "alice"
    - 1 record owned by "bob"
    
    Returns the records dict.
    """
    records = {
        "rec-alice-1": {
            "recordID": "rec-alice-1",
            "owner": "alice",
            "SN": "Smith",
            "GN": "Alice",
            "PEM": "alice@personal.com",
            "WEM": "alice@work.com",
            "PPH": "555-1111",
            "WPH": "555-2222",
            "SA": "123 Main St",
            "CITY": "Springfield",
            "STP": "IL",
            "CTY": "USA",
            "PC": "62701"
        },
        "rec-alice-2": {
            "recordID": "rec-alice-2",
            "owner": "alice",
            "SN": "Johnson",
            "GN": "Alice",
            "PEM": "alice.j@email.com",
            "WEM": "alice.johnson@corp.com",
            "PPH": "555-3333",
            "WPH": "555-4444",
            "SA": "456 Oak Ave",
            "CITY": "Chicago",
            "STP": "IL",
            "CTY": "USA",
            "PC": "60601"
        },
        "rec-bob-1": {
            "recordID": "rec-bob-1",
            "owner": "bob",
            "SN": "Brown",
            "GN": "Bob",
            "PEM": "bob@email.com",
            "WEM": "bob@work.com",
            "PPH": "555-5555",
            "WPH": "555-6666",
            "SA": "789 Elm St",
            "CITY": "Urbana",
            "STP": "IL",
            "CTY": "USA",
            "PC": "61801"
        }
    }
    save_records(records)
    return records
