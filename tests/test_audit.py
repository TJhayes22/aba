"""Tests for audit module."""

import pytest
import os
from audit import log_event, display_log
from storage import read_audit_log


class TestLogEvent:
    """Test log_event function."""
    
    def test_log_event_creates_file(self, tmp_data_dir):
        """After calling log_event, entry appears in audit.log file."""
        log_event("alice", "add_record", "rec-001", "OK")
        
        # Verify file exists
        log_file = os.path.join(str(tmp_data_dir), "audit.log")
        assert os.path.exists(log_file)
    
    def test_log_event_contains_fields(self, tmp_data_dir):
        """Entry contains the actor, action, target, and outcome fields."""
        log_event("alice", "add_record", "rec-001", "OK")
        
        log_entries = read_audit_log()
        assert len(log_entries) > 0
        
        entry = log_entries[0]
        assert "alice" in entry
        assert "add_record" in entry
        assert "rec-001" in entry
        assert "OK" in entry
    
    def test_log_event_contains_timestamp(self, tmp_data_dir):
        """Entry contains a timestamp."""
        log_event("alice", "add_record", "rec-001", "OK")
        
        log_entries = read_audit_log()
        entry = log_entries[0]
        
        # Should contain ISO timestamp format
        assert "[" in entry and "]" in entry and "Z" in entry
    
    def test_log_event_no_password_plaintext(self, tmp_data_dir):
        """Password arguments are not present in log."""
        log_event("alice", "login", "alice", "OK")
        
        log_entries = read_audit_log()
        entry = log_entries[0]
        
        # Should not contain any actual password
        assert "Admin@1234" not in entry
        assert "Alice@1234" not in entry


class TestDisplayLog:
    """Test display_log function."""
    
    def test_display_log_admin_allowed(self, tmp_data_dir, admin_session):
        """Admin session returns (True, list)."""
        log_event("alice", "add_record", "rec-001", "OK")
        
        success, result = display_log(admin_session)
        assert success is True
        assert isinstance(result, list)
    
    def test_display_log_user_denied(self, tmp_data_dir, user_session):
        """Standard user session returns (False, ...)."""
        log_event("alice", "add_record", "rec-001", "OK")
        
        success, result = display_log(user_session)
        assert success is False
    
    def test_display_log_unauthenticated_denied(self, tmp_data_dir, fresh_session):
        """Unauthenticated session returns (False, ...)."""
        log_event("alice", "add_record", "rec-001", "OK")
        
        success, result = display_log(fresh_session)
        assert success is False
    
    def test_display_log_contains_entries(self, tmp_data_dir, admin_session):
        """Returned list contains previously logged entries."""
        log_event("alice", "add_record", "rec-001", "OK")
        log_event("alice", "edit_record", "rec-001", "OK")
        
        success, result = display_log(admin_session)
        assert success is True
        assert len(result) >= 2
