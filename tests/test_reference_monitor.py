"""Tests for reference monitor module."""

import pytest
from reference_monitor import check_access


class TestUnauthenticatedSession:
    """Test access control for unauthenticated sessions."""
    
    def test_help_allowed_unauthenticated(self, fresh_session):
        """HELP returns True for unauthenticated."""
        assert check_access(fresh_session, "HELP") is True
    
    def test_login_allowed_unauthenticated(self, fresh_session):
        """LOGIN returns True for unauthenticated."""
        assert check_access(fresh_session, "LOGIN") is True
    
    def test_add_record_denied_unauthenticated(self, fresh_session):
        """ADD_RECORD returns False for unauthenticated."""
        assert check_access(fresh_session, "ADD_RECORD") is False
    
    def test_get_record_denied_unauthenticated(self, fresh_session):
        """GET_RECORD returns False for unauthenticated."""
        assert check_access(fresh_session, "GET_RECORD") is False
    
    def test_import_denied_unauthenticated(self, fresh_session):
        """IMPORT returns False for unauthenticated."""
        assert check_access(fresh_session, "IMPORT") is False
    
    def test_export_denied_unauthenticated(self, fresh_session):
        """EXPORT returns False for unauthenticated."""
        assert check_access(fresh_session, "EXPORT") is False
    
    def test_add_user_denied_unauthenticated(self, fresh_session):
        """ADD_USER returns False for unauthenticated."""
        assert check_access(fresh_session, "ADD_USER") is False
    
    def test_view_log_denied_unauthenticated(self, fresh_session):
        """VIEW_LOG returns False for unauthenticated."""
        assert check_access(fresh_session, "VIEW_LOG") is False


class TestStandardUserSession:
    """Test access control for standard user sessions."""
    
    def test_add_record_allowed(self, user_session):
        """ADD_RECORD returns True for user."""
        assert check_access(user_session, "ADD_RECORD") is True
    
    def test_import_allowed(self, user_session):
        """IMPORT returns True for user."""
        assert check_access(user_session, "IMPORT") is True
    
    def test_export_allowed(self, user_session):
        """EXPORT returns True for user."""
        assert check_access(user_session, "EXPORT") is True
    
    def test_add_user_denied(self, user_session):
        """ADD_USER returns False for user."""
        assert check_access(user_session, "ADD_USER") is False
    
    def test_delete_user_denied(self, user_session):
        """DELETE_USER returns False for user."""
        assert check_access(user_session, "DELETE_USER") is False
    
    def test_view_log_denied(self, user_session):
        """VIEW_LOG returns False for user."""
        assert check_access(user_session, "VIEW_LOG") is False
    
    def test_get_record_own_record(self, user_session):
        """GET_RECORD returns True for own record."""
        obj = {"owner": "alice"}
        assert check_access(user_session, "GET_RECORD", obj) is True
    
    def test_get_record_other_user_record(self, user_session, bob_session):
        """GET_RECORD returns False for other user's record."""
        obj = {"owner": "alice"}
        assert check_access(bob_session, "GET_RECORD", obj) is False
    
    def test_edit_record_other_user(self, bob_session):
        """EDIT_RECORD returns False for other user's record."""
        obj = {"owner": "alice"}
        assert check_access(bob_session, "EDIT_RECORD", obj) is False
    
    def test_delete_record_other_user(self, bob_session):
        """DELETE_RECORD returns False for other user's record."""
        obj = {"owner": "alice"}
        assert check_access(bob_session, "DELETE_RECORD", obj) is False


class TestAdminSession:
    """Test access control for admin sessions."""
    
    def test_add_user_allowed(self, admin_session):
        """ADD_USER returns True for admin."""
        assert check_access(admin_session, "ADD_USER") is True
    
    def test_delete_user_allowed(self, admin_session):
        """DELETE_USER returns True for admin."""
        assert check_access(admin_session, "DELETE_USER") is True
    
    def test_view_log_allowed(self, admin_session):
        """VIEW_LOG returns True for admin."""
        assert check_access(admin_session, "VIEW_LOG") is True
    
    def test_get_record_other_user_allowed(self, admin_session):
        """GET_RECORD returns True for admin accessing any record."""
        obj = {"owner": "alice"}
        assert check_access(admin_session, "GET_RECORD", obj) is True
    
    def test_edit_record_other_user_allowed(self, admin_session):
        """EDIT_RECORD returns True for admin."""
        obj = {"owner": "alice"}
        assert check_access(admin_session, "EDIT_RECORD", obj) is True
    
    def test_delete_record_other_user_allowed(self, admin_session):
        """DELETE_RECORD returns True for admin."""
        obj = {"owner": "alice"}
        assert check_access(admin_session, "DELETE_RECORD", obj) is True
