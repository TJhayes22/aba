"""Audit logging for ABA."""

from datetime import datetime, timezone
from typing import Optional

import storage
from reference_monitor import check_access


def log_event(actor: str, action: str, target: str, outcome: str):
    """Log an event to the audit log.
    
    Args:
        actor: The user or system performing the action.
        action: The action being performed.
        target: The object/subject of the action (never include sensitive data).
        outcome: The result of the action (e.g., "success" or "failure").
    """
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    entry = f"[{timestamp}] actor={actor} action={action} target={target} outcome={outcome}"
    storage.append_audit(entry)


def display_log(session) -> tuple[bool, Optional[list]]:
    """Display the audit log if user has access.
    
    Args:
        session: The user's session object.
        
    Returns:
        Tuple of (success: bool, content: list[str] | str).
        On success: (True, list of log entries)
        On failure: (False, error message)
    """
    if not check_access(session, "VIEW_LOG"):
        return (False, "Access denied.")
    
    log_entries = storage.read_audit_log()
    return (True, log_entries)
