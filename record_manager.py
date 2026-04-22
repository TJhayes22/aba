"""Record management for ABA."""

import uuid
import storage
from security import validate_field
from reference_monitor import check_access


FIELD_LIMITS = {
    "name": 100,
    "phone": 20,
    "email": 100,
    "address": 200
}
REQUIRED_FIELDS = ["name", "phone", "email", "address"]


def add_record(session, fields: dict) -> tuple[bool, str | tuple]:
    """Add a new address record.
    
    Args:
        session: The session of the person adding the record.
        fields: Dictionary with keys "name", "phone", "email", "address".
        
    Returns:
        Tuple of (success: bool, record_id_or_message: str).
        On success: (True, record_id)
        On failure: (False, error_message)
    """
    # Check access
    if not check_access(session, "ADD_RECORD"):
        return (False, "Access denied.")
    
    # Validate all required fields
    for field in REQUIRED_FIELDS:
        if field not in fields:
            return (False, f"Missing required field: {field}")
        
        if not validate_field(fields[field], FIELD_LIMITS[field]):
            return (False, f"Invalid or missing field: {field}")
    
    # Create record
    record_id = str(uuid.uuid4())
    record = {
        "id": record_id,
        "owner": session.username,
        "name": fields["name"],
        "phone": fields["phone"],
        "email": fields["email"],
        "address": fields["address"]
    }
    
    # Save
    records = storage.load_records()
    records[record_id] = record
    storage.save_records(records)
    
    return (True, record_id)


def get_record(session, record_id: str) -> tuple[bool, dict | str]:
    """Retrieve a record by ID.
    
    Args:
        session: The session of the person retrieving the record.
        record_id: The UUID of the record.
        
    Returns:
        Tuple of (success: bool, record_dict_or_message: dict | str).
        On success: (True, record_dict)
        On failure: (False, error_message)
    """
    # Load records
    records = storage.load_records()
    if record_id not in records:
        return (False, "Record not found.")
    
    record = records[record_id]
    
    # Check access
    if not check_access(session, "GET_RECORD", {"owner": record["owner"]}):
        return (False, "Access denied.")
    
    return (True, record)


def edit_record(session, record_id: str, updated_fields: dict) -> tuple[bool, str]:
    """Edit an existing record.
    
    Args:
        session: The session of the person editing the record.
        record_id: The UUID of the record.
        updated_fields: Dictionary with fields to update.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Load records
    records = storage.load_records()
    if record_id not in records:
        return (False, "Record not found.")
    
    record = records[record_id]
    
    # Check access
    if not check_access(session, "EDIT_RECORD", {"owner": record["owner"]}):
        return (False, "Access denied.")
    
    # Validate and merge fields
    for field, value in updated_fields.items():
        if field in FIELD_LIMITS:
            if not validate_field(value, FIELD_LIMITS[field]):
                return (False, f"Invalid field: {field}")
            record[field] = value
    
    # Save
    storage.save_records(records)
    
    return (True, "Record updated.")


def delete_record(session, record_id: str) -> tuple[bool, str]:
    """Delete a record.
    
    Args:
        session: The session of the person deleting the record.
        record_id: The UUID of the record.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Load records
    records = storage.load_records()
    if record_id not in records:
        return (False, "Record not found.")
    
    record = records[record_id]
    
    # Check access
    if not check_access(session, "DELETE_RECORD", {"owner": record["owner"]}):
        return (False, "Access denied.")
    
    # Delete
    del records[record_id]
    storage.save_records(records)
    
    return (True, "Record deleted.")
