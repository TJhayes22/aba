"""Record management for ABA."""

import uuid
import storage
from security import validate_field
from reference_monitor import check_access


# Field specifications (all max 64 chars per spec)
FIELD_NAMES = ["SN", "GN", "PEM", "WEM", "PPH", "WPH", "SA", "CITY", "STP", "CTY", "PC"]
FIELD_LIMITS = {name: 64 for name in FIELD_NAMES}
MAX_RECORDS_PER_USER = 256
MAX_RECORD_ID_LEN = 64


def add_record(session, fields: dict) -> tuple[bool, str]:
    """Add a new address record (ADR command).
    
    Args:
        session: The session of the person adding the record.
        fields: Dictionary with record ID and optional field values.
        
    Returns:
        Tuple of (success: bool, message_or_id: str).
        On success: (True, record_id)
        On failure: (False, error_message)
    """
    # Check access
    if not check_access(session, "ADD_RECORD"):
        return (False, "Admin not authorized")
    
    # Extract recordID
    record_id = fields.get("recordID", "").strip()
    if not record_id:
        return (False, "No recordID")
    
    if len(record_id) > MAX_RECORD_ID_LEN:
        return (False, "Invalid recordID")
    
    # Validate record fields
    record_data = {k: v for k, v in fields.items() if k in FIELD_NAMES}
    for field, value in record_data.items():
        if not validate_field(value, FIELD_LIMITS[field]):
            return (False, "One or more invalid record data fields")
    
    # Check record count
    records = storage.load_records()
    user_records = {rid: r for rid, r in records.items() if r.get("owner") == session.username}
    
    if len(user_records) >= MAX_RECORDS_PER_USER:
        return (False, "Number of records exceeds maximum")
    
    # Check duplicate recordID
    if record_id in user_records:
        return (False, "Duplicate recordID")
    
    # Create record
    new_record = {
        "recordID": record_id,
        "owner": session.username
    }
    new_record.update(record_data)
    
    # Save
    records[record_id] = new_record
    storage.save_records(records)
    
    return (True, record_id)


def get_record(session, record_id: str = None, field_names: list = None) -> tuple[bool, dict | str | list]:
    """Retrieve a record by ID (RER command).
    
    If no record_id specified, returns all records for the user.
    
    Args:
        session: The session of the person retrieving the record.
        record_id: Optional ID of the specific record. If None, returns all.
        field_names: Optional list of specific fields to return. If None, return all.
        
    Returns:
        Tuple of (success: bool, records_or_message).
    """
    # Check authentication
    if not session.is_authenticated:
        return (False, "No active login session")
    
    # Load records
    records = storage.load_records()
    
    # If no record_id specified, return all user records
    if not record_id:
        user_records = [r for r in records.values() if r.get("owner") == session.username]
        
        # Filter fields if specified
        if field_names:
            if not all(fn in FIELD_NAMES + ["recordID"] for fn in field_names):
                return (False, "Invalid fieldname(s)")
            filtered = []
            for rec in user_records:
                filtered_rec = {k: rec.get(k, "") for k in field_names if k in rec}
                filtered.append(filtered_rec)
            return (True, filtered)
        
        return (True, user_records)
    
    # Specific record requested
    if record_id not in records:
        return (False, "RecordID not found")
    
    record = records[record_id]
    
    # Check ownership
    if record.get("owner") != session.username:
        return (False, "Admin not authorized")
    
    # Filter fields if specified
    if field_names:
        if not all(fn in FIELD_NAMES + ["recordID"] for fn in field_names):
            return (False, "Invalid fieldname(s)")
        result = {k: record.get(k, "") for k in field_names if k in record}
    else:
        result = record
    
    return (True, result)


def edit_record(session, record_id: str, updated_fields: dict) -> tuple[bool, str]:
    """Edit an existing record (EDR command).
    
    Args:
        session: The session of the person editing the record.
        record_id: The ID of the record.
        updated_fields: Dictionary with fields to update.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check authentication
    if not session.is_authenticated:
        return (False, "No active login session")
    
    if not record_id:
        return (False, "Invalid recordID")
    
    # Load records
    records = storage.load_records()
    if record_id not in records:
        return (False, "RecordID not found")
    
    record = records[record_id]
    
    # Check ownership
    if record.get("owner") != session.username:
        return (False, "Admin not authorized")
    
    # Validate updated fields
    for field, value in updated_fields.items():
        if field not in FIELD_NAMES:
            return (False, "One or more invalid record data fields")
        if not validate_field(value, FIELD_LIMITS[field]):
            return (False, "One or more invalid record data fields")
        record[field] = value
    
    # Save
    storage.save_records(records)
    
    return (True, "OK")


def delete_record(session, record_id: str) -> tuple[bool, str]:
    """Delete a record (DER command).
    
    Args:
        session: The session of the person deleting the record.
        record_id: The ID of the record.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check authentication
    if not session.is_authenticated:
        return (False, "No active login session")
    
    if not record_id:
        return (False, "Invalid recordID")
    
    # Load records
    records = storage.load_records()
    if record_id not in records:
        return (False, "RecordID not found")
    
    record = records[record_id]
    
    # Check ownership
    if record.get("owner") != session.username:
        return (False, "Admin not authorized")
    
    # Delete
    del records[record_id]
    storage.save_records(records)
    
    return (True, "OK")

