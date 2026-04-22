"""Import/export functionality for ABA."""

import os
import json
import uuid
import storage
from security import sanitize_path, validate_field
from reference_monitor import check_access


APPROVED_EXPORT_DIRS = ["/tmp/aba_exports", "./exports"]
MAX_IMPORT_BYTES = 1_048_576
MAX_IMPORT_RECORDS = 500

FIELD_LIMITS = {
    "name": 100,
    "phone": 20,
    "email": 100,
    "address": 200
}
REQUIRED_FIELDS = ["name", "phone", "email", "address"]


def import_db(session, filepath: str) -> tuple[bool, str]:
    """Import records from a JSON file.
    
    Args:
        session: The session of the person importing.
        filepath: Path to the JSON file to import.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access
    if not check_access(session, "IMPORT"):
        return (False, "Access denied.")
    
    # Check file exists
    if not os.path.exists(filepath):
        return (False, "File not found.")
    
    # Check file size
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_IMPORT_BYTES:
            return (False, f"File too large. Maximum {MAX_IMPORT_BYTES} bytes.")
    except Exception:
        return (False, "Cannot read file.")
    
    # Parse JSON
    data = None
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except Exception:
        return (False, "Invalid JSON format.")
    
    # Must be a list
    if not isinstance(data, list):
        return (False, "Import data must be a list of records.")
    
    # Check record count
    if len(data) > MAX_IMPORT_RECORDS:
        return (False, f"Too many records. Maximum {MAX_IMPORT_RECORDS}.")
    
    # Validate all records before importing
    for record in data:
        if not isinstance(record, dict):
            return (False, "Invalid record format.")
        
        for field in REQUIRED_FIELDS:
            if field not in record:
                return (False, f"Missing required field: {field}")
            
            if not validate_field(record[field], FIELD_LIMITS[field]):
                return (False, f"Invalid field value: {field}")
    
    # All validations passed, import records (overwrite owner on each)
    records = storage.load_records()
    
    for record in data:
        record_id = str(uuid.uuid4())
        records[record_id] = {
            "id": record_id,
            "owner": session.username,
            "name": record["name"],
            "phone": record["phone"],
            "email": record["email"],
            "address": record["address"]
        }
    
    storage.save_records(records)
    
    return (True, f"Imported {len(data)} records.")


def export_db(session, filepath: str) -> tuple[bool, str]:
    """Export records to a JSON file.
    
    Args:
        session: The session of the person exporting.
        filepath: Path where to write the JSON file.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access
    if not check_access(session, "EXPORT"):
        return (False, "Access denied.")
    
    # Create export directories if needed
    try:
        for approved_dir in APPROVED_EXPORT_DIRS:
            if not os.path.exists(approved_dir):
                os.makedirs(approved_dir, exist_ok=True)
    except Exception:
        return (False, "Cannot create export directory.")
    
    # Sanitize path
    safe_path = sanitize_path(filepath, APPROVED_EXPORT_DIRS)
    if safe_path is None:
        return (False, "Unsafe or unapproved export path.")
    
    # Load records and filter by owner
    all_records = storage.load_records()
    user_records = [
        record for record in all_records.values()
        if record.get("owner") == session.username
    ]
    
    # Write to file
    try:
        with open(safe_path, 'w') as f:
            json.dump(user_records, f, indent=2)
        os.chmod(safe_path, 0o600)
        return (True, f"Exported {len(user_records)} records.")
    except Exception:
        return (False, "Cannot write export file.")
