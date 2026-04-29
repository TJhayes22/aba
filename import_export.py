"""Import/export functionality for ABA."""

import os
import csv
import storage
from security import validate_field
from reference_monitor import check_access


APPROVED_EXPORT_DIRS = ["/tmp/aba_exports", "./exports"]
MAX_IMPORT_BYTES = 1_048_576
MAX_IMPORT_RECORDS = 500

FIELD_NAMES = ["SN", "GN", "PEM", "WEM", "PPH", "WPH", "SA", "CITY", "STP", "CTY", "PC"]
FIELD_LIMITS = {name: 64 for name in FIELD_NAMES}


def import_db(session, filepath: str) -> tuple[bool, str]:
    """Import records from a semicolon-delimited CSV file (IMD command).
    
    CSV format per spec: recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC
    
    Args:
        session: The session of the person importing.
        filepath: Path to the CSV file to import.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access
    if not check_access(session, "IMPORT"):
        return (False, "Admin not authorized")
    
    if not filepath:
        return (False, "No Input_file specified")
    
    # Check file exists
    if not os.path.exists(filepath):
        return (False, "Can't open Input_file")
    
    # Check file size
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_IMPORT_BYTES:
            return (False, "Can't open Input_file")
    except Exception:
        return (False, "Can't open Input_file")
    
    # Parse CSV
    records_to_import = []
    try:
        with open(filepath, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=';')
            for row in reader:
                if not row or all(not cell.strip() for cell in row):
                    continue
                records_to_import.append(row)
    except Exception:
        return (False, "Input_file invalid format")
    
    # Check record count
    if len(records_to_import) > MAX_IMPORT_RECORDS:
        return (False, "Number of records exceeds maximum")
    
    # Validate all records
    imported_records = {}
    user_records = storage.load_records()
    
    for row in records_to_import:
        if len(row) < 1:
            return (False, "Input_file invalid format")
        
        record_id = row[0].strip()
        if not record_id:
            return (False, "Input_file invalid format")
        
        # Check for duplicate within import file
        if record_id in imported_records:
            return (False, "Duplicate recordID")
        
        # Check for duplicate in existing database
        if record_id in user_records:
            return (False, "Duplicate recordID")
        
        # Build record with field values
        record = {"recordID": record_id, "owner": session.username}
        
        # Fill in fields (max 12 fields: SN, GN, PEM, WEM, PPH, WPH, SA, CITY, STP, CTY, PC)
        for i, field_name in enumerate(FIELD_NAMES):
            if i + 1 < len(row):
                value = row[i + 1].strip()
                if value:
                    if not validate_field(value, FIELD_LIMITS[field_name]):
                        return (False, "Input_file invalid format")
                    record[field_name] = value
        
        imported_records[record_id] = record
    
    # All validations passed, add to database
    user_records.update(imported_records)
    storage.save_records(user_records)
    
    return (True, "OK")


def export_db(session, filepath: str) -> tuple[bool, str]:
    """Export records to a semicolon-delimited CSV file (EXD command).
    
    CSV format per spec: recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC
    
    Args:
        session: The session of the person exporting.
        filepath: Path where to write the CSV file.
        
    Returns:
        Tuple of (success: bool, message: str).
    """
    # Check access
    if not check_access(session, "EXPORT"):
        return (False, "Admin not authorized")
    
    if not filepath:
        return (False, "No Output_file specified")
    
    # Load records and filter by owner
    all_records = storage.load_records()
    user_records = [
        record for record in all_records.values()
        if record.get("owner") == session.username
    ]
    
    # Write to file
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            for record in user_records:
                row = [
                    record.get("recordID", ""),
                    record.get("SN", ""),
                    record.get("GN", ""),
                    record.get("PEM", ""),
                    record.get("WEM", ""),
                    record.get("PPH", ""),
                    record.get("WPH", ""),
                    record.get("SA", ""),
                    record.get("CITY", ""),
                    record.get("STP", ""),
                    record.get("CTY", ""),
                    record.get("PC", "")
                ]
                writer.writerow(row)
        os.chmod(filepath, 0o600)
        return (True, "OK")
    except IOError:
        return (False, "Can't open Output_file")
    except Exception:
        return (False, "Error writing Output_file")
