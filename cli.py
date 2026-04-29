"""CLI interface for ABA per COMP 365 spec."""

from typing import Optional

import auth
import storage
import user_manager
import record_manager
import import_export


def parse_command(raw: str) -> tuple[str, list[str]]:
    """Parse a raw command string into command and arguments.
    
    Args:
        raw: The raw command line input.
        
    Returns:
        Tuple of (command: str, args: list[str]).
        Returns ("", []) for empty input.
    """
    tokens = raw.strip().split()
    if not tokens:
        return ("", [])
    
    command = tokens[0].upper()  # Spec uses uppercase commands
    args = tokens[1:]
    
    return (command, args)


def parse_record_fields(args: list[str]) -> dict:
    """Parse record field arguments in field=value format.
    
    Args:
        args: List of arguments.
        
    Returns:
        Dictionary with field values.
    """
    result = {}
    for arg in args:
        if "=" in arg:
            key, value = arg.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def print_help(command_name: Optional[str] = None) -> str:
    """Return help text for commands (HLP command).
    
    Args:
        command_name: Optional specific command to show help for.
        
    Returns:
        Help text string.
    """
    if command_name:
        help_text = {
            "LIN": "LIN <userID>\n  Login to an account",
            "LOU": "LOU\n  Logout from current account",
            "CHP": "CHP <old_password>\n  Change password",
            "ADU": "ADU <userID>\n  Add new user (admin only)",
            "DEU": "DEU <userID>\n  Delete user (admin only)",
            "LSU": "LSU\n  List all users (admin only)",
            "DAL": "DAL [<userID>]\n  Display audit log (admin only)",
            "ADR": "ADR <recordID> [<field=value> ...]\n  Add address record",
            "RER": "RER [<recordID>] [<fieldname> ...]\n  Read record",
            "EDR": "EDR <recordID> <field=value> [<field=value> ...]\n  Edit record",
            "DER": "DER <recordID>\n  Delete record",
            "IMD": "IMD <Input_File>\n  Import records from CSV file",
            "EXD": "EXD <Output_File>\n  Export records to CSV file",
            "HLP": "HLP [<command>]\n  Show help",
            "EXT": "EXT\n  Exit program"
        }
        return help_text.get(command_name.upper(), "Unrecognized command")
    
    full_help = """Address Book Appliance (ABA) Commands:

LIN <userID>                  Login to an account
LOU                           Logout from current account
CHP <old_password>            Change password
ADU <userID>                  Add new user (admin only)
DEU <userID>                  Delete user (admin only)
LSU                           List all users (admin only)
DAL [<userID>]                Display audit log (admin only)
ADR <recordID> [fields...]    Add address record
RER [<recordID>] [fields...]  Read record(s)
EDR <recordID> <fields...>    Edit record
DER <recordID>                Delete record
IMD <Input_File>              Import records from CSV file
EXD <Output_File>             Export records to CSV file
HLP [<command>]               Show help
EXT                           Exit program
"""
    return full_help


def dispatch(command: str, args: list[str], session) -> tuple[str, bool]:
    """Dispatch a command to its handler.
    
    Args:
        command: The command to execute (uppercase).
        args: List of arguments for the command.
        session: The user's session object.
        
    Returns:
        Tuple of (result_message: str, should_exit: bool).
    """
    if command == "HLP":
        if args:
            return (print_help(args[0]), False)
        return (print_help(), False)
    
    elif command == "EXT":
        if session.is_authenticated:
            session.reset()
        return ("OK", True)
    
    elif command == "LIN":
        if not args:
            return ("Invalid userID", False)
        
        # Check if user exists (to determine if first time)
        users = storage.load_users()
        is_first_time = args[0] not in users or not users[args[0]].get("password_hash")
        
        success, message = auth.login(args[0], is_first_time, session)
        return (message, False)
    
    elif command == "LOU":
        success, message = auth.logout(session)
        return (message, False)
    
    elif command == "CHP":
        if not args:
            return ("Invalid credentials", False)
        success, message = auth.change_password(session, args[0])
        return (message, False)
    
    elif command == "ADU":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role != "admin":
            return ("Admin not active", False)
        if not args:
            return ("Invalid userID", False)
        
        success, message = user_manager.add_user(session, args[0])
        return (message, False)
    
    elif command == "DEU":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role != "admin":
            return ("Admin not active", False)
        if not args:
            return ("Invalid userID", False)
        
        success, message = user_manager.delete_user(session, args[0])
        return (message, False)
    
    elif command == "LSU":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role != "admin":
            return ("Admin not active", False)
        
        users_list = user_manager.list_users(session)
        return (users_list, False)
    
    elif command == "DAL":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role != "admin":
            return ("Admin not active", False)
        
        target_user = args[0] if args else None
        result = user_manager.display_audit_log(session, target_user)
        return (result, False)
    
    elif command == "ADR":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role == "admin":
            return ("Admin not authorized", False)
        if not args:
            return ("No recordID", False)
        
        record_id = args[0]
        fields = {"recordID": record_id}
        fields.update(parse_record_fields(args[1:]))
        
        success, result = record_manager.add_record(session, fields)
        return (result if not success else f"OK\n{result}", False)
    
    if command == "RER":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role == "admin":
            return ("Admin not authorized", False)
        
        record_id = args[0] if args else None
        field_names = args[1:] if len(args) > 1 else None
        
        success, result = record_manager.get_record(session, record_id, field_names)
        if not success:
            return (result, False)
        
        # Format output
        if isinstance(result, list):
            output_lines = []
            for rec in result:
                line = f"{rec.get('recordID', '')}"
                for fn in record_manager.FIELD_NAMES:
                    if fn in rec:
                        line += f" {fn}={rec[fn]}"
                output_lines.append(line)
            return ("\n".join(output_lines), False)
        else:
            line = f"{result.get('recordID', '')}"
            for fn in record_manager.FIELD_NAMES:
                if fn in result:
                    line += f" {fn}={result[fn]}"
            return (line, False)
    
    elif command == "EDR":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role == "admin":
            return ("Admin not authorized", False)
        if not args:
            return ("No recordID", False)
        
        record_id = args[0]
        fields = parse_record_fields(args[1:])
        
        success, message = record_manager.edit_record(session, record_id, fields)
        return (message, False)
    
    if command == "DER":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role == "admin":
            return ("Admin not authorized", False)
        if not args:
            return ("No recordID", False)
        
        success, message = record_manager.delete_record(session, args[0])
        return (message, False)
    
    elif command == "IMD":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role == "admin":
            return ("Admin not authorized", False)
        if not args:
            return ("No Input_file specified", False)
        
        success, message = import_export.import_db(session, args[0])
        return (message, False)
    
    elif command == "EXD":
        if not session.is_authenticated:
            return ("No active login session", False)
        if session.role == "admin":
            return ("Admin not authorized", False)
        if not args:
            return ("No Output_file specified", False)
        
        success, message = import_export.export_db(session, args[0])
        return (message, False)
    
    elif command == "":
        return ("", False)
    
    else:
        return ("Unrecognized command", False)
