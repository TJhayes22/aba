"""CLI interface for ABA."""

import auth
import user_manager
import record_manager
import import_export
import audit
from reference_monitor import check_access


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
    
    command = tokens[0].lower()
    args = tokens[1:]
    
    return (command, args)


def parse_record_args(args: list[str]) -> dict:
    """Parse record arguments into a dictionary.
    
    Expected format:
    name phone email address
    Or:
    name=value phone=value email=value address=value
    
    Args:
        args: List of arguments.
        
    Returns:
        Dictionary with record fields.
    """
    result = {}
    
    # Try key=value format first
    if args and "=" in args[0]:
        for arg in args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                result[key] = value
    else:
        # Positional format: name phone email address
        field_names = ["name", "phone", "email", "address"]
        for i, field_name in enumerate(field_names):
            if i < len(args):
                result[field_name] = args[i]
    
    return result


def print_help() -> str:
    """Return help text listing all commands.
    
    Returns:
        Help text string.
    """
    help_text = """
ABA - Address Book Appliance

Commands:
  help                          Show this help message
  login <username> <password>   Log in to the system
  logout                        Log out of the system
  passwd <old_pw> <new_pw>      Change your password
  adduser <username> <passwd>   Add a new user (admin only)
  deluser <username>            Delete a user (admin only)
  showlog                       View audit log (admin only)
  addrec <name> <phone> <email> <address>
                                Add a new address record
  getrec <record_id>            Get a record by ID
  editrec <record_id> <name> <phone> <email> <address>
                                Edit a record
  delrec <record_id>            Delete a record
  import <filepath>             Import records from JSON file
  export <filepath>             Export records to JSON file
""".strip()
    return help_text


def dispatch(command: str, args: list[str], session) -> str | list[str]:
    """Dispatch a command to its handler.
    
    Args:
        command: The command to execute.
        args: List of arguments for the command.
        session: The user's session object.
        
    Returns:
        String result to print to the user.
    """
    if command == "help":
        return print_help()
    
    elif command == "login":
        if len(args) < 2:
            return "Usage: login <username> <password>"
        success, message = auth.login(args[0], args[1], session)
        outcome = "success" if success else "failure"
        audit.log_event("SYSTEM" if not success else args[0], "LOGIN", args[0], outcome)
        return message
    
    elif command == "logout":
        success, message = auth.logout(session)
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "LOGOUT", actor, outcome)
        return message
    
    elif command == "passwd":
        if len(args) < 2:
            return "Usage: passwd <old_password> <new_password>"
        success, message = auth.change_password(session, args[0], args[1])
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "CHANGE_PW", actor, outcome)
        return message
    
    elif command == "adduser":
        if len(args) < 2:
            return "Usage: adduser <username> <password>"
        role = args[2] if len(args) > 2 else "user"
        success, message = user_manager.add_user(session, args[0], args[1], role)
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "ADD_USER", args[0], outcome)
        return message
    
    elif command == "deluser":
        if len(args) < 1:
            return "Usage: deluser <username>"
        success, message = user_manager.delete_user(session, args[0])
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "DELETE_USER", args[0], outcome)
        return message
    
    elif command == "showlog":
        success, content = audit.display_log(session)
        if not success:
            outcome = "failure"
            audit.log_event(session.username if session.is_authenticated else "SYSTEM", "VIEW_LOG", "audit_log", outcome)
            return content
        outcome = "success"
        audit.log_event(session.username, "VIEW_LOG", "audit_log", outcome)
        if isinstance(content, list):
            return "\n".join(content) if content else "(empty log)"
        return content
    
    elif command == "addrec":
        if len(args) < 4:
            return "Usage: addrec <name> <phone> <email> <address>"
        fields = parse_record_args(args)
        success, result = record_manager.add_record(session, fields)
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        target = result if success else "unknown"
        audit.log_event(actor, "ADD_RECORD", target, outcome)
        if success:
            return f"Record added with ID: {result}"
        return result
    
    elif command == "getrec":
        if len(args) < 1:
            return "Usage: getrec <record_id>"
        success, result = record_manager.get_record(session, args[0])
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "GET_RECORD", args[0], outcome)
        if success:
            r = result
            return f"Record: name={r['name']}, phone={r['phone']}, email={r['email']}, address={r['address']}"
        return result
    
    elif command == "editrec":
        if len(args) < 5:
            return "Usage: editrec <record_id> <name> <phone> <email> <address>"
        record_id = args[0]
        fields = parse_record_args(args[1:])
        success, message = record_manager.edit_record(session, record_id, fields)
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "EDIT_RECORD", record_id, outcome)
        return message
    
    elif command == "delrec":
        if len(args) < 1:
            return "Usage: delrec <record_id>"
        success, message = record_manager.delete_record(session, args[0])
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "DELETE_RECORD", args[0], outcome)
        return message
    
    elif command == "import":
        if len(args) < 1:
            return "Usage: import <filepath>"
        success, message = import_export.import_db(session, args[0])
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "IMPORT", args[0], outcome)
        return message
    
    elif command == "export":
        if len(args) < 1:
            return "Usage: export <filepath>"
        success, message = import_export.export_db(session, args[0])
        actor = session.username if session.is_authenticated else "SYSTEM"
        outcome = "success" if success else "failure"
        audit.log_event(actor, "EXPORT", args[0], outcome)
        return message
    
    elif command == "":
        return ""
    
    else:
        return "Unknown command. Type 'help' for usage."
