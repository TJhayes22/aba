"""Main entry point for ABA - Address Book Appliance per COMP 365 spec."""

from session import Session
from cli import parse_command, dispatch

# Version per COMP 365 spec
VERSION = "1.2.3"  # pylint: disable=invalid-name


def main():
    """Main loop for the ABA CLI application."""
    session = Session()
    print(f"Address Book Application, version {VERSION}. Type \"HLP\" for a list of commands.")
    
    while True:
        try:
            raw = input("ABA> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        
        if not raw:
            continue
        
        command, args = parse_command(raw)
        result, should_exit = dispatch(command, args, session)
        
        if result:
            print(result)
        
        if should_exit:
            break


if __name__ == "__main__":
    main()
