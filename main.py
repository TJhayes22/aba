"""Main entry point for ABA - Address Book Appliance."""

from session import Session
from cli import parse_command, dispatch


def main():
    """Main loop for the ABA CLI application."""
    session = Session()
    print("ABA - Address Book Appliance. Type 'help' for commands.")
    
    while True:
        try:
            raw = input("aba> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        
        if not raw:
            continue
        
        command, args = parse_command(raw)
        result = dispatch(command, args, session)
        print(result)


if __name__ == "__main__":
    main()
