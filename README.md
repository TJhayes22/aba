# ABA - Address Book Appliance

A secure Python CLI application for managing address books with role-based access control, audit logging, and identity verification. Built with security as the top priority.

## Setup

### Prerequisites
- Python 3.9+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/TJhayes22/aba.git
cd aba

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run the Application

```bash
python main.py
```

## Quick Start

**WARNING: This application comes with a default admin account. If deploying in any shared environment, IMMEDIATELY change the password:**

```
aba> login admin Admin@1234
aba> passwd Admin@1234 [NEW_STRONG_PASSWORD]
```

**Default Credentials (Demo Only):**
- Username: `admin`
- Password: `Admin@1234`

## Commands

### Authentication
- `help` — Show all available commands
- `login <username> <password>` — Authenticate and start a session
- `logout` — End the current session
- `passwd <old_pw> <new_pw>` — Change your password

### User Management (Admin Only)
- `adduser <username> <password> [role]` — Add a new user (default role: user)
- `deluser <username>` — Delete a user (cannot delete 'admin')

### Address Records
- `addrec <name> <phone> <email> <address>` — Add a new address record
- `getrec <record_id>` — Retrieve a record by ID
- `editrec <record_id> <name> <phone> <email> <address>` — Edit an existing record
- `delrec <record_id>` — Delete a record

### Admin Functions
- `showlog` — View the audit log (admin only)

### Import/Export
- `import <filepath>` — Import records from JSON file
- `export <filepath>` — Export records to JSON file

## Features

- **Secure password hashing** — bcrypt with configurable rounds
- **Role-based access control** — Admin and User roles with granular permissions
- **Audit logging** — Complete audit trail with ISO timestamps
- **Import/export** — Secure backup and restore of address records
- **Account lockout** — Protection against brute force (5 failed attempts = 300s lockout)
- **Path sanitization** — Prevents directory traversal attacks
- **Input validation** — Strict field length and format validation
- **Session management** — Secure authentication with token-like sessions

## Data Storage

Persistent data is stored locally in the `data/` directory:
- `users.json` — User accounts with bcrypt-hashed passwords
- `records.json` — Address book records with ownership metadata
- `audit.log` — Audit trail with timestamps and outcomes

**Note:** The `data/` directory is not tracked by Git for privacy.

## Security Features

- Passwords never stored or logged in plaintext
- Bcrypt hashing with random salts
- Role-based access control (RBAC) enforced by reference monitor
- Record ownership validation — users can only access their own records
- Account lockout after 5 failed login attempts
- Path sanitization blocks directory traversal attacks
- Field length and format validation on all inputs
- Complete audit trail of all operations
- File permissions set to 0o600 (user read/write only)

## Project Structure

```
aba/
├── main.py                  # Application entry point
├── cli.py                   # Command parsing and dispatch
├── session.py               # Session state management
├── auth.py                  # Authentication logic
├── security.py              # Password hashing and validation
├── storage.py               # Persistent file I/O
├── reference_monitor.py     # Access control enforcement
├── audit.py                 # Event logging
├── user_manager.py          # User CRUD operations
├── record_manager.py        # Address record CRUD operations
├── import_export.py         # Secure import/export functionality
├── requirements.txt         # Python dependencies
├── README.md                # This file
└── data/                    # Runtime data directory (created on first use)
    ├── users.json
    ├── records.json
    └── audit.log
```

## Example Workflow

```bash
# Start the app
python main.py

# Login as admin
aba> login admin Admin@1234
Login successful.

# Change the admin password
aba> passwd Admin@1234 MyNewPassword@5678
Password changed successfully.

# Add a new user
aba> adduser alice Alice@password user
User added.

# Add an address record
aba> addrec "Alice Smith" "555-1234" "alice@example.com" "123 Main St"
Record added with ID: 12345678-1234-1234-1234-123456789abc

# View the record
aba> getrec 12345678-1234-1234-1234-123456789abc
Record: name=Alice Smith, phone=555-1234, email=alice@example.com, address=123 Main St

# View audit log
aba> showlog
[2026-04-21T10:15:30Z] actor=admin action=LOGIN target=admin outcome=success
[2026-04-21T10:15:45Z] actor=admin action=CHANGE_PW target=admin outcome=success
...

# Logout
aba> logout
Logged out.
```

## Development Notes

- All dependencies are listed in `requirements.txt`
- The reference monitor (`reference_monitor.py`) is the single source of truth for access control
- Audit logging is called after every command regardless of success/failure
- Path validation prevents file operations outside approved directories

## License

MIT

---

**For security questions or issues, please contact the development team.