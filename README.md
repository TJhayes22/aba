# ABA - Address Book Appliance

A secure Python CLI application for managing address books with role-based access control, audit logging, and identity verification. Built with security as the top priority.

## Setup

### Prerequisites
- Python 3.9+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/TJhayes22/aba
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
ABA> LIN admin
[Enter new password on first login]
ABA> CHP
[Enter new strong password]
```

**Note:** Default admin account password is created on first login.

## Commands (COMP 365 Specification v1.2.3)

### Authentication & Help
- `HLP` — Display help for all commands
- `HLP <command>` — Display help for specific command
- `LIN <userID>` — Login (password created interactively on first use)
- `LOU` — Logout
- `CHP` — Change password (interactive password entry)
- `EXT` — Exit application

### User Management (Admin Only)
- `ADU <userID>` — Add a new user account
- `DEU <userID>` — Delete a user account
- `LSU` — List all user accounts (admin only)
- `DAL [userID]` — Display audit log (optionally filtered by user)

### Address Records (User Commands)
- `ADR <recordID> [field=value...]` — Add a new address record
  - Fields: SN (surname), GN (given name), PEM (personal email), WEM (work email), PPH (personal phone), WPH (work phone), SA (street address), CITY, STP (state/province), CTY (country), PC (postal code)
  - Example: `ADR 001 SN=Smith GN=John PEM=john@email.com WPH=555-1234`
- `RER [recordID] [fieldnames...]` — Read record(s)
  - No arguments: returns all user records
  - With recordID only: returns specific record
  - With field list: returns specific fields from record
- `EDR <recordID> <field=value...>` — Edit an existing record
- `DER <recordID>` — Delete a record

### Import/Export (User Commands)
- `IMD <Input_File>` — Import records from CSV file (semicolon-delimited)
- `EXD <Output_File>` — Export records to CSV file (semicolon-delimited)

### CSV Format (Semicolon-Delimited)
```
recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC
001;Smith;John;john@personal.com;john@work.com;555-1234;555-5678;123 Main St;Springfield;IL;USA;62701
```

## Testing

### Run Tests

```bash
# Run all tests with pytest
python -m pytest tests/ -v

# Run tests with coverage report
python -m pytest tests/ --cov=. --cov-report=html
```

All 103 tests verify security functionality, CRUD operations, access control, import/export, and audit logging.

## Code Quality

### Run Pylint Analysis

```bash
# Run pylint on all source files and save report
.venv\Scripts\python.exe -m pylint audit.py auth.py cli.py import_export.py main.py record_manager.py reference_monitor.py security.py session.py storage.py user_manager.py --rcfile=.pylintrc --output-format=text --reports=yes > pylint_report.txt

# Or use the bash script (Linux/Mac with bash or WSL)
bash run_pylint.sh
```

Configure settings in `.pylintrc`. Current score: **9.56/10**

## Testing

### Install Test Dependencies
```bash
pip install -r requirements.txt
```

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
pytest tests/test_security.py -v
pytest tests/test_auth.py -v
```

### Run Tests with Coverage Report
```bash
pip install pytest-cov
pytest tests/ --cov=. --cov-report=html
```

## Test Suite Structure

The test suite is organized in `tests/`:

- **conftest.py** — Shared pytest fixtures (session objects, temporary data directories, seeded data)
- **test_security.py** — Password hashing, validation, field validation, path sanitization
- **test_auth.py** — Login, logout, password change with lockout testing
- **test_reference_monitor.py** — Access control enforcement for all user roles
- **test_record_manager.py** — Record CRUD operations with ownership validation
- **test_import_export.py** — CSV import/export with validation and file limits
- **test_audit.py** — Event logging and audit log display
- **test_integration.py** — End-to-end workflows (10 integration tests)

**Total: 60+ test cases covering all core functionality.**

## Fuzzing System

Automated fuzzing harness for comprehensive security testing of the ABA CLI.

### Quick Start

```bash
# Run the full fuzzing pipeline (generates 1000 test cases)
python -u fuzzer/fuzz_generator.py | python -u main.py | python -u fuzzer/fuzz_checker.py > fuzzer/fuzz_results.txt

# View results summary
tail -n 50 fuzzer/fuzz_results.txt
```

### Components

The fuzzer consists of three scripts connected by pipes:

- **fuzz_generator.py** — Generates 1000 test cases covering valid, boundary, malformed, and attack scenarios
- **fuzz_checker.py** — Validates ABA responses against expected patterns using regex
- **fuzz_config.py** — Shared configuration with field limits, credentials, and regex patterns

### Test Coverage

The fuzzer generates 1000 test cases with the following minimum coverage:

- **50 unauthenticated command attempts** — Verify access is denied without login
- **30 lockout sequences** — Test account lockout after 5 wrong password attempts
- **50 path traversal attacks** — Test for directory traversal vulnerabilities
- **50 oversized field attempts** — Test field length validation
- **30 cross-user access attempts** — Verify users can't access each other's records
- **100 random garbage commands** — Test error handling for invalid input
- **200+ valid session flows** — Test realistic login/command/logout sequences
- **400+ boundary and malformed tests** — Test edge cases and invalid formats

### Test Categories

- **Valid (30%)** — Realistic, well-formed inputs with expected success
- **Boundary (30%)** — Field limits, empty fields, oversized inputs
- **Malformed (25%)** — Invalid format, garbage data, missing fields
- **Attack (15%)** — Path traversal, SQL injection, shell injection, fuzzing payloads

### Output

The fuzzer produces a detailed report: `fuzzer/fuzz_results.txt`

```
[PASS] Case 0001 | valid | login alice Alice@1234
[FAIL] Case 0025 | attack | addrec ../../../../etc/passwd ...
[CRASH] Case 0073 | malformed | <random garbage>
...
============================================================
FUZZ RESULTS SUMMARY
============================================================
Total Cases:    1000
Passed:         980
Failed:         15
Crashed:        5
Pass Rate:      98.0%
============================================================
```

### Attack Payloads Tested

- Path traversal: `../../../etc/passwd`, `/etc/shadow`
- Shell injection: `;`, `|`, `&`, `$()`, `` ` ``, `>`
- SQL injection: `'; DROP TABLE;`, `--`
- Null bytes: `\x00`
- Unicode and ANSI escape sequences
- Very long strings (1000+ characters)
- Malformed CSV and oversized files

### Technical Details

- **Reproducibility**: All tests use a seeded RNG (seed stored in expected_results.json)
- **Buffering**: Uses `python -u` flag and explicit `sys.stdout.flush()` to prevent pipe deadlocks
- **Session state**: Tracks simulated login state across test sequences
- **Crash detection**: Identifies Python tracebacks, exceptions, segfaults
- **Temporary files**: Automatic cleanup of generated import files

## Features

- **COMP 365 Specification Compliant** — Meets formal address book application requirements
- **Secure password hashing** — bcrypt with salt for password protection
- **Role-based access control** — Admin and User roles with granular permissions
- **Audit logging** — Complete audit trail with timestamps and operation types
- **CSV import/export** — Semicolon-delimited CSV format per specification
- **First-time login password creation** — Users create passwords on first login
- **Path sanitization** — Prevents directory traversal attacks
- **Input validation** — Field length (max 64 chars) and format validation
- **Session management** — Secure session state tracking

## Data Storage

Persistent data is stored locally in the `data/` directory:
- `users.json` — User accounts with bcrypt-hashed passwords
- `records.json` — Address book records with 11 formal fields
- `audit.log` — Audit trail with timestamps and operation codes

**Note:** The `data/` directory is not tracked by Git for privacy.

## Security Features

- Passwords never stored or logged in plaintext
- Bcrypt hashing with random salts
- Role-based access control (RBAC) enforced by reference monitor
- Record ownership validation — users can only access their own records
- Password requirements per spec: 1-24 alphanumeric characters only (letters a-z, A-Z, 0-9)
- Path sanitization blocks directory traversal attacks
- Field length and format validation (max 64 characters per field)
- Complete audit trail of all operations
- File permissions set to 0o600 (user read/write only)
- Directory permissions set to 0o700 (user read/write/execute only)

## Project Structure

```
aba/
├── main.py                  # Application entry point and REPL loop
├── cli.py                   # Command parsing (LIN, LOU, etc.) and dispatch
├── session.py               # Session state management (username, role, auth status)
├── auth.py                  # Authentication logic (login, logout, password change)
├── security.py              # Password hashing (bcrypt), validation, and field validation
├── storage.py               # Persistent file I/O (JSON users/records, audit.log)
├── reference_monitor.py     # Access control enforcement (single source of authorization)
├── audit.py                 # Event logging with timestamps
├── user_manager.py          # User CRUD operations (add, delete, list)
├── record_manager.py        # Address record CRUD with 11 formal fields (SN, GN, PEM, etc.)
├── import_export.py         # CSV import/export (semicolon-delimited per spec)
├── requirements.txt         # Python dependencies (bcrypt)
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