#!/usr/bin/env python3
"""
Fuzz test case checker for ABA Address Book Appliance.

Reads expected_results.json and compares actual output from the ABA CLI
against expected patterns. Generates a detailed pass/fail report.

Architecture:
- Loads expected_results.json at startup
- Reads ABA stdout line by line
- Matches output against expected patterns
- Detects crashes
- Writes summary and detailed results to stdout
"""

import json
import sys
import io
import re
import os
from typing import List, Dict, Any, Optional

# Fix encoding for Windows (use UTF-8 instead of cp1252)
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
if sys.stdin.encoding != 'utf-8':
    sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')


class FuzzChecker:
    """Main checker class for validating fuzz test results."""

    CRASH_INDICATORS = [
        "Traceback",
        "Error:",
        "Exception",
        "Segmentation fault",
        "Killed",
    ]

    def __init__(self):
        self.expected_results: List[Dict[str, Any]] = []
        self.results: List[Dict[str, Any]] = []
        self.case_index = 0
        self.actual_outputs: List[str] = []

    def load_expected_results(self):
        """Load expected_results.json from the fuzzer directory."""
        fuzzer_dir = os.path.dirname(os.path.abspath(__file__))
        expected_file = os.path.join(fuzzer_dir, "expected_results.json")

        if not os.path.exists(expected_file):
            print(f"[ERROR] Expected results file not found: {expected_file}", file=sys.stderr)
            sys.exit(1)

        try:
            with open(expected_file, "r") as f:
                data = json.load(f)
                self.expected_results = data.get("cases", [])
                seed = data.get("seed", "unknown")
                print(f"[INFO] Loaded {len(self.expected_results)} expected cases (seed: {seed})", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse {expected_file}: {e}", file=sys.stderr)
            sys.exit(1)

    def is_crash(self, output: str) -> bool:
        """Check if output indicates a crash."""
        for indicator in self.CRASH_INDICATORS:
            if indicator in output:
                return True
        return False

    def check_case(self, output_line: str) -> None:
        """Process one line of ABA output against the next expected case."""
        if self.case_index >= len(self.expected_results):
            # Extra output beyond expected cases
            print(f"[EXTRA] Unexpected output (case index {self.case_index}): {output_line[:100]}", file=sys.stderr)
            return

        expected = self.expected_results[self.case_index]
        command = expected["command"]
        expected_pattern = expected["expected_pattern"]
        expected_pass = expected["expected_pass"]
        case_id = expected["case_id"]
        category = expected["category"]
        description = expected["description"]

        # Check for crash first
        is_crashed = self.is_crash(output_line)

        if is_crashed:
            result_status = "CRASH"
            passed = False
        else:
            # Try to match pattern
            try:
                pattern_matches = bool(re.search(expected_pattern, output_line))
            except re.error as e:
                pattern_matches = False
                print(f"[ERROR] Invalid regex pattern for case {case_id}: {e}", file=sys.stderr)

            # Determine pass/fail based on expected_pass
            if expected_pass:
                # We expect the pattern to match
                passed = pattern_matches
                result_status = "PASS" if passed else "FAIL"
            else:
                # We expect the pattern to NOT match
                passed = not pattern_matches
                result_status = "PASS" if passed else "FAIL"

        # Format and print result line
        result_line = f"[{result_status}] Case {case_id:04d} | {category:10s} | {command}"
        print(result_line)

        # Store result details
        self.results.append({
            "case_id": case_id,
            "category": category,
            "command": command,
            "expected_pattern": expected_pattern,
            "expected_pass": expected_pass,
            "description": description,
            "actual_output": output_line,
            "pattern_matches": pattern_matches if not is_crashed else None,
            "is_crash": is_crashed,
            "passed": passed,
        })

        self.actual_outputs.append(output_line)
        self.case_index += 1

    def read_and_check_output(self):
        """Read output from stdin and check each line."""
        skip_banner = True  # Skip initial startup banner
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    # EOF reached
                    break
                
                # Strip trailing newline
                line = line.rstrip("\n\r")

                # Skip empty lines
                if not line.strip():
                    continue

                # Skip initial startup banner
                if skip_banner and ("Address Book Application" in line or ("Type" in line and "HLP" in line)):
                    skip_banner = False
                    continue

                # Remove the "ABA> " prompt if it appears at the start
                if line.startswith("ABA> "):
                    line = line[5:].strip()
                
                # Skip empty after prompt removal
                if not line.strip():
                    continue

                self.check_case(line)

        except KeyboardInterrupt:
            print("\n[INFO] Fuzzer interrupted by user", file=sys.stderr)
        except Exception as e:
            print(f"[ERROR] Exception while reading output: {e}", file=sys.stderr)

    def write_summary(self):
        """Write test summary to stdout."""
        total_cases = len(self.results)
        passed_count = sum(1 for r in self.results if r["passed"])
        crash_count = sum(1 for r in self.results if r["is_crash"])
        failed_count = total_cases - passed_count - crash_count

        # Adjust failed count to exclude crashes
        failed_count = sum(1 for r in self.results if not r["passed"] and not r["is_crash"])

        pass_rate = (passed_count / total_cases * 100) if total_cases > 0 else 0

        print()
        print("=" * 62)
        print("FUZZ RESULTS SUMMARY")
        print("=" * 62)
        print(f"Total Cases:    {total_cases}")
        print(f"Passed:         {passed_count}")
        print(f"Failed:         {failed_count}")
        print(f"Crashed:        {crash_count}")
        print(f"Pass Rate:      {pass_rate:.1f}%")
        print()

        # Report failures
        failures = [r for r in self.results if not r["passed"] and not r["is_crash"]]
        if failures:
            print("FAILURES:")
            for failure in failures[:20]:  # Limit to first 20
                print(f"  Case {failure['case_id']:04d} | {failure['category']:10s} | {failure['command'][:50]}")
                print(f"    Expected pattern: {failure['expected_pattern'][:60]}")
                print(f"    Expected pass:    {failure['expected_pass']}")
                print(f"    Pattern matched:  {failure['pattern_matches']}")
                print(f"    Actual output:    {failure['actual_output'][:80]}")
                print()
            if len(failures) > 20:
                print(f"  ... and {len(failures) - 20} more failures")
            print()

        # Report crashes
        crashes = [r for r in self.results if r["is_crash"]]
        if crashes:
            print("CRASHES:")
            for crash in crashes[:10]:  # Limit to first 10
                print(f"  Case {crash['case_id']:04d} | {crash['category']:10s} | {crash['command'][:50]}")
                print(f"    Output: {crash['actual_output'][:100]}")
                print()
            if len(crashes) > 10:
                print(f"  ... and {len(crashes) - 10} more crashes")
            print()

        print("=" * 62)

    def run(self):
        """Main entry point for checker."""
        self.load_expected_results()
        self.read_and_check_output()
        self.write_summary()


def main():
    checker = FuzzChecker()
    checker.run()


if __name__ == "__main__":
    main()
