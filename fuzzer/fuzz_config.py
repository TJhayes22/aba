"""
Fuzzing configuration constants for ABA Address Book Appliance.
Shared between fuzz_generator.py and fuzz_checker.py.
"""

# Number of test cases to generate
NUM_CASES = 1000

# Field length limits (matching ABA spec)
MAX_NAME_LEN = 100
MAX_PHONE_LEN = 20
MAX_EMAIL_LEN = 100
MAX_ADDRESS_LEN = 200
MAX_USERNAME_LEN = 32
MAX_PASSWORD_LEN = 128

# Approved export directories (matching ABA spec)
APPROVED_EXPORT_DIRS = ["/tmp/aba_exports", "./exports"]

# Test case weight distribution (must sum to 1.0)
WEIGHT_VALID = 0.30
WEIGHT_BOUNDARY = 0.30
WEIGHT_MALFORMED = 0.25
WEIGHT_ATTACK = 0.15

# Known ABA credentials for valid test cases
VALID_USER = "alice"
VALID_PASSWORD = "Alice@1234"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "Admin@1234"

# Output pattern strings (used by checker for regex matching)
# These match actual ABA responses
PATTERN_SUCCESS = r"(?i)(record|added|updated|deleted|logged in|success|completed|user added|exported|imported|displayed)"
PATTERN_DENIED = r"(?i)(denied|not logged in|access denied|no active login|unauthorized|invalid credentials|not admin|already)"
PATTERN_INVALID = r"(?i)(invalid|error|unknown|unrecognized|missing|too long|weak|incorrect|unsafe|locked|bad|failed|failure|no active|already)"
PATTERN_HELP = r"(?i)(usage|commands|help|address book|application|aba)"
PATTERN_ANY = r"[\s\S]+"  # any non-empty output
PATTERN_LOCKED = r"(?i)(locked|account.*locked|too many)"
