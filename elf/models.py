"""
Elf 🧝 — Core Data Models
Shared finding and result structures used across all check modules.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # Definitive threat — block immediately
    HIGH     = "HIGH"       # Strong signal — very likely dangerous
    MEDIUM   = "MEDIUM"     # Significant concern — warrants review
    LOW      = "LOW"        # Weak signal — informational


class Category(str, Enum):
    IDENTITY      = "IDENTITY & OWNERSHIP"
    ACTIONS       = "GITHUB ACTIONS & CI/CD"
    DEPENDENCIES  = "DEPENDENCIES & PACKAGES"
    SOURCE        = "SOURCE CODE"
    BUILD         = "BUILD SYSTEM"
    STRUCTURE     = "REPOSITORY STRUCTURE"
    AGENT_SAFETY  = "AGENT SAFETY & PROMPT INJECTION"
    PROVENANCE    = "PROVENANCE & SIGNING"


class Verdict(str, Enum):
    SAFE         = "SAFE"
    WARN         = "WARN"
    NOT_SAFE     = "NOT SAFE"


@dataclass
class Finding:
    """A single security finding from any check."""
    check_id:    int
    name:        str
    category:    Category
    severity:    Severity
    detail:      str          # Technical explanation for pro coders
    evidence:    str = ""     # Specific evidence found (file, line, value)
    check_name:  str = ""     # Short machine-readable name

    def __post_init__(self):
        if not self.check_name:
            self.check_name = f"CHECK_{self.check_id:03d}"


@dataclass
class CheckResult:
    """Result of running all checks against a repository."""
    repo_url:      str
    owner:         str
    repo_name:     str
    scanned_at:    str
    scan_mode:     str           # "remote" or "full"

    verdict:       Verdict = Verdict.SAFE
    findings:      list = field(default_factory=list)
    checks_run:    int = 0
    checks_passed: int = 0
    checks_failed: int = 0

    # Summary counts by severity
    critical_count: int = 0
    high_count:     int = 0
    medium_count:   int = 0
    low_count:      int = 0

    # Metadata for report
    repo_description:  str = ""
    repo_stars:        int = 0
    repo_forks:        int = 0
    repo_language:     str = ""
    repo_created_at:   str = ""
    repo_updated_at:   str = ""
    repo_cloned_path:  Optional[str] = None

    errors: list = field(default_factory=list)  # Non-fatal scan errors
