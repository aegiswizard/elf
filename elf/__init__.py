"""
Elf 🧝 — GitHub Repository Safety Scanner
MIT License | github.com/aegiswizard/elf

136 security checks across 8 threat categories.
Safe | Warn | Not Safe. One URL. Any agent.

Quick start:
    from elf.agent import check
    result = check("https://github.com/owner/repo")
    print(result["report"])
"""

__version__ = "1.0.0"
__author__  = "Aegis Wizard"
__license__ = "MIT"
__url__     = "https://github.com/aegiswizard/elf"

from .scanner import scan
from .report  import format_text_report, format_json_report
from .agent   import check

__all__ = ["scan", "format_text_report", "format_json_report", "check"]
