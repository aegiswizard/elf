"""
Elf 🧝 — Agent Interface
Single clean function for OpenClaw, Hermes, Claude, and any agent framework.

Usage:
    from elf.agent import check
    result = check("https://github.com/owner/repo")
    print(result["report"])
    print(result["verdict"])   # "SAFE" | "WARN" | "NOT SAFE"
    print(result["safe"])      # True / False
"""

import os
from typing import Optional, Callable

from .scanner import scan
from .report  import format_text_report, format_json_report
from .models  import Verdict


def check(
    url: str,
    token: Optional[str] = None,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Run all 136 Elf security checks against a GitHub repository.

    This is the primary entry point for agent frameworks.
    One URL in → one structured dict out.

    Args:
        url:               GitHub repository URL or 'owner/repo'
        token:             GitHub personal access token
                           Falls back to $GITHUB_TOKEN or $GH_TOKEN env vars
                           Without token: 60 req/hr (will rate-limit on most repos)
                           With token:  5,000 req/hr (full scan ~90 seconds)
        progress_callback: Optional callable(str) for live progress messages

    Returns dict with keys:

        report          (str)   Full human-readable text report
        report_json     (dict)  Structured JSON-serialisable result
        verdict         (str)   "SAFE" | "WARN" | "NOT SAFE"
        safe            (bool)  True only if verdict is SAFE
        findings_count  (int)   Total number of findings
        critical        (int)   Critical severity finding count
        high            (int)   High severity finding count
        medium          (int)   Medium severity finding count
        low             (int)   Low severity finding count
        findings        (list)  All Finding objects
        errors          (list)  Non-fatal scan errors

    Raises:
        ValueError   if the URL cannot be parsed or repo does not exist
        RuntimeError if GitHub API is unreachable
    """
    if token is None:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    result = scan(url=url, token=token, progress=progress_callback)

    return {
        "report":         format_text_report(result),
        "report_json":    format_json_report(result),
        "verdict":        result.verdict.value,
        "safe":           result.verdict == Verdict.SAFE,
        "findings_count": len(result.findings),
        "critical":       result.critical_count,
        "high":           result.high_count,
        "medium":         result.medium_count,
        "low":            result.low_count,
        "findings":       result.findings,
        "errors":         result.errors,
        "repo": {
            "url":         result.repo_url,
            "owner":       result.owner,
            "name":        result.repo_name,
            "stars":       result.repo_stars,
            "forks":       result.repo_forks,
            "language":    result.repo_language,
            "description": result.repo_description,
        },
    }
