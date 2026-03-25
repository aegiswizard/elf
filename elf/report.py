"""
Elf 🧝 — Report Formatter
Renders scan results as a detailed human-readable text report
or structured JSON. Every finding includes full technical detail.
"""

import json
from .models import CheckResult, Finding, Verdict, Severity, Category


DIVIDER  = "━" * 60
DIVIDER2 = "─" * 60

VERDICT_BANNERS = {
    Verdict.NOT_SAFE: "🔴  NOT SAFE",
    Verdict.WARN:     "⚠️   WARN — Review Required",
    Verdict.SAFE:     "✅  SAFE",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🚨 HIGH    ",
    Severity.MEDIUM:   "⚠️  MEDIUM  ",
    Severity.LOW:      "🔎 LOW     ",
}

CATEGORY_ORDER = [
    Category.IDENTITY,
    Category.ACTIONS,
    Category.DEPENDENCIES,
    Category.SOURCE,
    Category.BUILD,
    Category.STRUCTURE,
    Category.AGENT_SAFETY,
    Category.PROVENANCE,
]


def _wrap(text: str, width: int = 62, indent: str = "       ") -> str:
    """Word-wrap text at width, indenting continuation lines."""
    words  = text.split()
    lines  = []
    current = []
    for word in words:
        if len(" ".join(current + [word])) > width:
            if current:
                lines.append(indent + " ".join(current))
            current = [word]
        else:
            current.append(word)
    if current:
        lines.append(indent + " ".join(current))
    return "\n".join(lines)


def format_text_report(result: CheckResult) -> str:
    lines = [""]

    # ── Header ───────────────────────────────────────────────────────────
    lines += [
        f"🧝  {DIVIDER}",
        f"    ELF REPOSITORY SAFETY REPORT",
        f"🧝  {DIVIDER}",
        "",
        f"    Repository : {result.repo_url}",
        f"    Scanned    : {result.scanned_at[:19].replace('T', ' ')} UTC",
        f"    Checks run : {result.checks_run}",
        "",
    ]

    # ── Repo summary ─────────────────────────────────────────────────────
    if result.repo_description:
        lines.append(f"    Description: {result.repo_description[:80]}")
    lines += [
        f"    Language   : {result.repo_language or '—'}",
        f"    Stars      : {result.repo_stars:,}",
        f"    Forks      : {result.repo_forks:,}",
        f"    Created    : {result.repo_created_at[:10] if result.repo_created_at else '—'}",
        "",
    ]

    # ── Verdict banner ───────────────────────────────────────────────────
    verdict_line = VERDICT_BANNERS[result.verdict]
    lines += [
        f"    {DIVIDER}",
        f"    VERDICT:  {verdict_line}",
        f"    {DIVIDER}",
        "",
    ]

    if result.verdict == Verdict.SAFE and not result.findings:
        lines += [
            "    All 136 checks passed. No threats detected.",
            "    This repository passed Elf's full security analysis.",
            "",
            "    ⚠️  Remember: Elf performs static analysis only.",
            "    Dynamic runtime behavior is not checked.",
            "    Always apply human judgment before production use.",
            "",
        ]
        lines += _footer()
        return "\n".join(lines)

    # ── Finding summary ──────────────────────────────────────────────────
    lines += [
        "    FINDINGS SUMMARY",
        f"    {DIVIDER2}",
        f"    🔴 Critical : {result.critical_count}",
        f"    🚨 High     : {result.high_count}",
        f"    ⚠️  Medium   : {result.medium_count}",
        f"    🔎 Low      : {result.low_count}",
        f"    ── Total    : {len(result.findings)} finding(s)",
        "",
    ]

    # ── Plain English summary ────────────────────────────────────────────
    lines.append("    PLAIN ENGLISH SUMMARY")
    lines.append(f"    {DIVIDER2}")

    if result.verdict == Verdict.NOT_SAFE:
        lines.append("    This repository is NOT SAFE for agent use or installation.")
        lines.append("    Critical or high-severity threats were detected that could")
        lines.append("    compromise your system, credentials, or agent behavior.")
        if result.critical_count:
            lines.append(f"    {result.critical_count} CRITICAL finding(s) require immediate attention.")
    elif result.verdict == Verdict.WARN:
        lines.append("    This repository has signals that warrant human review")
        lines.append("    before any agent interacts with or installs from it.")

    # Category breakdown in plain English
    cats_found = {}
    for f in result.findings:
        if f.category not in cats_found:
            cats_found[f.category] = []
        cats_found[f.category].append(f)

    if Category.AGENT_SAFETY in cats_found:
        lines.append(f"    ⚠️  AGENT SAFETY: Prompt injection or manipulation content detected.")
    if Category.DEPENDENCIES in cats_found:
        lines.append(f"    ⚠️  DEPENDENCIES: Dangerous or suspicious package dependencies found.")
    if Category.ACTIONS in cats_found:
        lines.append(f"    ⚠️  CI/CD: GitHub Actions workflows have security vulnerabilities.")
    if Category.SOURCE in cats_found:
        lines.append(f"    ⚠️  SOURCE CODE: Dangerous patterns or secrets found in source.")
    if Category.IDENTITY in cats_found:
        lines.append(f"    ⚠️  IDENTITY: Repository or owner trust signals are weak.")
    if Category.BUILD in cats_found:
        lines.append(f"    ⚠️  BUILD: Build scripts execute dangerous code during install.")
    if Category.PROVENANCE in cats_found:
        lines.append(f"    ⚠️  PROVENANCE: Release integrity cannot be verified.")

    lines.append("")

    # ── Detailed findings by category ────────────────────────────────────
    lines.append("    DETAILED TECHNICAL FINDINGS")
    lines.append(f"    {DIVIDER2}")
    lines.append("    (Full technical detail for security review)")
    lines.append("")

    for category in CATEGORY_ORDER:
        cat_findings = [f for f in result.findings if f.category == category]
        if not cat_findings:
            continue

        lines.append(f"    ┌── {category.value} ({len(cat_findings)} finding(s))")
        lines.append("")

        for i, finding in enumerate(cat_findings):
            icon = SEVERITY_ICONS[finding.severity]
            lines.append(f"    │  [{icon}]  {finding.name}")
            lines.append(f"    │")

            # Technical detail — word wrapped
            detail_lines = _wrap(finding.detail, width=58, indent="    │     ").split("\n")
            for dl in detail_lines:
                lines.append(dl)
            lines.append(f"    │")

            if finding.evidence:
                lines.append(f"    │  Evidence:")
                ev_lines = finding.evidence.split("\n")
                for ev in ev_lines[:5]:
                    lines.append(f"    │     {ev[:70]}")
                lines.append(f"    │")

            lines.append(f"    │  Check ID : {finding.check_id:03d}  |  Code: {finding.check_name}")

            if i < len(cat_findings) - 1:
                lines.append(f"    │")
                lines.append(f"    │  {DIVIDER2[:-4]}")
                lines.append(f"    │")

        lines.append("")
        lines.append(f"    └{'─' * 58}")
        lines.append("")

    # ── Errors ───────────────────────────────────────────────────────────
    if result.errors:
        lines.append("    SCAN ERRORS (non-fatal)")
        for err in result.errors:
            lines.append(f"    ⚠  {err}")
        lines.append("")

    lines += _footer()
    return "\n".join(lines)


def _footer() -> list:
    return [
        f"    {DIVIDER}",
        "    SAFETY ARCHITECTURE",
        "    Elf performs static analysis only via the GitHub REST API.",
        "    No code was cloned, executed, installed, or fetched.",
        "    No URLs found inside the repository were visited.",
        "    No network connections were made to the repository's content.",
        "",
        "    WHAT ELF DOES NOT COVER",
        "    • Dynamic runtime behavior (requires sandbox execution)",
        "    • Binary artifact disassembly (requires reverse engineering tools)",
        "    • Hermetic rebuild comparison (requires build infrastructure)",
        "    • Zero-day exploits with no static signature",
        "    Always apply human expert judgment before production deployment.",
        "",
        "    🧝  Elf v1.0.0  ·  MIT License",
        "        https://github.com/aegiswizard/elf",
        "",
        f"    {DIVIDER}",
        "",
    ]


def format_json_report(result: CheckResult) -> str:
    data = {
        "elf_version":   "1.0.0",
        "repo_url":      result.repo_url,
        "scanned_at":    result.scanned_at,
        "scan_mode":     result.scan_mode,
        "verdict":       result.verdict.value,
        "safe":          result.verdict == Verdict.SAFE,
        "checks_run":    result.checks_run,
        "checks_failed": result.checks_failed,
        "summary": {
            "critical": result.critical_count,
            "high":     result.high_count,
            "medium":   result.medium_count,
            "low":      result.low_count,
            "total":    len(result.findings),
        },
        "repository": {
            "owner":       result.owner,
            "name":        result.repo_name,
            "description": result.repo_description,
            "stars":       result.repo_stars,
            "forks":       result.repo_forks,
            "language":    result.repo_language,
            "created_at":  result.repo_created_at,
        },
        "findings": [
            {
                "check_id":   f.check_id,
                "check_name": f.check_name,
                "name":       f.name,
                "category":   f.category.value,
                "severity":   f.severity.value,
                "detail":     f.detail,
                "evidence":   f.evidence,
            }
            for f in sorted(result.findings, key=lambda x: (
                ["CRITICAL","HIGH","MEDIUM","LOW"].index(x.severity.value), x.check_id
            ))
        ],
        "errors": result.errors,
    }
    return json.dumps(data, indent=2, default=str)
