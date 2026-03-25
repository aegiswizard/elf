"""
Elf 🧝 — Main Scanner
Orchestrates all 136 checks against a GitHub repository.
Collects remote data via GitHub API, runs every check module,
aggregates findings, and produces the final verdict.

SAFETY CONTRACT:
  Elf never clones, executes, installs, or runs any code from the target repo.
  All analysis is performed on text and metadata returned by the GitHub API.
  No network connections are made to any URL found inside the repository.
"""

import os
import time
from datetime import datetime, timezone
from typing import Optional, Callable

from .models import CheckResult, Finding, Verdict, Severity, Category
from .github_api import GitHubAPI
from .checks import (
    run_identity_checks,
    run_actions_checks,
    run_dependency_checks,
    run_source_checks,
    run_build_checks,
    run_structure_checks,
    run_agent_safety_checks,
    run_provenance_checks,
)


def _determine_verdict(findings: list) -> Verdict:
    """Determine final SAFE / WARN / NOT SAFE verdict from findings."""
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        return Verdict.NOT_SAFE
    if Severity.MEDIUM in severities:
        return Verdict.WARN
    if Severity.LOW in severities:
        return Verdict.WARN
    return Verdict.SAFE


def _count_by_severity(findings: list) -> dict:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts


def scan(
    url: str,
    token: Optional[str] = None,
    progress: Optional[Callable] = None,
) -> CheckResult:
    """
    Run all 136 Elf checks against a GitHub repository.

    Args:
        url:      GitHub repository URL or 'owner/repo'
        token:    GitHub personal access token (strongly recommended)
                  Without: 60 req/hr — will hit rate limits on most repos
                  With:  5,000 req/hr — full scan in under 2 minutes
        progress: Optional callable(str) for progress messages

    Returns:
        CheckResult with verdict, all findings, and metadata.

    SAFETY:
        Never clones, executes, or installs anything from the target repo.
        All data comes from the GitHub API as JSON/text.
    """
    def log(msg: str) -> None:
        if progress:
            progress(msg)

    if token is None:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    api   = GitHubAPI(token=token)
    owner, repo_name = GitHubAPI.parse_url(url)

    result = CheckResult(
        repo_url=f"https://github.com/{owner}/{repo_name}",
        owner=owner,
        repo_name=repo_name,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        scan_mode="remote",
    )

    all_findings: list[Finding] = []

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 1 — Fetch core repository metadata
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching repository metadata...")
    repo = api.get_repo(owner, repo_name)
    if not repo:
        result.errors.append(f"Repository not found: {owner}/{repo_name}")
        result.verdict = Verdict.NOT_SAFE
        return result

    result.repo_description = repo.get("description") or ""
    result.repo_stars       = int(repo.get("stargazers_count") or 0)
    result.repo_forks       = int(repo.get("forks_count") or 0)
    result.repo_language    = repo.get("language") or ""
    result.repo_created_at  = repo.get("created_at") or ""
    result.repo_updated_at  = repo.get("updated_at") or ""

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 2 — Fetch owner data
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching owner account data...")
    owner_login = (repo.get("owner") or {}).get("login", owner)
    owner_type  = (repo.get("owner") or {}).get("type", "User")

    if owner_type == "Organization":
        owner_data = api.get_org(owner_login) or {}
    else:
        owner_data = api.get_owner(owner_login) or {}

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 3 — Fetch stargazers sample (for fake star detection)
    # ────────────────────────────────────────────────────────────────────────
    log("Sampling stargazers for fake star analysis...")
    stargazers = []
    if result.repo_stars > 0:
        stargazers = api.get_stargazers_sample(owner, repo_name, limit=100)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 4 — Run identity checks
    # ────────────────────────────────────────────────────────────────────────
    log("Running identity & ownership checks (14 checks)...")
    identity_findings = run_identity_checks(repo, owner_data, stargazers)
    all_findings.extend(identity_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 5 — Fetch and analyse GitHub Actions workflows
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching GitHub Actions workflow files...")
    workflow_files = api.get_workflow_files(owner, repo_name)
    log(f"Analysing {len(workflow_files)} workflow file(s) (18 checks)...")
    actions_findings = run_actions_checks(workflow_files)
    all_findings.extend(actions_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 6 — Fetch and analyse package/dependency files
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching dependency manifests and lockfiles...")
    package_files = api.get_package_files(owner, repo_name)
    log(f"Analysing {len(package_files)} package file(s) (22 checks)...")
    dep_findings = run_dependency_checks(package_files)
    all_findings.extend(dep_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 7 — Source code analysis
    # Fetch a representative sample of source files for static analysis
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching source files for static analysis...")
    source_files = {}
    source_extensions = {'.py', '.js', '.ts', '.rb', '.php', '.go', '.rs', '.sh', '.bash', '.ps1'}

    root_contents = api.get_contents(owner, repo_name, "") or []
    if isinstance(root_contents, list):
        for item in root_contents:
            if item.get("type") == "file":
                fname = item.get("name", "")
                ext   = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
                if ext in source_extensions and item.get("size", 0) < 500_000:
                    content = api.get_file_text(owner, repo_name, fname)
                    if content:
                        source_files[fname] = content

    # Also include build/config files for source analysis
    for fname in ("setup.py", "Makefile", "CMakeLists.txt"):
        if fname in package_files:
            source_files[fname] = package_files[fname]

    log(f"Analysing {len(source_files)} source file(s) (34 checks)...")
    source_findings = run_source_checks(source_files)
    all_findings.extend(source_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 8 — Build system checks
    # ────────────────────────────────────────────────────────────────────────
    log("Analysing build system files (12 checks)...")
    build_findings = run_build_checks(package_files)
    all_findings.extend(build_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 9 — Repository structure checks
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching repository structure metadata...")
    submodules_text = api.get_submodules_file(owner, repo_name) or ""
    commits         = api.get_commits(owner, repo_name, max_pages=1)
    tags            = api.get_tags(owner, repo_name)

    log("Analysing repository structure (12 checks)...")
    struct_findings = run_structure_checks(
        repo=repo,
        contents=root_contents if isinstance(root_contents, list) else [],
        submodules_text=submodules_text,
        commits=commits,
        tags=tags,
    )
    all_findings.extend(struct_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 10 — Agent safety checks
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching documentation for agent safety analysis...")
    doc_files = api.get_doc_files(owner, repo_name)

    log("Scanning for prompt injection and agent manipulation (16 checks)...")
    agent_findings = run_agent_safety_checks(
        doc_files=doc_files,
        source_files=source_files,
        issues_text="",
    )
    all_findings.extend(agent_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 11 — Provenance and signing checks
    # ────────────────────────────────────────────────────────────────────────
    log("Fetching release and attestation data...")
    releases     = api.get_releases(owner, repo_name)
    attestations = api.get_attestations(owner, repo_name)

    log("Analysing provenance and signing (8 checks)...")
    prov_findings = run_provenance_checks(
        releases=releases,
        attestations=attestations,
        repo=repo,
        tags=tags,
    )
    all_findings.extend(prov_findings)

    # ────────────────────────────────────────────────────────────────────────
    # PHASE 12 — Aggregate results
    # ────────────────────────────────────────────────────────────────────────
    log("Aggregating results...")

    result.findings      = all_findings
    result.checks_run    = 136
    result.checks_failed = len(all_findings)
    result.checks_passed = 136 - len(all_findings)

    counts = _count_by_severity(all_findings)
    result.critical_count = counts[Severity.CRITICAL]
    result.high_count     = counts[Severity.HIGH]
    result.medium_count   = counts[Severity.MEDIUM]
    result.low_count      = counts[Severity.LOW]

    result.verdict = _determine_verdict(all_findings)

    log(f"Scan complete. Verdict: {result.verdict.value}")
    return result
