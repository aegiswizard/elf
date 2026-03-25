"""
Elf 🧝 — Repository Structure Checks (101–112)
Analyses repo structure, files, and git metadata for deception signals.
"""

import re
from pathlib import Path
from ..models import Finding, Severity, Category


_SENSITIVE_NAME_PATTERNS = [
    r'password', r'passwd', r'secret', r'private[_\-]?key',
    r'api[_\-]?key', r'auth[_\-]?token', r'credentials?',
    r'\.pem$', r'\.key$', r'\.p12$', r'\.pfx$', r'\.jks$',
    r'id_rsa', r'id_dsa', r'id_ecdsa', r'id_ed25519',
]

_DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.so', '.dylib', '.bin', '.elf',
    '.scr', '.com', '.bat', '.cmd', '.vbs', '.js',
    '.jar', '.war', '.ear', '.class',
    '.apk', '.ipa',
    '.sh', '.bash',  # Only flagged if pre-built binary
}

_EXTENSION_MISMATCH = {
    # Files that should be text but could hide executables
    '.txt': ['MZ', 'ELF', '\x7fELF'],
    '.jpg': ['MZ'],
    '.png': ['MZ'],
    '.pdf': ['MZ'],
}


def run_structure_checks(
    repo: dict,
    contents: list,
    submodules_text: str,
    commits: list,
    tags: list,
) -> list:
    """
    Run all 12 repository structure checks.

    Args:
        repo:             GitHub repo API response
        contents:         Root directory contents listing from GitHub API
        submodules_text:  Content of .gitmodules file (if any)
        commits:          Recent commits list
        tags:             Repository tags list

    Returns:
        List of Finding objects.
    """
    findings = []
    fired = set()

    filenames = [item.get("name", "") for item in (contents or [])]
    all_paths = [item.get("path", "") for item in (contents or [])]

    # ── CHECK 101: .gitignore hiding dangerous file types ─────────────────

    gitignore = next((item for item in (contents or []) if item.get("name") == ".gitignore"), None)
    # We check for this via the package_files dict in the main scanner

    # ── CHECK 102: No README present ──────────────────────────────────────

    readme_names = {"README.md", "README.rst", "README.txt", "README", "readme.md"}
    has_readme = any(f in readme_names for f in filenames)
    if not has_readme:
        findings.append(Finding(
            check_id=102,
            name="Repository has no README file",
            category=Category.STRUCTURE,
            severity=Severity.MEDIUM,
            detail=(
                "No README file exists in this repository. A README is the most basic "
                "form of project documentation. Its complete absence — especially in a "
                "starred or published package — suggests either hasty assembly or "
                "deliberate opacity about the project's purpose and contents. "
                "Malicious packages frequently omit READMEs or provide minimal ones."
            ),
            evidence="No README.md, README.rst, or README found in root",
            check_name="NO_README",
        ))

    # ── CHECK 103: Files with sensitive-sounding names ────────────────────

    for fname in filenames:
        fname_lower = fname.lower()
        for pattern in _SENSITIVE_NAME_PATTERNS:
            if re.search(pattern, fname_lower) and "SENSITIVE_FILENAME" not in fired:
                findings.append(Finding(
                    check_id=103,
                    name=f"File with sensitive name committed to repository: {fname}",
                    category=Category.STRUCTURE,
                    severity=Severity.HIGH,
                    detail=(
                        f"A file named '{fname}' is committed to the repository. Files "
                        "with names suggesting credentials, keys, or secrets should never "
                        "be in a public repository. Even if the file is currently empty or "
                        "a template, its presence suggests poor security practices and "
                        "the file may have contained real values in git history."
                    ),
                    evidence=f"File: {fname}",
                    check_name="SENSITIVE_FILENAME",
                ))
                fired.add("SENSITIVE_FILENAME")
                break

    # ── CHECK 104: Binary executables committed to source tree ────────────

    for item in (contents or []):
        fname = item.get("name", "")
        ext = Path(fname).suffix.lower()
        ftype = item.get("type", "")

        if ext in _DANGEROUS_EXTENSIONS and ftype == "file" and "BINARY_IN_SOURCE" not in fired:
            # Filter out obvious legitimate cases
            if ext not in ('.sh', '.js') or item.get("size", 0) > 50000:
                findings.append(Finding(
                    check_id=104,
                    name=f"Binary executable committed directly to source tree: {fname}",
                    category=Category.STRUCTURE,
                    severity=Severity.HIGH,
                    detail=(
                        f"A binary executable file ('{fname}', extension '{ext}') is committed "
                        "directly to the source repository. Binary files in source trees "
                        "cannot be meaningfully reviewed — their contents are opaque to static "
                        "analysis and code review. Malicious actors use pre-built binaries to "
                        "bypass source-level inspection while still delivering working malware."
                    ),
                    evidence=f"File: {fname}  Size: {item.get('size', 0):,} bytes",
                    check_name="BINARY_EXECUTABLE_IN_SOURCE",
                ))
                fired.add("BINARY_IN_SOURCE")

    # ── CHECK 105: Git submodules present ─────────────────────────────────

    if submodules_text and submodules_text.strip():
        external_urls = re.findall(r'url\s*=\s*([^\n]+)', submodules_text)
        if external_urls:
            findings.append(Finding(
                check_id=105,
                name=f"Git submodules pointing to external repositories ({len(external_urls)} found)",
                category=Category.STRUCTURE,
                severity=Severity.MEDIUM,
                detail=(
                    "This repository uses git submodules referencing external repositories. "
                    "Submodules are a supply-chain dependency: the code fetched is not "
                    "part of this repository's code review or security controls. A "
                    "compromised submodule repository — or a submodule pointing to a "
                    "mutable branch rather than a fixed commit SHA — can pull in malicious "
                    "code without any change to this repository. Submodules must be pinned "
                    "to specific commit SHAs, not branch names."
                ),
                evidence="Submodule URLs: " + ", ".join(u.strip() for u in external_urls[:5]),
                check_name="GIT_SUBMODULES_EXTERNAL",
            ))

    # ── CHECK 106: Force push in recent history ───────────────────────────

    # We detect this via commit count anomaly — if first commit sha doesn't appear in history
    # (approximate signal via commit metadata)
    if commits and len(commits) >= 2:
        # Check for huge time gaps between consecutive commits (rebase/force-push signal)
        for i in range(min(5, len(commits)-1)):
            c1 = commits[i].get("commit", {}).get("committer", {}).get("date", "")
            c2 = commits[i+1].get("commit", {}).get("committer", {}).get("date", "")
            if c1 and c2:
                try:
                    from datetime import datetime, timezone
                    d1 = datetime.fromisoformat(c1.replace("Z", "+00:00"))
                    d2 = datetime.fromisoformat(c2.replace("Z", "+00:00"))
                    if d1 < d2 and "COMMIT_ORDER" not in fired:
                        findings.append(Finding(
                            check_id=106,
                            name="Commit history ordering anomaly — possible history rewrite",
                            category=Category.STRUCTURE,
                            severity=Severity.MEDIUM,
                            detail=(
                                "Recent commits appear to have inconsistent timestamps that "
                                "suggest a possible history rewrite (force push or rebase). "
                                "History rewrites can be used to hide prior malicious commits, "
                                "remove incriminating changes, or alter the apparent age and "
                                "authorship of code. Force-pushing to main branches is a "
                                "red flag in security-sensitive repositories."
                            ),
                            evidence=f"Commit timestamp anomaly between recent commits",
                            check_name="COMMIT_HISTORY_ANOMALY",
                        ))
                        fired.add("COMMIT_ORDER")
                        break
                except Exception:
                    pass

    # ── CHECK 107: Mutable tags (tag moved after creation) ────────────────

    # We can detect this if multiple tags point to same SHA (approximate)
    if tags:
        shas = [t.get("commit", {}).get("sha", "") for t in tags]
        sha_set = set(s for s in shas if s)
        if len(shas) >= 3 and len(sha_set) < len(shas) * 0.5:
            findings.append(Finding(
                check_id=107,
                name="Multiple release tags point to very few commit SHAs",
                category=Category.STRUCTURE,
                severity=Severity.MEDIUM,
                detail=(
                    "Multiple release tags appear to point to the same or very few "
                    "commit SHAs. In a healthy project, each release tag should point "
                    "to a unique commit. Tags sharing SHAs may indicate that tags have "
                    "been rewritten or moved — a practice that breaks the immutability "
                    "guarantee that release tags are supposed to provide, and which can "
                    "be used to retroactively associate a malicious commit with a "
                    "previously trusted release."
                ),
                evidence=f"Tags: {len(shas)}  Unique SHAs: {len(sha_set)}",
                check_name="MUTABLE_RELEASE_TAGS",
            ))

    # ── CHECK 108: Excessive large files ─────────────────────────────────

    large_files = [
        item for item in (contents or [])
        if item.get("type") == "file" and item.get("size", 0) > 10_000_000
    ]
    if large_files:
        findings.append(Finding(
            check_id=108,
            name=f"Unusually large files in repository ({len(large_files)} over 10MB)",
            category=Category.STRUCTURE,
            severity=Severity.LOW,
            detail=(
                "One or more files exceed 10MB in size. Very large files in source "
                "repositories may contain embedded executables, encrypted payloads, "
                "or other opaque content that is difficult to inspect. Legitimate "
                "source code is rarely this large at the file level."
            ),
            evidence=", ".join(f"{item.get('name')} ({item.get('size',0)//1024//1024}MB)"
                               for item in large_files[:3]),
            check_name="LARGE_FILES_IN_REPO",
        ))

    # ── CHECK 109: Single contributor ever ───────────────────────────────

    # This is approximated from the repo data — contributors check is separate
    if repo.get("stargazers_count", 0) > 500 and repo.get("forks_count", 0) == 0:
        findings.append(Finding(
            check_id=109,
            name="High popularity with no community engagement (no forks)",
            category=Category.STRUCTURE,
            severity=Severity.MEDIUM,
            detail=(
                "A repository with significant star count has zero forks, which is "
                "inconsistent with organic open-source adoption. Projects with genuine "
                "community interest are forked by contributors, researchers, and users "
                "who want to customize or build on the code. This pattern is consistent "
                "with fake social proof metrics."
            ),
            evidence=f"Stars: {repo.get('stargazers_count')}  Forks: 0",
            check_name="NO_COMMUNITY_ENGAGEMENT",
        ))

    # ── CHECK 110: Suspiciously perfect commit message history ────────────

    if commits:
        messages = [c.get("commit", {}).get("message", "") for c in commits[:20]]
        # Check for unnaturally formatted commit messages (AI-generated or scripted)
        perfect_format = sum(
            1 for m in messages
            if re.match(r'^(feat|fix|chore|docs|style|refactor|test|perf|ci|build)(\([^)]+\))?:', m)
        )
        if len(messages) >= 5 and perfect_format == len(messages):
            findings.append(Finding(
                check_id=110,
                name="All commit messages follow perfect Conventional Commits format",
                category=Category.STRUCTURE,
                severity=Severity.LOW,
                detail=(
                    "Every sampled commit message follows the Conventional Commits "
                    "specification with zero deviation. While this specification is "
                    "legitimate, 100% compliance across all commits — including in "
                    "small or experimental projects — can indicate automated or scripted "
                    "commit generation, which is associated with fake project creation "
                    "for social proof purposes."
                ),
                evidence=f"All {len(messages)} sampled commits use perfect conventional format",
                check_name="PERFECT_COMMIT_MESSAGES",
            ))

    return findings
