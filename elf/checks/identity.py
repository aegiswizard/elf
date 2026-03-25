"""
Elf 🧝 — Identity & Ownership Checks (1–14)
Who owns this repo, how long has it existed, and can that identity be trusted?
"""

import re
from datetime import datetime, timezone, timedelta
from typing import Optional

from ..models import Finding, Severity, Category


def _parse_date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _days_old(date_str: Optional[str]) -> Optional[int]:
    d = _parse_date(date_str)
    if not d:
        return None
    return (datetime.now(timezone.utc) - d).days


def run_identity_checks(repo: dict, owner_data: dict, stargazers: list) -> list:
    """
    Run all 14 identity and ownership checks.

    Args:
        repo:        GitHub repo API response dict
        owner_data:  GitHub user/org API response dict for the owner
        stargazers:  Sample of stargazers with starred_at timestamps

    Returns:
        List of Finding objects for every triggered check.
    """
    findings = []

    created_at   = repo.get("created_at", "")
    pushed_at    = repo.get("pushed_at", "")
    repo_age     = _days_old(created_at)
    stars        = int(repo.get("stargazers_count") or 0)
    forks        = int(repo.get("forks_count") or 0)
    watchers     = int(repo.get("watchers_count") or 0)
    is_fork      = bool(repo.get("fork"))
    has_issues   = bool(repo.get("has_issues"))
    owner_login  = (repo.get("owner") or {}).get("login", "")
    owner_type   = (repo.get("owner") or {}).get("type", "")

    owner_created     = owner_data.get("created_at", "") if owner_data else ""
    owner_age         = _days_old(owner_created)
    owner_public_repos = int((owner_data or {}).get("public_repos") or 0)
    owner_followers   = int((owner_data or {}).get("followers") or 0)
    owner_bio         = (owner_data or {}).get("bio") or ""
    owner_company     = (owner_data or {}).get("company") or ""
    owner_blog        = (owner_data or {}).get("blog") or ""
    owner_email       = (owner_data or {}).get("email") or ""
    owner_location    = (owner_data or {}).get("location") or ""
    owner_name        = (owner_data or {}).get("name") or ""
    owner_website     = (owner_data or {}).get("blog") or ""

    # ── CHECK 1 ─────────────────────────────────────────────────────────────
    # Repository is less than 7 days old.
    # Brand-new repos with significant star counts or claims are extremely suspicious.
    if repo_age is not None and repo_age < 7:
        findings.append(Finding(
            check_id=1,
            name="Repository created less than 7 days ago",
            category=Category.IDENTITY,
            severity=Severity.HIGH,
            detail=(
                "This repository was created fewer than 7 days ago. Malicious packages "
                "are frequently published under fresh accounts to bypass reputation-based "
                "trust systems. A repo this new should not be used in production or by "
                "autonomous agents without thorough manual review."
            ),
            evidence=f"Created: {created_at[:10]} ({repo_age} days ago)",
            check_name="REPO_AGE_UNDER_7_DAYS",
        ))

    # ── CHECK 2 ─────────────────────────────────────────────────────────────
    # Repository is less than 30 days old.
    elif repo_age is not None and repo_age < 30:
        findings.append(Finding(
            check_id=2,
            name="Repository created less than 30 days ago",
            category=Category.IDENTITY,
            severity=Severity.MEDIUM,
            detail=(
                "This repository is under 30 days old. While not inherently malicious, "
                "very new repositories have no established trust history. Real-world "
                "supply-chain attacks frequently use newly created packages to avoid "
                "detection. Treat with heightened scrutiny."
            ),
            evidence=f"Created: {created_at[:10]} ({repo_age} days ago)",
            check_name="REPO_AGE_UNDER_30_DAYS",
        ))

    # ── CHECK 3 ─────────────────────────────────────────────────────────────
    # Owner account is less than 30 days old.
    if owner_age is not None and owner_age < 30:
        sev = Severity.CRITICAL if owner_age < 7 else Severity.HIGH
        findings.append(Finding(
            check_id=3 if owner_age >= 7 else 4,
            name=f"Owner account created {'less than 7' if owner_age < 7 else 'less than 30'} days ago",
            category=Category.IDENTITY,
            severity=sev,
            detail=(
                f"The account '{owner_login}' that owns this repository was created only "
                f"{owner_age} days ago. Freshly created accounts are a primary indicator "
                "of throwaway attacker infrastructure. Legitimate maintainers of production "
                "software typically have established GitHub histories."
            ),
            evidence=f"Owner created: {owner_created[:10]} ({owner_age} days ago)",
            check_name=f"OWNER_AGE_UNDER_{'7' if owner_age < 7 else '30'}_DAYS",
        ))

    # ── CHECK 5 ─────────────────────────────────────────────────────────────
    # Owner has zero other public repositories.
    if owner_public_repos == 0:
        findings.append(Finding(
            check_id=5,
            name="Owner has zero other public repositories",
            category=Category.IDENTITY,
            severity=Severity.HIGH,
            detail=(
                f"The owner account '{owner_login}' has no other public repositories. "
                "This is consistent with single-purpose attacker infrastructure created "
                "solely to distribute this package. Real developers accumulate a history "
                "of projects over time."
            ),
            evidence=f"Owner public repos: 0",
            check_name="OWNER_ZERO_REPOS",
        ))
    elif owner_public_repos <= 2:
        findings.append(Finding(
            check_id=5,
            name="Owner has very few public repositories",
            category=Category.IDENTITY,
            severity=Severity.MEDIUM,
            detail=(
                f"The owner '{owner_login}' has only {owner_public_repos} public "
                "repositories. Limited GitHub history reduces confidence in the account's "
                "legitimacy and prior trustworthiness."
            ),
            evidence=f"Owner public repos: {owner_public_repos}",
            check_name="OWNER_FEW_REPOS",
        ))

    # ── CHECK 6 ─────────────────────────────────────────────────────────────
    # Owner profile is completely empty.
    profile_fields = [owner_bio, owner_company, owner_blog, owner_email, owner_location, owner_name]
    empty_count = sum(1 for f in profile_fields if not f.strip())
    if empty_count == 6 and owner_type == "User":
        findings.append(Finding(
            check_id=6,
            name="Owner account has completely empty profile",
            category=Category.IDENTITY,
            severity=Severity.MEDIUM,
            detail=(
                "The repository owner has no name, bio, email, website, company, or location "
                "on their GitHub profile. While not conclusive, ghost profiles are consistent "
                "with attacker infrastructure accounts. Real developers and maintainers "
                "typically have at least partial profile information."
            ),
            evidence=f"All 6 profile fields are empty for @{owner_login}",
            check_name="OWNER_EMPTY_PROFILE",
        ))

    # ── CHECK 7 ─────────────────────────────────────────────────────────────
    # Stars present but zero forks — classic fake star signal.
    if stars >= 50 and forks == 0:
        findings.append(Finding(
            check_id=7,
            name="High star count with zero forks — fake star indicator",
            category=Category.IDENTITY,
            severity=Severity.HIGH,
            detail=(
                f"This repository has {stars:,} stars but zero forks. In organic growth, "
                "stars and forks are correlated — people who find a project useful tend to "
                "fork it for their own use. A high star count with zero forks is a strong "
                "signal that the stars were purchased from a star-farming service rather "
                "than representing genuine developer interest."
            ),
            evidence=f"Stars: {stars:,}  Forks: 0",
            check_name="FAKE_STAR_SIGNAL_NO_FORKS",
        ))
    elif stars >= 100 and forks < (stars * 0.005):
        findings.append(Finding(
            check_id=7,
            name="Star-to-fork ratio is abnormally low",
            category=Category.IDENTITY,
            severity=Severity.MEDIUM,
            detail=(
                f"Fork-to-star ratio is {forks/max(stars,1)*100:.2f}%, far below the "
                "typical 1-5% range for healthy open-source projects. This may indicate "
                "star inflation through purchased or automated star services."
            ),
            evidence=f"Stars: {stars:,}  Forks: {forks:,}  Ratio: {forks/max(stars,1)*100:.2f}%",
            check_name="LOW_FORK_TO_STAR_RATIO",
        ))

    # ── CHECK 8 ─────────────────────────────────────────────────────────────
    # Fake star detection — stargazers created same day they starred.
    if stargazers:
        same_day_count = 0
        for sg in stargazers:
            starred_at  = sg.get("starred_at", "")
            user        = sg.get("user", {}) or {}
            created_at_ = user.get("created_at", "")
            if starred_at and created_at_:
                sd = _parse_date(starred_at)
                cd = _parse_date(created_at_)
                if sd and cd and sd.date() == cd.date():
                    same_day_count += 1

        fake_rate = same_day_count / len(stargazers)
        if fake_rate >= 0.15:
            sev = Severity.CRITICAL if fake_rate >= 0.40 else Severity.HIGH
            findings.append(Finding(
                check_id=8,
                name=f"Fake star accounts detected — {fake_rate*100:.0f}% of sample",
                category=Category.IDENTITY,
                severity=sev,
                detail=(
                    f"Of {len(stargazers)} sampled stargazers, {same_day_count} "
                    f"({fake_rate*100:.1f}%) were accounts created on the exact same day "
                    "they starred this repository. This is the primary fingerprint of "
                    "purchased fake GitHub stars. Fake stars are used to manufacture "
                    "artificial credibility and are strongly associated with fraudulent "
                    "or malicious package distribution."
                ),
                evidence=f"Fake accounts: {same_day_count}/{len(stargazers)} sampled",
                check_name="FAKE_STAR_ACCOUNTS_DETECTED",
            ))

    # ── CHECK 9 ─────────────────────────────────────────────────────────────
    # Repository is a fork presented as original.
    if is_fork:
        parent = (repo.get("parent") or {})
        parent_full = parent.get("full_name", "unknown/unknown")
        findings.append(Finding(
            check_id=9,
            name="Repository is a fork of another project",
            category=Category.IDENTITY,
            severity=Severity.LOW,
            detail=(
                f"This repository is a fork of '{parent_full}'. While forks are normal "
                "in open-source development, attackers frequently fork popular projects "
                "and inject malicious code before publishing the fork as if it were the "
                "original. Always verify you are using the canonical upstream source."
            ),
            evidence=f"Forked from: {parent_full}",
            check_name="REPO_IS_FORK",
        ))

    # ── CHECK 10 ────────────────────────────────────────────────────────────
    # Owner has very low followers relative to their repo count.
    if owner_public_repos >= 5 and owner_followers == 0 and owner_type == "User":
        findings.append(Finding(
            check_id=10,
            name="Owner has repos but zero followers — credibility signal",
            category=Category.IDENTITY,
            severity=Severity.LOW,
            detail=(
                f"Owner '{owner_login}' has {owner_public_repos} public repositories but "
                "zero followers. Legitimate developers who maintain meaningful projects "
                "typically accumulate followers over time. Zero followers across a "
                "non-trivial number of repos is an unusual signal."
            ),
            evidence=f"Public repos: {owner_public_repos}  Followers: 0",
            check_name="OWNER_ZERO_FOLLOWERS",
        ))

    # ── CHECK 11 ────────────────────────────────────────────────────────────
    # No description on repository.
    description = repo.get("description") or ""
    if not description.strip():
        findings.append(Finding(
            check_id=11,
            name="Repository has no description",
            category=Category.IDENTITY,
            severity=Severity.LOW,
            detail=(
                "This repository has no description set. While minor on its own, "
                "the complete absence of a description — combined with other signals — "
                "can indicate a hastily assembled malicious package or a project with "
                "no intention of transparent documentation."
            ),
            evidence="Repository description field is empty",
            check_name="NO_REPO_DESCRIPTION",
        ))

    # ── CHECK 12 ────────────────────────────────────────────────────────────
    # No license declared.
    license_info = repo.get("license")
    if not license_info:
        findings.append(Finding(
            check_id=12,
            name="No license declared",
            category=Category.IDENTITY,
            severity=Severity.LOW,
            detail=(
                "No software license has been declared for this repository. Legitimate "
                "open-source projects almost universally declare a license. The absence "
                "of a license creates legal ambiguity and is also associated with "
                "hastily created attacker infrastructure."
            ),
            evidence="No LICENSE file or license field detected",
            check_name="NO_LICENSE",
        ))

    # ── CHECK 13 ────────────────────────────────────────────────────────────
    # Repository has no README.
    has_readme = bool(repo.get("default_branch"))  # Approximation; will refine in structure checks
    # We'll rely on structure check 101 for README — this check focuses on topics
    topics = repo.get("topics") or []
    if not topics and stars > 100:
        findings.append(Finding(
            check_id=13,
            name="Popular repository has no topics/tags set",
            category=Category.IDENTITY,
            severity=Severity.LOW,
            detail=(
                f"A repository with {stars:,} stars has no GitHub topic tags. "
                "Real projects that gain organic traction are typically tagged. "
                "The absence of topics on a high-star repo may indicate the stars "
                "are not organically earned."
            ),
            evidence=f"Stars: {stars:,}  Topics: none",
            check_name="HIGH_STARS_NO_TOPICS",
        ))

    # ── CHECK 14 ────────────────────────────────────────────────────────────
    # Repository was recently made public (private then public).
    # Approximate signal: many commits but very recent creation.
    if repo_age is not None and repo_age < 3 and stars > 10:
        findings.append(Finding(
            check_id=14,
            name="Very new repo with unusual star velocity",
            category=Category.IDENTITY,
            severity=Severity.HIGH,
            detail=(
                f"Repository is only {repo_age} day(s) old but already has {stars} stars. "
                "Organic GitHub stars accumulate gradually. Immediate high star counts "
                "in a brand-new repository are a near-certain indicator of purchased "
                "fake stars, which is a hallmark of fraudulent package distribution."
            ),
            evidence=f"Age: {repo_age} day(s)  Stars: {stars}",
            check_name="NEW_REPO_STAR_VELOCITY_ANOMALY",
        ))

    return findings
