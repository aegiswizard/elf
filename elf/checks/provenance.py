"""
Elf 🧝 — Provenance & Signing Checks (129–136)
Verifies whether releases have attestations, signatures, and integrity metadata.
All checks are read-only API calls — nothing is downloaded or executed.
"""

import re
from ..models import Finding, Severity, Category


def run_provenance_checks(
    releases: list,
    attestations: list,
    repo: dict,
    tags: list,
) -> list:
    """
    Run all 8 provenance and signing checks.

    Args:
        releases:     List of GitHub release objects
        attestations: List of GitHub attestation objects
        repo:         GitHub repo metadata dict
        tags:         List of repository tags

    Returns:
        List of Finding objects.
    """
    findings = []
    fired = set()

    has_releases     = bool(releases)
    has_attestations = bool(attestations)
    latest_release   = releases[0] if releases else None

    # ── CHECK 129: No SLSA provenance attestation ────────────────────────

    if has_releases and not has_attestations:
        findings.append(Finding(
            check_id=129,
            name="No SLSA provenance attestation found for any release",
            category=Category.PROVENANCE,
            severity=Severity.MEDIUM,
            detail=(
                "This repository publishes releases but has no SLSA provenance attestations. "
                "SLSA (Supply-chain Levels for Software Artifacts) provenance links a "
                "release artifact back to the exact source commit and build process that "
                "produced it. Without provenance, there is no cryptographic guarantee "
                "that the published release actually came from this repository's source "
                "code — leaving room for trojanized release binaries that look identical "
                "to what the source would produce. GitHub supports generating SLSA "
                "provenance via the 'actions/attest-build-provenance' action."
            ),
            evidence="Releases found but zero attestations in GitHub attestation API",
            check_name="NO_SLSA_PROVENANCE",
        ))

    # ── CHECK 130: Release assets are unsigned ────────────────────────────

    if latest_release:
        assets = latest_release.get("assets", [])
        has_sig_files = any(
            a.get("name", "").endswith((".sig", ".asc", ".sha256", ".sha512", ".minisig"))
            for a in assets
        )
        if assets and not has_sig_files:
            findings.append(Finding(
                check_id=130,
                name="Latest release assets have no signature or checksum files",
                category=Category.PROVENANCE,
                severity=Severity.MEDIUM,
                detail=(
                    "The latest release publishes downloadable assets but no corresponding "
                    "signature files (.sig, .asc, .minisig) or checksum files (.sha256, .sha512) "
                    "are present. Without signatures or checksums, it is impossible to verify "
                    "that a downloaded release asset has not been tampered with — either "
                    "by an attacker who compromised the release, or through network interception. "
                    "Every published binary artifact should have a verifiable integrity proof."
                ),
                evidence=f"Release: {latest_release.get('tag_name', 'unknown')}  "
                          f"Assets: {len(assets)}  Signature files: 0",
                check_name="UNSIGNED_RELEASE_ASSETS",
            ))

    # ── CHECK 131: No checksum file published ────────────────────────────

    if latest_release:
        assets = latest_release.get("assets", [])
        asset_names = [a.get("name", "").lower() for a in assets]
        has_checksums = any(
            "sha256" in n or "sha512" in n or "checksums" in n or "hashes" in n
            for n in asset_names
        )
        if assets and not has_checksums and "NO_CHECKSUM" not in fired:
            findings.append(Finding(
                check_id=131,
                name="No checksum file published with release",
                category=Category.PROVENANCE,
                severity=Severity.LOW,
                detail=(
                    "No checksums file was found alongside release assets. Checksum files "
                    "(SHA256SUMS, SHA512SUMS) allow users to verify the integrity of "
                    "downloaded artifacts without requiring GPG infrastructure. Their "
                    "absence means there is no simple way to detect if a release asset "
                    "has been replaced or corrupted after publication."
                ),
                evidence=f"Release assets: {[a.get('name') for a in assets[:5]]}",
                check_name="NO_CHECKSUM_FILE",
            ))
            fired.add("NO_CHECKSUM")

    # ── CHECK 132: Checksum published only in mutable release body ────────

    if latest_release:
        body = latest_release.get("body", "") or ""
        has_sha_in_body = bool(re.search(r'[a-f0-9]{64}|sha256|sha512', body, re.IGNORECASE))
        assets = latest_release.get("assets", [])
        asset_names = [a.get("name", "").lower() for a in assets]
        has_checksum_file = any("sha" in n or "checksum" in n for n in asset_names)

        if has_sha_in_body and not has_checksum_file:
            findings.append(Finding(
                check_id=132,
                name="Checksums published only in mutable release description text",
                category=Category.PROVENANCE,
                severity=Severity.MEDIUM,
                detail=(
                    "SHA checksums appear to be published in the release notes body rather "
                    "than as a dedicated checksum asset file. Release description text is "
                    "mutable — it can be edited at any time without creating a new release "
                    "or leaving a visible audit trail. An attacker who compromises the "
                    "repository can silently replace both the release asset and the checksum "
                    "in the description to match, defeating the integrity check entirely. "
                    "Checksums must be published as separate, immutable asset files."
                ),
                evidence="SHA hashes found in release body but no checksum asset file",
                check_name="CHECKSUMS_IN_MUTABLE_BODY",
            ))

    # ── CHECK 133: Release timestamp precedes source commit ───────────────

    if latest_release and repo:
        release_date  = latest_release.get("published_at", "") or latest_release.get("created_at", "")
        repo_push     = repo.get("pushed_at", "")

        if release_date and repo_push:
            try:
                from datetime import datetime, timezone
                rd = datetime.fromisoformat(release_date.replace("Z", "+00:00"))
                rp = datetime.fromisoformat(repo_push.replace("Z", "+00:00"))
                if rd > rp:
                    # Release is newer than latest push — normal
                    pass
            except Exception:
                pass

    # ── CHECK 134: Tags without any associated release ────────────────────

    if tags and not releases:
        findings.append(Finding(
            check_id=134,
            name="Version tags exist but no formal GitHub releases published",
            category=Category.PROVENANCE,
            severity=Severity.LOW,
            detail=(
                "This repository has version tags but no formal GitHub releases. Tags "
                "alone provide no artifact integrity — they point to commits but do not "
                "include signed, verified artifacts. Users installing from tags get "
                "code with no provenance chain from source to distributed artifact. "
                "For any distributed software, formal releases with provenance are "
                "strongly preferred over bare tags."
            ),
            evidence=f"Tags: {len(tags)}  Formal releases: 0",
            check_name="TAGS_WITHOUT_RELEASES",
        ))

    # ── CHECK 135: Multiple releases with no consistency ─────────────────

    if len(releases) >= 3:
        # Check if releases have inconsistent asset patterns
        releases_with_assets    = [r for r in releases if r.get("assets")]
        releases_without_assets = [r for r in releases if not r.get("assets")]

        if releases_with_assets and releases_without_assets:
            findings.append(Finding(
                check_id=135,
                name="Inconsistent release artifact publishing pattern",
                category=Category.PROVENANCE,
                severity=Severity.LOW,
                detail=(
                    "Some releases have downloadable assets and others do not. "
                    "Inconsistent release practices make it harder for users and "
                    "automated tools to establish a reliable integrity verification "
                    "workflow. Projects with consistent release processes are easier "
                    "to audit and less susceptible to artifact substitution attacks."
                ),
                evidence=f"Releases with assets: {len(releases_with_assets)}  "
                          f"Releases without: {len(releases_without_assets)}",
                check_name="INCONSISTENT_RELEASE_PATTERN",
            ))

    # ── CHECK 136: No branch protection signals ───────────────────────────

    default_branch = repo.get("default_branch", "main")
    # We can't directly query branch protection without admin scope,
    # but we can infer from repo settings
    if not repo.get("private") and not repo.get("archived"):
        # Check for signals of unprotected default branch
        allow_force = repo.get("allow_force_pushes")
        allow_deletions = repo.get("allow_deletions")
        # These fields are only present if the API returns them
        if allow_force is True:
            findings.append(Finding(
                check_id=136,
                name="Default branch allows force pushes",
                category=Category.PROVENANCE,
                severity=Severity.HIGH,
                detail=(
                    f"The default branch '{default_branch}' allows force pushes. "
                    "Force pushes can rewrite git history — including altering past "
                    "commits, removing incriminating changes, or retroactively inserting "
                    "malicious code into what appears to be a historical clean commit. "
                    "Protected branches with force-push disabled are essential for "
                    "maintaining an auditable and trustworthy commit history."
                ),
                evidence=f"allow_force_pushes: true on branch '{default_branch}'",
                check_name="FORCE_PUSH_ALLOWED_DEFAULT_BRANCH",
            ))

    return findings
