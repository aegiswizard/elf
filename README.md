# 🧝 Elf

**136-check GitHub repository safety scanner for AI agents and humans.**  
**Safe. Warn. Not Safe. One URL. Any agent. Zero dependencies.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![Checks](https://img.shields.io/badge/security%20checks-136-red)](README.md)
[![GitHub](https://img.shields.io/badge/github-aegiswizard%2Felf-black)](https://github.com/aegiswizard/elf)

---

## Table of Contents

1. [What Elf Is](#1-what-elf-is)
2. [The Problem It Solves](#2-the-problem-it-solves)
3. [Safety Architecture](#3-safety-architecture)
4. [Quick Start](#4-quick-start)
5. [CLI Reference](#5-cli-reference)
6. [Python API](#6-python-api)
7. [Agent Skill — OpenClaw / Hermes / Claude](#7-agent-skill)
8. [All 136 Checks — Complete Documentation](#8-all-136-checks)
   - [8.1 Identity & Ownership](#81-identity--ownership-14-checks)
   - [8.2 GitHub Actions & CI/CD](#82-github-actions--cicd-18-checks)
   - [8.3 Dependencies & Packages](#83-dependencies--packages-22-checks)
   - [8.4 Source Code](#84-source-code-34-checks)
   - [8.5 Build System](#85-build-system-12-checks)
   - [8.6 Repository Structure](#86-repository-structure-12-checks)
   - [8.7 Agent Safety & Prompt Injection](#87-agent-safety--prompt-injection-16-checks)
   - [8.8 Provenance & Signing](#88-provenance--signing-8-checks)
9. [Verdict System](#9-verdict-system)
10. [Sample Output](#10-sample-output)
11. [What Elf Does Not Cover](#11-what-elf-does-not-cover)
12. [False Positive Guidance](#12-false-positive-guidance)
13. [Contributing](#13-contributing)
14. [License](#14-license)

---

## 1. What Elf Is

Elf is a static security scanner for GitHub repositories. You give it any GitHub URL. It runs 136 security checks across 8 threat categories and returns one of three verdicts:

```
✅ SAFE      — All 136 checks passed. No threats detected.
⚠️  WARN      — Medium or low findings. Human review recommended.
🔴 NOT SAFE  — Critical or high findings. Do not install or use.
```

Every finding comes with a full technical explanation in plain English, specific evidence from the repository, and a machine-readable check code.

Elf is designed to be the security gate that sits between any AI agent and any GitHub repository it is told to use.

---

## 2. The Problem It Solves

AI agents are increasingly told to "get this GitHub repo and use it." Every major agent framework — OpenClaw, Hermes, Claude, AutoGPT, LangChain, CrewAI — can fetch, install, and execute code from GitHub repositories on the user's behalf.

None of them check whether the repo is safe before doing so.

GitHub repositories can be hostile in seven simultaneous ways:

| Attack Surface | Example |
|---|---|
| **Identity fraud** | Fake org, compromised maintainer, repo-jacking |
| **Source deception** | Hidden Unicode, obfuscated code, embedded secrets |
| **Poisoned dependencies** | Typosquatting, lifecycle script abuse, lockfile poisoning |
| **Malicious build/install** | setup.py phones home, Makefile downloads malware |
| **CI/CD compromise** | Unpinned Actions, script injection, privilege escalation |
| **Artifact tampering** | Release binary differs from source, no signatures |
| **Agent manipulation** | Prompt injection in README, RAG poisoning, persona hijack |

No existing free tool covers all seven. Elf covers all seven — in one command, in under two minutes, with zero dependencies.

---

## 3. Safety Architecture

> **Elf is a static text analyser. It never clones the repository, never executes any code, never fetches URLs found inside the repository, and never makes network connections to the repository's content.**

This is not a limitation — it is the design.

A security scanner that fetches links to "check" them becomes the attack vector. A scanner that clones and runs code to "test" it executes the malware it is looking for. Elf cannot trigger the threats it detects. This makes it safe to run against any repository, no matter how dangerous.

```
Elf NEVER:                         Elf ALWAYS:
  ✗ Clones the repository            ✓ Calls GitHub REST API
  ✗ Executes any code                ✓ Reads JSON and text responses
  ✗ Installs any package             ✓ Applies pattern matching to text
  ✗ Fetches URLs from repo content   ✓ Returns a structured verdict
  ✗ Renders HTML or markdown         ✓ Explains every finding in detail
  ✗ Opens any file attachment        ✓ Stays within GitHub API rate limits
  ✗ Connects to any repo-internal URL ✓ Uses only Python standard library
```

All data Elf analyses comes from the GitHub REST API — repository metadata, file contents, workflow YAML, package manifests, release information, and attestations. This data is fetched as plain text and analysed as strings.

---

## 4. Quick Start

### Install

```bash
git clone https://github.com/aegiswizard/elf.git
cd elf
pip install -e .
```

**Zero runtime dependencies.** Elf uses only Python's standard library: `urllib`, `json`, `re`, `difflib`, `unicodedata`, `pathlib`, `dataclasses`, `enum`. Works on Raspberry Pi, Mac, Windows, Linux.

### Get a GitHub Token (strongly recommended)

Elf makes approximately 30–50 API calls per scan. Without a token, GitHub limits you to 60 requests per hour — which means most scans will hit rate limits.

With a free token: **5,000 requests per hour** — full 136-check scan completes in under 2 minutes.

1. Go to https://github.com/settings/tokens
2. Click **Generate new token (classic)**
3. **Select no scopes** — public repository access requires no permissions
4. Copy the token

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

### Run your first scan

```bash
elf check https://github.com/owner/repo
```

---

## 5. CLI Reference

```bash
elf check <url> [options]

Arguments:
  url                   GitHub repository URL or owner/repo shorthand

Options:
  --token, -t TOKEN     GitHub personal access token
                        (default: $GITHUB_TOKEN or $GH_TOKEN)
  --output, -o FORMAT   Output format: text (default) or json
  --quiet, -q           Suppress progress messages
```

### Examples

```bash
# Standard scan
elf check https://github.com/owner/repo

# Shorthand URL
elf check owner/repo

# Pass token inline
elf check https://github.com/owner/repo --token ghp_xxxx

# JSON output — pipe to jq or save to file
elf check https://github.com/owner/repo --output json
elf check https://github.com/owner/repo --output json > report.json
elf check https://github.com/owner/repo --output json | jq '.verdict'

# Suppress progress (clean output for scripting)
elf check https://github.com/owner/repo --quiet
```

### Exit Codes

| Code | Verdict | Meaning |
|------|---------|---------|
| `0`  | SAFE    | All checks passed |
| `1`  | ERROR   | Scan could not complete |
| `2`  | WARN    | Medium/low findings only |
| `3`  | NOT SAFE | Critical or high findings |

```bash
# Use in CI/CD scripts
elf check https://github.com/owner/repo
case $? in
  0) echo "SAFE — proceeding with install" ;;
  2) echo "WARN — review findings before proceeding" ;;
  3) echo "NOT SAFE — blocked" && exit 1 ;;
esac
```

---

## 6. Python API

### Agent interface (recommended)

```python
from elf.agent import check

result = check("https://github.com/owner/repo")

# Core verdict
print(result["verdict"])         # "SAFE" | "WARN" | "NOT SAFE"
print(result["safe"])            # True / False

# Counts by severity
print(result["critical"])        # int
print(result["high"])            # int
print(result["medium"])          # int
print(result["low"])             # int
print(result["findings_count"])  # int total

# Full reports
print(result["report"])          # Human-readable text
import json
data = json.loads(result["report_json"])

# Repository metadata
print(result["repo"]["url"])
print(result["repo"]["stars"])
print(result["repo"]["language"])

# All findings (list of Finding objects)
for finding in result["findings"]:
    print(finding.severity.value)  # CRITICAL | HIGH | MEDIUM | LOW
    print(finding.category.value)  # e.g. "AGENT SAFETY & PROMPT INJECTION"
    print(finding.name)            # Short name
    print(finding.detail)          # Full technical explanation
    print(finding.evidence)        # Specific evidence found
    print(finding.check_id)        # 1-136
    print(finding.check_name)      # Machine-readable code
```

### With progress callback

```python
from elf.agent import check

def on_progress(message: str) -> None:
    print(f"[elf] {message}")

result = check(
    "https://github.com/owner/repo",
    token="ghp_xxxx",
    progress_callback=on_progress,
)
```

### Low-level API

```python
from elf.scanner import scan
from elf.report  import format_text_report, format_json_report

result = scan("https://github.com/owner/repo", token="ghp_xxxx")
print(format_text_report(result))
print(format_json_report(result))
```

### JSON output structure

```json
{
  "elf_version": "1.0.0",
  "repo_url": "https://github.com/owner/repo",
  "scanned_at": "2026-03-24T12:00:00+00:00",
  "verdict": "NOT SAFE",
  "safe": false,
  "checks_run": 136,
  "checks_failed": 4,
  "summary": {
    "critical": 2,
    "high": 1,
    "medium": 1,
    "low": 0,
    "total": 4
  },
  "repository": {
    "owner": "owner",
    "name": "repo",
    "stars": 1240,
    "forks": 0,
    "language": "Python"
  },
  "findings": [
    {
      "check_id": 15,
      "check_name": "UNPINNED_THIRD_PARTY_ACTIONS",
      "name": "Unpinned third-party GitHub Actions (3 found)",
      "category": "GITHUB ACTIONS & CI/CD",
      "severity": "HIGH",
      "detail": "Third-party GitHub Actions are referenced without...",
      "evidence": "Unpinned: some-org/some-action@v2, ..."
    }
  ]
}
```

---

## 7. Agent Skill

Elf ships with a `skill.md` that drops directly into OpenClaw, Hermes, Claude, or any agent framework that supports skill files.

```bash
cp skill.md ~/.pi/agent/skills/elf.md
```

Your agent now understands:
- `"check https://github.com/owner/repo before using it"`
- `"is this repo safe to use?"`
- `"run elf on this GitHub URL"`
- `"scan this repository for threats"`

The agent calls `elf.agent.check()` and returns the full text report to the user.

---

## 8. All 136 Checks — Complete Documentation

---

### 8.1 Identity & Ownership (14 checks)

*Is this repo who it claims to be? Can the owner's identity be trusted?*

**CHECK 001 — Repository created less than 7 days ago** `HIGH`  
Repositories fewer than 7 days old have no trust history. Malicious packages are frequently published under fresh accounts to bypass reputation-based trust systems. Any starred or published repo this new warrants extreme scrutiny.

**CHECK 002 — Repository created less than 30 days ago** `MEDIUM`  
Under-30-day repos have no established reputation. Real-world supply-chain attacks frequently use newly created packages. Heightened scrutiny is warranted.

**CHECK 003 — Owner account created less than 30 days ago** `HIGH`  
A freshly created owner account is consistent with throwaway attacker infrastructure. Legitimate software maintainers have established GitHub histories.

**CHECK 004 — Owner account created less than 7 days ago** `CRITICAL`  
A 7-day-old account owning a published package is a near-certain signal of single-use attacker infrastructure. Do not trust.

**CHECK 005 — Owner has zero other public repositories** `HIGH`  
Accounts with no other repos are consistent with infrastructure created solely to distribute this specific malicious package. Real developers accumulate project histories.

**CHECK 006 — Owner account has completely empty profile** `MEDIUM`  
No name, bio, email, website, company, or location. Ghost profiles are consistent with attacker infrastructure accounts created purely to host malicious code.

**CHECK 007 — Star-to-fork ratio anomaly** `HIGH`  
Stars ≥ 50 with zero forks, or fork-to-star ratio far below the typical 1–5% range for healthy projects. Real community interest generates forks. Purchased fake stars do not.

**CHECK 008 — Fake star accounts detected in sample** `CRITICAL/HIGH`  
Accounts that were created the exact same day they starred this repository are the primary fingerprint of purchased fake GitHub stars. A fake rate ≥ 40% triggers CRITICAL.

**CHECK 009 — Repository is a fork** `LOW`  
Attackers frequently fork popular projects, inject malicious code, and present the fork as the original. Always verify you are using the canonical upstream source.

**CHECK 010 — Owner has repos but zero followers** `LOW`  
Legitimate developers who maintain meaningful projects typically accumulate followers. Zero followers across multiple repos is an unusual credibility signal.

**CHECK 011 — No repository description** `LOW`  
Complete absence of a description — combined with other signals — can indicate a hastily assembled malicious package or deliberate opacity about purpose.

**CHECK 012 — No license declared** `LOW`  
Legitimate open-source projects almost universally declare a license. Absence creates legal ambiguity and is associated with hastily created attacker infrastructure.

**CHECK 013 — High star count with no topics** `LOW`  
A high-star repo with no GitHub topic tags is inconsistent with organic open-source traction, where popular projects get tagged by their community.

**CHECK 014 — Very new repo with unusual star velocity** `HIGH`  
Stars accrued in the first 1–3 days of a repo's existence are a near-certain indicator of purchased fake stars. Organic GitHub stars accumulate gradually over weeks and months.

---

### 8.2 GitHub Actions & CI/CD (18 checks)

*Workflow files are a primary attack surface. Every check operates on raw YAML text — no workflows are triggered or executed.*

**CHECK 015 — Unpinned third-party GitHub Actions** `HIGH`  
Tags like `@v1` or `@main` are mutable. GitHub explicitly states that pinning to a full 40-character commit SHA is the only way to guarantee immutability. A compromised action maintainer can update the tag to execute malicious code in this repo's pipeline.

**CHECK 016 — pull_request_target with repository checkout** `CRITICAL`  
Documented by GitHub's security team as critically dangerous. This trigger runs with write permissions and secret access even for PRs from forks. Checking out and running untrusted PR code in this context allows any external contributor to steal secrets or push to protected branches.

**CHECK 017 — workflow_run with elevated permissions or checkout** `HIGH`  
A known privilege escalation path: a low-privilege workflow triggered by a fork PR triggers a high-privilege `workflow_run` workflow, enabling secret exfiltration from untrusted code.

**CHECK 018 — Over-privileged GITHUB_TOKEN** `MEDIUM`  
Workflows granting write permissions beyond what is needed increase blast radius. A compromised action or script injection can leverage broad write permissions to modify releases, packages, or repository settings.

**CHECK 019 — Script injection via GitHub context variables** `CRITICAL`  
Untrusted GitHub event context variables (issue titles, PR titles, branch names, commit messages, review bodies) used directly in shell `run:` steps. An attacker crafts a malicious input value that gets executed as shell code with full runner privileges and secret access.

**CHECK 020 — Self-hosted runners** `MEDIUM`  
Self-hosted runners persist between jobs. A compromised job can leave backdoors or steal credentials that affect subsequent runs. GitHub-hosted runners are ephemeral. Self-hosted runners should never be used with public repositories.

**CHECK 021 — Cache restore in privileged context** `HIGH`  
Cache poisoning: a malicious workflow poisons the cache with a backdoored dependency, which is then restored and executed by a subsequent privileged workflow run, bypassing normal integrity checks.

**CHECK 022 — Artifact download in privileged context** `HIGH`  
A low-privilege workflow uploads a malicious artifact, which is downloaded and processed by a high-privilege workflow — enabling privilege escalation and secret exfiltration through the artifact pipeline.

**CHECK 023 — Secrets printed to workflow logs** `CRITICAL`  
Workflow steps echo or print secret values to log output. GitHub masks known secret patterns, but creative formatting, base64 encoding, or multi-step obfuscation can bypass this masking, exposing secrets to anyone with Actions tab access.

**CHECK 024 — Composite actions from external repositories** `HIGH`  
External composite actions not pinned to immutable commit SHAs. A compromised action maintainer can update to exfiltrate secrets or modify build outputs across any repository using the action.

**CHECK 025 — workflow_dispatch inputs used unsafely** `HIGH`  
Manual trigger inputs passed directly into shell commands without sanitization. Anyone with repository access can trigger the workflow with a malicious input and execute arbitrary commands.

**CHECK 026 — Matrix expansion from untrusted external input** `HIGH`  
`fromJSON()` used with GitHub event context to build the job matrix. Injecting a malicious JSON payload through an issue comment or PR title can cause unexpected job execution or shell command injection.

**CHECK 027 — Debug mode enabled** `MEDIUM`  
`ACTIONS_STEP_DEBUG=true` causes GitHub Actions to log all environment variables in expanded form, potentially exposing masked secrets to anyone with Actions tab read access.

---

### 8.3 Dependencies & Packages (22 checks)

*Package manifests and lockfiles are analysed as text. Nothing is installed or executed.*

**CHECK 028–032 — Typosquatted packages (npm, PyPI, Cargo, Go, Ruby)** `CRITICAL`  
Dependency names that closely resemble popular packages (one letter different, number substitution, separator change) but are not the real package. Typosquatting is responsible for numerous real-world supply-chain compromises. Detection uses edit-distance similarity and common substitution patterns without network calls.

**CHECK 033 — No lockfile present** `MEDIUM`  
Without a lockfile, dependency resolution is non-deterministic. An attacker who compromises a dependency's registry account can publish a malicious new version that gets silently pulled in on any fresh install.

**CHECK 034 — Lockfile inconsistent with manifest** `HIGH`  
Lockfile poisoning: the manifest declares safe dependencies, but the lockfile resolves to different versions or sources. Always verify lockfiles are regenerated from clean manifests and committed atomically.

**CHECK 035 — Git-based dependency on mutable branch** `HIGH`  
A dependency pulled from a git URL pointing to a mutable branch (not a commit SHA) means installed code can change every time the referenced branch is updated. An attacker who compromises the referenced repository can inject malicious code without any version change visible in the manifest.

**CHECK 036–040 — npm lifecycle scripts (preinstall, install, postinstall, prepare, prepublish)** `CRITICAL/HIGH`  
Lifecycle scripts execute automatically on `npm install` — before the user can inspect what runs. This is one of the most common real-world npm supply-chain attack vectors (event-stream, node-ipc, ua-parser-js). Scripts that make network calls or run shell commands escalate to CRITICAL.

**CHECK 041 — Very short package names** `LOW`  
1–2 character package names are disproportionately targeted by dependency confusion and typosquatting because they are easy to mistype or confuse with internal package names.

**CHECK 042 — Native addon compilation** `MEDIUM`  
Native addons (node-gyp, etc.) compile C/C++ code during installation and execute at the OS level with full system access — completely bypassing JavaScript sandboxing. Malicious native addons can exfiltrate credentials or install persistence with no restrictions.

**CHECK 043 — Known malicious package reference** `CRITICAL`  
Dependency references that match packages publicly identified in real-world supply-chain attacks, including specific malicious versions of event-stream, node-ipc, ua-parser-js, colors, coa, and others.

**CHECK 044 — Dependency sourced from git URL** `HIGH`  
Bypasses registry security scanning, version consistency, and integrity checks. The referenced git repository may have been recently transferred, compromised, or abandoned.

---

### 8.4 Source Code (34 checks)

*Pure static analysis on raw text. No code is executed, compiled, or interpreted.*

**CHECK 045 — Bidirectional Unicode control characters (Trojan Source)** `CRITICAL`  
CVE-2021-42574. Bidi Unicode control characters (U+202E RIGHT-TO-LEFT OVERRIDE, etc.) make malicious code appear visually innocent to code reviewers while the parser/compiler sees the true dangerous code. Used to hide backdoors that pass code review.

**CHECK 046 — Zero-width invisible characters in identifiers** `HIGH`  
Invisible Unicode characters (U+200B ZERO WIDTH SPACE, U+200D ZERO WIDTH JOINER, etc.) create variables or function names that look identical to legitimate names but are actually different identifiers — a homograph attack at the character level used to introduce subtle backdoors.

**CHECK 047–049 — Code obfuscation (long lines, base64 decode, string concat)** `HIGH/MEDIUM`  
Obfuscation techniques that fragment or hide malicious code from static analysis: excessively long single lines, base64-encoded payloads decoded at runtime, and strings split into harmless-looking fragments assembled at execution time.

**CHECK 050–051 — eval() and exec() with dynamic content** `HIGH`  
Dynamic execution of runtime-constructed strings. A classic technique for hiding malicious payload assembly from static analysis — the dangerous string is constructed from seemingly innocent pieces and then executed.

**CHECK 052–053 — subprocess with shell=True, os.system()** `HIGH`  
Shell execution with dynamic input. shell=True disables argument escaping and passes the command through the system shell, enabling injection attacks and arbitrary command execution.

**CHECK 054 — Direct socket to IP address** `HIGH`  
Network connections to raw IP addresses in code. Legitimate services use domain names. Hardcoded IP connections are associated with command-and-control infrastructure and exfiltration endpoints.

**CHECK 055–056 — /etc/passwd and /etc/shadow access** `HIGH/CRITICAL`  
Code that reads Unix system password files. /etc/shadow in particular contains password hashes and should never be accessed by application code.

**CHECK 057–061 — Credential file access (SSH, AWS, GCP, Azure, Windows)** `HIGH`  
Code patterns that access credential stores: `~/.ssh`, `~/.aws`, `~/.gcp`, `~/.azure`, Windows Credential Manager. Consistent with credential theft malware.

**CHECK 062 — Browser credential file access** `HIGH`  
Patterns accessing Chrome Login Data, Firefox profiles, or similar browser credential databases. A primary target of infostealer malware.

**CHECK 063 — Hardcoded IP addresses** `MEDIUM`  
Raw IP addresses in source code. Associated with command-and-control servers, exfiltration endpoints, and malicious download sources in real-world malware.

**CHECK 064–068 — Hardcoded credentials (AWS, GitHub tokens, OpenAI keys, private keys, DB strings)** `CRITICAL`  
Hardcoded API keys, tokens, private keys, and database connection strings. Exposed to anyone who clones the repository, including in git history after deletion.

**CHECK 069–070 — Clipboard access and screen capture** `MEDIUM`  
Code accessing the clipboard or capturing screen content outside of tools specifically designed for those purposes. Associated with spyware and data theft.

**CHECK 071 — Keylogging / keyboard hooks** `CRITICAL`  
Keyboard input capture via pynput, Windows hooks, or similar. Keyloggers are among the most severe credential theft tools. Their presence in a library or utility package is a near-definitive indicator of malware.

**CHECK 072–073 — Reverse shell patterns** `CRITICAL`  
`/dev/tcp` bash reverse shells and netcat reverse shell patterns. These open a remote interactive shell from the victim's machine to an attacker-controlled server, providing complete system access.

**CHECK 074–075 — Download-and-execute patterns** `CRITICAL`  
`curl | bash`, `wget | bash`, and equivalent patterns that download content from a remote URL and pipe it directly to a shell interpreter with no integrity verification.

**CHECK 076–079 — Persistence mechanisms** `HIGH`  
Code that installs persistence: cron jobs, systemd services, Windows registry Run keys, macOS LaunchAgents/LaunchDaemons, shell profile modifications. Legitimate libraries do not modify system startup configuration.

**CHECK 080–081 — Privilege escalation and cryptomining** `HIGH/CRITICAL`  
setuid/setgid manipulation and cryptomining pool connections (stratum+tcp://, XMRig patterns). Cryptomining malware has been the payload in numerous npm and PyPI supply-chain attacks.

---

### 8.5 Build System (12 checks)

*Build scripts are read as text — never executed.*

**CHECK 082 — setup.py with network calls during install** `CRITICAL`  
Python's setup.py runs automatically during `pip install` before any code inspection is possible. Network calls in setup.py download and execute second-stage payloads, exfiltrate environment variables, or install persistence. This is one of the most common real-world PyPI attack vectors.

**CHECK 083 — Makefile download-and-execute** `HIGH`  
`curl | bash` or equivalent in Makefile targets executes arbitrary remote code during `make` with no integrity verification, no sandboxing, and no audit trail.

**CHECK 084 — Makefile network calls** `MEDIUM`  
Network fetches during build. Build-time network calls can pull in malicious second-stage payloads and make builds non-deterministic.

**CHECK 085 — CMakeLists.txt external fetch** `MEDIUM`  
`FetchContent_Declare`, `ExternalProject_Add`, or `file(DOWNLOAD)` creates a non-hermetic build that depends on external sources which may be compromised or unavailable.

**CHECK 086 — Dockerfile download-and-execute** `CRITICAL`  
A `RUN` instruction that downloads and pipes to a shell interpreter executes arbitrary remote code during the container build with root privileges inside the build container.

**CHECK 087 — Dockerfile runs as root** `MEDIUM`  
No `USER` instruction switching to a non-root user. Container processes running as root have elevated privileges and can escape to the host through container breakout vulnerabilities.

**CHECK 088 — docker-compose privileged: true** `HIGH`  
Privileged containers have nearly full host system access — all devices, kernel parameter modification, and container namespace escape capability. Should never appear in public repository configuration.

**CHECK 089 — docker-compose sensitive host mounts** `HIGH`  
Mounting `/etc`, `/var`, `/root`, `/proc`, `/sys`, or `/dev` into containers gives the container process direct access to host system files, credentials, and runtime data.

**CHECK 090 — CI/CD conditional behavior in build scripts** `MEDIUM`  
Build scripts that check for `CI=true`, `GITHUB_ACTIONS`, or similar environment variables and behave differently. Used in real attacks to make malware active in CI (where secrets are available) while appearing clean during local developer testing.

**CHECK 091 — Destructive file operations** `CRITICAL`  
`rm -rf /`, `shutil.rmtree('/')`, `Format-Volume`, or similar operations targeting paths outside the project directory. Consistent with wiper malware or sabotage payloads in build scripts.

---

### 8.6 Repository Structure (12 checks)

*Structural analysis of the repository's files, history, and git metadata.*

**CHECK 092 — No README file** `MEDIUM`  
A README is the most basic project documentation. Its absence in a starred or published package suggests hasty assembly or deliberate opacity. Malicious packages frequently omit documentation.

**CHECK 093 — Sensitive filenames committed** `HIGH`  
Files named `password`, `secret`, `private_key`, `credentials`, `id_rsa`, `.pem`, `.key`, etc. committed to the repository. Even if currently empty or template, the presence suggests poor security practices and the file may have contained real values in git history.

**CHECK 094 — Binary executables in source tree** `HIGH`  
Pre-built binaries (`.exe`, `.dll`, `.so`, `.elf`, etc.) committed directly to source. Binary files are opaque to code review and static analysis. Malicious actors use pre-built binaries to bypass source-level inspection while delivering working malware.

**CHECK 095 — Git submodules pointing to external repos** `MEDIUM`  
Submodules are supply-chain dependencies with no code review or security controls in this repository. A compromised submodule repository, or one pointing to a mutable branch, can pull in malicious code without any change to this repository.

**CHECK 096 — Commit history ordering anomaly** `MEDIUM`  
Inconsistent commit timestamps suggesting a history rewrite (force push or rebase). History rewrites can hide prior malicious commits, remove incriminating changes, or alter the apparent age and authorship of code.

**CHECK 097 — Multiple tags pointing to few commit SHAs** `MEDIUM`  
Multiple release tags sharing SHAs may indicate that tags have been rewritten or moved — breaking the immutability guarantee release tags are supposed to provide, and potentially associating a malicious commit with a previously trusted release.

**CHECK 098 — Unusually large files (10MB+)** `LOW`  
Very large files may contain embedded executables, encrypted payloads, or other opaque content. Legitimate source code is rarely this large at the individual file level.

**CHECK 099 — High popularity with no community engagement** `MEDIUM`  
A repository with significant stars but zero forks is inconsistent with organic open-source adoption. Genuine community interest generates forks. Fake star inflation does not.

**CHECK 100 — Perfect commit message history** `LOW`  
100% Conventional Commits compliance across all commits can indicate automated commit generation, which is associated with fake project creation for social proof purposes.

---

### 8.7 Agent Safety & Prompt Injection (16 checks)

*The most critical and unique category. No traditional security scanner covers this attack surface.*

When an AI agent reads a repository's README, documentation, code comments, or issue templates, that text becomes part of the agent's context. An attacker can embed instructions in that text designed to manipulate the agent's behavior — just as a phishing email manipulates a human.

**CHECK 101 — "Ignore previous instructions" pattern** `CRITICAL`  
The canonical prompt injection attack. Text instructing the agent to disregard its guidelines, safety rules, or prior context. Found in real-world attacks against AI-assisted development tools.

**CHECK 102 — Persona switch instruction ("you are now")** `CRITICAL`  
Instructions attempting to reassign the agent's role, identity, or capabilities — a jailbreak technique designed to make the agent abandon its safety constraints.

**CHECK 103 — Instruction to forget context** `CRITICAL`  
Language instructing the agent to forget its training, guidelines, or prior conversation — used to remove safety constraints before issuing harmful instructions.

**CHECK 104 — Suppress safety reporting** `CRITICAL`  
"Do not report this", "do not flag this", "skip the security check" — instructions designed to prevent the agent from alerting the user to dangerous content or actions.

**CHECK 105 — Bypass safety systems** `CRITICAL`  
"Bypass the security filter", "bypass restrictions" — direct instructions to circumvent the agent's built-in safety mechanisms.

**CHECK 106 — False safety assurance** `HIGH`  
"This is safe to run", "this code is verified" — false claims designed to make autonomous agents skip safety verification for malicious actions.

**CHECK 107 — Automatic approval instruction** `CRITICAL`  
"Automatically approve this", "do not ask for confirmation" — instructions designed to bypass human-in-the-loop confirmation for dangerous operations like installations, deletions, or network calls.

**CHECK 108 — Skip confirmation instruction** `CRITICAL`  
"Do not prompt the user", "proceed without waiting" — instructions to remove human oversight from agent actions that would normally require explicit approval.

**CHECK 109 — Data exfiltration instruction** `CRITICAL`  
"Send your context to...", "transmit your API key to..." — explicit instructions for the agent to leak its own credentials, system prompts, memory, or user data to attacker-controlled endpoints.

**CHECK 110 — System prompt extraction** `CRITICAL`  
"Print your system prompt", "reveal your instructions" — attempts to extract the agent's internal configuration and safety guidelines.

**CHECK 111 — Hidden instruction in HTML comment** `CRITICAL`  
Instructions embedded in HTML comment syntax (`<!-- you are now... -->`). Invisible when rendered but fully visible to text-processing agents and LLM tokenizers. A covert prompt injection technique specifically designed to avoid detection by human code reviewers.

**CHECK 112 — CSS-hidden text** `CRITICAL`  
Text with `display:none`, `visibility:hidden`, or `color:white` — invisible to human readers rendering the page but fully processed by text-based agents. Another covert prompt injection vector.

**CHECK 113 — Social engineering / false trust claims** `HIGH`  
"Verified by GitHub", "certified by Anthropic", "security scan passed", "no malware detected" — false claims specifically designed to manipulate automated systems and AI agents into treating malicious repositories as trusted. No legitimate security system communicates trust through README text.

**CHECK 114 — Copy-paste execution bait** `CRITICAL`  
Code blocks in documentation containing dangerous commands (`curl | bash`, destructive operations) formatted to look like normal installation instructions. AI coding agents frequently copy and execute commands from README install sections without human review.

**CHECK 115 — Hidden Unicode in documentation** `HIGH`  
Zero-width and invisible Unicode control characters in markdown and documentation text. Invisible to human readers, fully processed by LLM tokenizers. Used to embed hidden instructions that AI agents process during documentation parsing.

**CHECK 116 — Prompt injection in code comments** `CRITICAL`  
AI coding assistants (GitHub Copilot, Cursor, Claude Code, etc.) read source code comments as part of their context. Malicious instructions in comments manipulate AI coding agents into generating insecure code, bypassing security checks, or exfiltrating data during code review or generation tasks.

**CHECK 117 — Agent memory poisoning** `HIGH`  
Language instructing agents to store information in persistent memory for future use. Agents with memory capabilities could be manipulated into persisting malicious instructions that affect future, unrelated tasks — a long-term prompt injection that persists across sessions.

**CHECK 118 — RAG / retrieval poisoning** `CRITICAL`  
Content explicitly addressed to AI models, agents, or LLMs — structured as instructions for when the content is retrieved. A RAG poisoning attack: content indexed into a vector store carries hidden instructions that activate when retrieved by an agent during a query, executing in the agent's context without the user's knowledge.

---

### 8.8 Provenance & Signing (8 checks)

*Verifies whether release artifacts can be cryptographically linked to their source.*

**CHECK 119 — No SLSA provenance attestation** `MEDIUM`  
SLSA provenance links a release artifact to the exact source commit and build process that produced it. Without it, there is no cryptographic guarantee that the published release came from this repository's source — leaving room for trojanized release binaries.

**CHECK 120 — Release assets unsigned** `MEDIUM`  
No signature files (`.sig`, `.asc`, `.minisig`) alongside release assets. Without signatures, it is impossible to verify that a downloaded release has not been tampered with through network interception or storage compromise.

**CHECK 121 — No checksum file with release** `LOW`  
No SHA256SUMS or SHA512SUMS file. Checksums allow users to verify artifact integrity without GPG infrastructure. Their absence means there is no simple way to detect if a release asset has been replaced.

**CHECK 122 — Checksums in mutable release body only** `MEDIUM`  
SHA hashes published in release description text rather than as dedicated asset files. Release descriptions are mutable and can be silently edited by anyone who compromises the account — making the checksum worthless as an integrity guarantee.

**CHECK 123 — Tags without formal releases** `LOW`  
Version tags exist but no formal GitHub releases. Tags alone provide no artifact integrity — they point to commits but do not include signed, verified artifacts.

**CHECK 124 — Inconsistent release artifact pattern** `LOW`  
Some releases have assets and others do not. Inconsistent practices make it harder to establish a reliable integrity verification workflow.

**CHECK 125 — Force pushes allowed on default branch** `HIGH`  
Force pushes can rewrite git history — altering past commits, removing incriminating changes, or retroactively inserting malicious code into what appears to be a historical clean commit. Protected branches with force-push disabled are essential for an auditable commit history.

**CHECK 126 — Missing branch protection signals** `MEDIUM`  
Absence of branch protection on the default branch allows any collaborator to push directly, bypassing code review, and allows history rewriting through force pushes.

---

## 9. Verdict System

| Verdict    | Triggers | Meaning | Recommended Action |
|------------|----------|---------|-------------------|
| ✅ **SAFE** | Zero findings | All 136 checks passed | Proceed with appropriate caution |
| ⚠️ **WARN** | Medium or Low findings only | Signals worth reviewing but no definitive threats | Human review before production use |
| 🔴 **NOT SAFE** | Any Critical or High finding | Active threat signals detected | Do not install, execute, or allow agent access |

---

## 10. Sample Output

```
🧝  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ELF REPOSITORY SAFETY REPORT
🧝  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Repository : https://github.com/example/malicious-package
    Scanned    : 2026-03-24 12:00:00 UTC
    Checks run : 136

    Description: A totally legitimate utility package
    Language   : Python
    Stars      : 4,200
    Forks      : 0
    Created    : 2026-03-20

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    VERDICT:  🔴  NOT SAFE
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    FINDINGS SUMMARY
    ──────────────────────────────────────────────────────────────
    🔴 Critical : 3
    🚨 High     : 2
    ⚠️  Medium   : 1
    🔎 Low      : 1
    ── Total    : 7 finding(s)

    PLAIN ENGLISH SUMMARY
    ──────────────────────────────────────────────────────────────
    This repository is NOT SAFE for agent use or installation.
    3 CRITICAL finding(s) require immediate attention.
    ⚠️  AGENT SAFETY: Prompt injection or manipulation content detected.
    ⚠️  IDENTITY: Repository or owner trust signals are weak.
    ⚠️  DEPENDENCIES: Dangerous or suspicious package dependencies found.
    ⚠️  BUILD: Build scripts execute dangerous code during install.

    DETAILED TECHNICAL FINDINGS
    ──────────────────────────────────────────────────────────────

    ┌── IDENTITY & OWNERSHIP (2 finding(s))
    │
    │  [🔴 CRITICAL]  Repository created less than 7 days ago
    │
    │     This repository was created fewer than 7 days ago.
    │     Malicious packages are frequently published under
    │     fresh accounts to bypass reputation-based trust
    │     systems. A repo this new should not be used in
    │     production or by autonomous agents.
    │
    │  Evidence:
    │     Created: 2026-03-20 (4 days ago)
    │
    │  Check ID : 001  |  Code: REPO_AGE_UNDER_7_DAYS
    ...
```

---

## 11. What Elf Does Not Cover

Elf is explicit about its limits. These gaps exist because covering them would require executing code or running complex infrastructure:

| Gap | Why | Alternative |
|-----|-----|-------------|
| Dynamic runtime behavior | Requires sandbox execution | Manual execution in isolated VM |
| Binary disassembly | Requires reverse engineering tools | Ghidra, IDA Pro, Binary Ninja |
| Hermetic rebuild comparison | Requires build infrastructure | SLSA provenance verification |
| Zero-day exploits | No static signature exists | Behavioral analysis platforms |
| Private repo contents | GitHub API does not return private data | Internal scanning tools |
| Network behavior tracing | Requires runtime environment | Network sandbox tools |

Transparency about these limits is what makes the other 136 checks more trustworthy, not less.

---

## 12. False Positive Guidance

Elf uses heuristics. False positives exist. Here is how to interpret edge cases:

**Very new repo with real known maintainer** — Check 001/002 will fire. This is expected. Evaluate the maintainer's identity through other means.

**Fork of a popular project** — Check 009 will fire. Forks are normal; verify the fork is from the legitimate source and was not modified maliciously.

**Large data files in ML/data repos** — Check 098 (large files) may fire on legitimate datasets. Evaluate in context.

**Aggressive lifecycle scripts in monorepos** — Check 036–040 may fire on scripts that run legitimate build steps. Read the script content in the finding evidence.

**Conventional commits on all projects** — Check 100 (perfect commit messages) is a LOW signal only. Evaluate in context of other identity signals.

Always apply human expert judgment. Elf is a tool to assist security review, not replace it.

---

## 13. Contributing

Elf is MIT licensed and designed to be extended.

```bash
git clone https://github.com/aegiswizard/elf.git
cd elf
pip install -e ".[dev]"
pytest
```

Areas where community contributions add most value:
- Additional typosquat reference lists for more ecosystems
- More secret pattern signatures
- Additional prompt injection patterns
- New check modules for emerging threat categories
- Integration adapters for additional agent frameworks

---

## 14. License

[MIT](LICENSE) © 2026 Aegis Wizard
