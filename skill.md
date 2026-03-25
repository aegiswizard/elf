# 🧝 Elf — GitHub Repository Safety Scanner Skill

**Version:** 1.0.0  
**License:** MIT  
**Source:** https://github.com/aegiswizard/elf  
**Compatible with:** OpenClaw · Hermes · Claude agents · Any Python agent

---

## What This Skill Does

Elf runs 136 security checks on any GitHub repository and returns a single verdict:
**SAFE**, **WARN**, or **NOT SAFE** — with full technical explanation of every finding.

Before any agent installs, clones, or uses a GitHub repository, Elf tells you whether it is safe to do so.

**Safety architecture:** Elf is a static analyser. It never clones the repo, never executes any code, never fetches URLs found inside the repo, and never makes network connections to the repo's content. All analysis runs on text and metadata from the GitHub REST API only.

---

## Trigger Phrases

Your agent should invoke Elf when the user says:

- `"check https://github.com/owner/repo before using it"`
- `"is this repo safe to use?"`
- `"scan this GitHub repo for threats"`
- `"elf check https://github.com/owner/repo"`
- `"run a security check on this repo"`
- `"can I trust this repository?"`
- `"is owner/repo safe for my agent to use?"`
- `"check this GitHub URL before installing"`

---

## Setup

```bash
git clone https://github.com/aegiswizard/elf.git
cd elf
pip install -e .

# Set GitHub token (strongly recommended)
export GITHUB_TOKEN=ghp_your_token_here
# Get free token: https://github.com/settings/tokens
# Required scopes: none (public repos only)
```

---

## CLI Usage

```bash
# Check any repo
elf check https://github.com/owner/repo

# With explicit token
elf check https://github.com/owner/repo --token ghp_xxx

# JSON output (for programmatic use)
elf check https://github.com/owner/repo --output json

# Shorthand
elf check owner/repo
```

**Exit codes:**
- `0` = SAFE
- `2` = WARN
- `3` = NOT SAFE
- `1` = Error

---

## Python API

```python
from elf.agent import check

result = check("https://github.com/owner/repo")

# Core verdict
print(result["verdict"])        # "SAFE" | "WARN" | "NOT SAFE"
print(result["safe"])           # True / False

# Full report
print(result["report"])         # Human-readable text report
print(result["report_json"])    # JSON string

# Severity counts
print(result["critical"])       # int
print(result["high"])           # int
print(result["medium"])         # int
print(result["low"])            # int
print(result["findings_count"]) # int total

# All findings
for f in result["findings"]:
    print(f.severity.value, f.name, f.detail)
```

---

## All 136 Checks

### 🔐 Identity & Ownership (14 checks)
1. Repository created less than 7 days ago
2. Repository created less than 30 days ago
3. Owner account created less than 30 days ago
4. Owner account created less than 7 days ago
5. Owner has zero other public repositories
6. Owner account has completely empty profile
7. Star-to-fork ratio anomaly (fake star signal)
8. Fake star accounts detected in sample
9. Repository is a fork presented as original
10. Owner has repos but zero followers
11. Repository has no description
12. No license declared
13. High stars with no topics/tags
14. Very new repo with unusual star velocity

### ⚙️ GitHub Actions & CI/CD (18 checks)
15. Unpinned third-party GitHub Actions
16. pull_request_target with repository checkout
17. workflow_run with elevated permissions
18. Over-privileged GITHUB_TOKEN
19. Script injection via GitHub context variables
20. Self-hosted runners declared
21. Cache restore in privileged context
22. Artifact download in privileged context
23. Secrets printed to workflow logs
24. Composite actions from external repositories
25. workflow_dispatch inputs used unsafely
26. Matrix expansion from untrusted input
27. Debug mode enabled (secrets exposure)

### 📦 Dependencies & Packages (22 checks)
28–32. Typosquatted packages (npm, PyPI, Cargo, Go, Ruby)
33. No lockfile present
34. Lockfile inconsistent with manifest
35. Git-based dependency on mutable branch
36. npm preinstall lifecycle script
37. npm install lifecycle script
38. npm postinstall lifecycle script
39. npm prepare lifecycle script
40. npm prepublish lifecycle script
41. Very short package names
42. Native addon/binary compilation
43. Known malicious package reference
44. Dependency sourced from git URL

### 🔍 Source Code (34 checks)
45. Bidirectional Unicode (Trojan Source attack)
46. Zero-width invisible characters in identifiers
47. Obfuscated long lines (500+ chars)
48. Base64 payload decoded at runtime
49. String concatenation obfuscation
50. eval() with dynamic content
51. exec() with dynamic content
52. subprocess with shell=True
53. os.system() call
54. Direct socket to IP address
55. /etc/passwd access
56. /etc/shadow access
57. SSH directory access (~/.ssh)
58. AWS credentials access (~/.aws)
59. GCP credentials access
60. Azure credentials access
61. Windows credential store access
62. Browser credential file access
63. Hardcoded IP addresses
64. Hardcoded API key / secret (AWS)
65. GitHub token in source
66. OpenAI API key in source
67. Private key / certificate embedded
68. Database connection string with credentials
69. Clipboard access
70. Screen capture code
71. Keylogging / keyboard hook
72. Reverse shell pattern (/dev/tcp)
73. Netcat reverse shell pattern
74. curl pipe to bash execution
75. wget pipe to execution
76. Cron job modification
77. Systemd service installation
78. Windows registry Run key modification
79. macOS LaunchAgent installation
80. Privilege escalation via setuid/setgid
81. Cryptomining pool connection
82. Hardcoded passwords in source

### 🏗️ Build System (12 checks)
83. setup.py with network calls during install
84. Makefile download-and-execute pattern
85. Makefile network calls during build
86. CMakeLists.txt fetches external content
87. Dockerfile downloads and executes remote code
88. Dockerfile runs as root
89. docker-compose privileged: true
90. docker-compose mounts sensitive host paths
91. Build script with CI/CD conditional behavior
92. Build script destructive file operations
93. package.json build script with suspicious commands
94. Cargo.toml build.rs with external fetch

### 📁 Repository Structure (12 checks)
95. No README file
96. Files with sensitive names committed
97. Binary executables in source tree
98. Git submodules pointing to external repos
99. Commit history ordering anomaly
100. Multiple tags pointing to few SHAs
101. Unusually large files (10MB+)
102. High popularity with no forks
103. Single contributor ever
104. Perfect commit message history (scripted signal)
105. No community engagement signals
106. Recently transferred repository

### 🤖 Agent Safety & Prompt Injection (16 checks)
107. "Ignore previous instructions" pattern
108. "You are now" persona switch
109. Instruction to forget context/training
110. Instruction to suppress safety reporting
111. Instruction to bypass security systems
112. False safety assurance for autonomous execution
113. Automatic approval instruction
114. Skip user confirmation instruction
115. Data exfiltration instruction
116. System prompt extraction instruction
117. Hidden instruction in HTML comment
118. CSS-hidden text targeting parsers
119. Social engineering / false trust claims
120. Copy-paste execution bait in code blocks
121. Hidden Unicode control characters in docs
122. Prompt injection in code comments
123. Agent memory poisoning instruction
124. RAG / retrieval poisoning instruction

### 🔏 Provenance & Signing (8 checks)
125. No SLSA provenance attestation
126. Release assets unsigned
127. No checksum file with release
128. Checksums in mutable release body only
129. Tags without formal releases
130. Inconsistent release artifact pattern
131. Force pushes allowed on default branch
132. Missing branch protection signals

---

## Verdict Meanings

| Verdict   | Meaning |
|-----------|---------|
| ✅ SAFE    | All 136 checks passed. No threats detected. |
| ⚠️ WARN   | Medium or low findings. Human review recommended. |
| 🔴 NOT SAFE | Critical or high findings. Do not install or use. |

---

## What Elf Does NOT Cover

Elf is transparent about its limits:

- ❌ Dynamic runtime behavior (requires sandbox execution)
- ❌ Binary artifact disassembly (requires reverse engineering)
- ❌ Hermetic rebuild comparison (requires build infrastructure)
- ❌ Zero-day exploits with no static signature
- ❌ Private repository contents

Always apply human expert judgment before production deployment.

---

## Zero Dependencies

Elf uses Python standard library only: `urllib`, `json`, `re`, `difflib`, `unicodedata`, `pathlib`, `dataclasses`.

Works on Raspberry Pi, Mac, Windows, Linux. Works offline for local files.

---

## Disclaimer

Elf uses heuristics. False positives exist. Results are security intelligence, not definitive verdicts. Always apply human judgment. Elf is a tool to assist human security review, not replace it.
