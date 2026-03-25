"""
Elf 🧝 — Source Code Checks (55–88)
Static analysis of source files. Never executes any code.
All analysis is pattern matching on raw text.
"""

import re
import unicodedata
from pathlib import Path
from ..models import Finding, Severity, Category


# ---------------------------------------------------------------------------
# Unicode danger characters
# ---------------------------------------------------------------------------

# Bidirectional override characters used in Trojan Source attacks
_BIDI_CHARS = {
    '\u202a': 'LEFT-TO-RIGHT EMBEDDING',
    '\u202b': 'RIGHT-TO-LEFT EMBEDDING',
    '\u202c': 'POP DIRECTIONAL FORMATTING',
    '\u202d': 'LEFT-TO-RIGHT OVERRIDE',
    '\u202e': 'RIGHT-TO-LEFT OVERRIDE',
    '\u2066': 'LEFT-TO-RIGHT ISOLATE',
    '\u2067': 'RIGHT-TO-LEFT ISOLATE',
    '\u2068': 'FIRST STRONG ISOLATE',
    '\u2069': 'POP DIRECTIONAL ISOLATE',
    '\u200f': 'RIGHT-TO-LEFT MARK',
}

# Zero-width and invisible characters
_INVISIBLE_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\ufeff': 'ZERO WIDTH NO-BREAK SPACE (BOM)',
    '\u2060': 'WORD JOINER',
    '\u00ad': 'SOFT HYPHEN',
}

# Source file extensions to scan
_SOURCE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.rb', '.php', '.java', '.go', '.rs', '.cs', '.cpp', '.c',
    '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.psd1',
    '.lua', '.pl', '.pm', '.r', '.swift', '.kt', '.kts',
    '.vue', '.svelte', '.html', '.htm',
}

# ---------------------------------------------------------------------------
# Secret / credential patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']?([A-Z0-9]{16,})',
     "AWS credential", Severity.CRITICAL),
    (r'AKIA[0-9A-Z]{16}',
     "AWS Access Key ID", Severity.CRITICAL),
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
     "API key pattern", Severity.HIGH),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
     "Hardcoded password", Severity.HIGH),
    (r'(?i)(secret|token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']',
     "Hardcoded secret/token", Severity.HIGH),
    (r'ghp_[A-Za-z0-9]{36}',
     "GitHub Personal Access Token", Severity.CRITICAL),
    (r'gho_[A-Za-z0-9]{36}',
     "GitHub OAuth token", Severity.CRITICAL),
    (r'sk-[A-Za-z0-9]{48}',
     "OpenAI API key", Severity.CRITICAL),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
     "Private key", Severity.CRITICAL),
    (r'(?i)private[_\s]key\s*[=:]\s*["\']([A-Za-z0-9+/=]{40,})["\']',
     "Base64-encoded private key", Severity.CRITICAL),
    (r'(?i)database_url\s*[=:]\s*["\']postgresql://[^"\']+:[^"\']+@',
     "Database connection string with credentials", Severity.HIGH),
    (r'(?i)mongodb\+srv://[^:]+:[^@]+@',
     "MongoDB connection string with credentials", Severity.HIGH),
]

# ---------------------------------------------------------------------------
# Dangerous code patterns
# ---------------------------------------------------------------------------

_DANGEROUS_CODE_PATTERNS = [
    # Dynamic execution
    (r'\beval\s*\(', "eval() call", Severity.HIGH),
    (r'\bexec\s*\(', "exec() call", Severity.HIGH),
    (r'\bFunction\s*\(\s*["\']', "Function() constructor with string", Severity.HIGH),
    (r'new\s+Function\s*\(', "new Function() constructor", Severity.HIGH),
    # Dynamic imports
    (r'require\s*\(\s*[a-zA-Z_$][a-zA-Z_$0-9]*\s*\)', "require() with variable argument", Severity.MEDIUM),
    (r'import\s*\(\s*[a-zA-Z_$][a-zA-Z_$0-9]*\s*\)', "__import__/dynamic import with variable", Severity.MEDIUM),
    # Shell execution
    (r'subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
     "subprocess with shell=True", Severity.HIGH),
    (r'os\.system\s*\(', "os.system() call", Severity.HIGH),
    (r'os\.popen\s*\(', "os.popen() call", Severity.MEDIUM),
    # Network in suspicious context
    (r'socket\.connect\s*\(\s*\(["\'][0-9]+\.[0-9]+\.[0-9]+\.[0-9]+["\']',
     "Direct socket connection to IP address", Severity.HIGH),
    # File system targets
    (r'/etc/passwd', "Access to /etc/passwd", Severity.HIGH),
    (r'/etc/shadow', "Access to /etc/shadow", Severity.CRITICAL),
    (r'~/.ssh', "Access to SSH directory", Severity.HIGH),
    (r'~/.aws', "Access to AWS credentials directory", Severity.HIGH),
    (r'~/.gcp|google/credentials\.json', "Access to GCP credentials", Severity.HIGH),
    (r'~/.azure', "Access to Azure credentials directory", Severity.HIGH),
    (r'AppData.*Roaming.*Microsoft.*Credentials', "Access to Windows credentials", Severity.HIGH),
    # Browser credentials
    (r'Login\s*Data.*sqlite|Chrome.*Cookies|Firefox.*profiles',
     "Browser credential file access", Severity.HIGH),
    # Clipboard
    (r'pyperclip|clipboard\.get|GetClipboardData|xdotool.*clipboard',
     "Clipboard access", Severity.MEDIUM),
    # Screen capture
    (r'pyautogui\.screenshot|PIL\.ImageGrab|mss\.mss\(\)|CaptureScreen',
     "Screen capture", Severity.MEDIUM),
    # Keylogging
    (r'pynput\.keyboard|keyboard\.on_press|SetWindowsHookEx|GetAsyncKeyState',
     "Keyboard hook / keylogging", Severity.CRITICAL),
    # Reverse shell patterns
    (r'bash\s+-i\s+>&?\s*/dev/tcp/',
     "Reverse shell via /dev/tcp", Severity.CRITICAL),
    (r'nc\s+-[el].*\d{4,5}|ncat\s+.*\d{4,5}',
     "Netcat reverse shell pattern", Severity.CRITICAL),
    # Download and execute
    (r'curl\s+[^|]*\|\s*(bash|sh|python|perl|ruby|node)',
     "curl pipe to shell execution", Severity.CRITICAL),
    (r'wget\s+[^-]*-O-?\s*\|?\s*(bash|sh|python)',
     "wget pipe to execution", Severity.CRITICAL),
    # Persistence
    (r'crontab\s+-[lei]|/etc/cron\.',
     "Cron job modification", Severity.HIGH),
    (r'systemctl\s+enable|systemctl\s+daemon-reload',
     "Systemd service installation", Severity.HIGH),
    (r'HKEY_(LOCAL_MACHINE|CURRENT_USER).*Run\b',
     "Windows registry Run key modification", Severity.HIGH),
    (r'LaunchAgent|LaunchDaemon.*plist',
     "macOS launch agent/daemon installation", Severity.HIGH),
    # Cryptomining
    (r'stratum\+tcp://|pool\.minergate|xmrig|coinhive',
     "Cryptomining pool connection", Severity.CRITICAL),
    # Privilege escalation
    (r'\bsudo\b.*\bchmod\b|\bsetuid\b|\bsetgid\b',
     "Privilege escalation via setuid/setgid", Severity.HIGH),
]


def _scan_text_for_bidi(text: str, filename: str) -> list:
    findings = []
    found_chars = set()
    for char in text:
        if char in _BIDI_CHARS and char not in found_chars:
            found_chars.add(char)
    if found_chars:
        char_names = [_BIDI_CHARS[c] for c in found_chars]
        findings.append(Finding(
            check_id=55,
            name="Bidirectional Unicode control characters (Trojan Source attack)",
            category=Category.SOURCE,
            severity=Severity.CRITICAL,
            detail=(
                "One or more bidirectional Unicode control characters were found in source "
                "files. These characters are used in the 'Trojan Source' attack (CVE-2021-42574) "
                "to make malicious code appear visually innocent to code reviewers. The actual "
                "parser/compiler sees the true — dangerous — code, while human readers see a "
                "visually reordered, innocent-looking version. This technique has been used to "
                "hide backdoors in open-source code that passed code review."
            ),
            evidence=f"File: {filename}  Characters: {', '.join(char_names)}",
            check_name="BIDI_TROJAN_SOURCE",
        ))
    return findings


def _scan_text_for_invisible(text: str, filename: str) -> list:
    findings = []
    found_chars = set()
    # Check for zero-width characters in identifiers (variable names etc.)
    # Find them in non-whitespace context
    for i, char in enumerate(text):
        if char in _INVISIBLE_CHARS:
            # Only flag if in identifier-like context (not just in strings/comments for now)
            context_start = max(0, i - 10)
            context = text[context_start:i+10]
            if re.search(r'[a-zA-Z_$]', context):
                found_chars.add(char)

    if found_chars:
        char_names = [_INVISIBLE_CHARS[c] for c in found_chars]
        findings.append(Finding(
            check_id=56,
            name="Zero-width / invisible Unicode characters in source identifiers",
            category=Category.SOURCE,
            severity=Severity.HIGH,
            detail=(
                "Invisible Unicode characters were found in proximity to code identifiers. "
                "These are used to create variables or function names that look identical "
                "to legitimate names but are actually different symbols — a form of homograph "
                "attack at the character level. For example, 'login' with a hidden zero-width "
                "joiner becomes a completely different identifier while appearing identical. "
                "This technique is used to introduce subtle backdoors that survive casual review."
            ),
            evidence=f"File: {filename}  Characters: {', '.join(char_names)}",
            check_name="INVISIBLE_UNICODE_IDENTIFIERS",
        ))
    return findings


def _check_obfuscation(text: str, filename: str) -> list:
    findings = []
    lines = text.split("\n")

    # Long lines — strong obfuscation signal
    long_lines = [i+1 for i, l in enumerate(lines) if len(l) > 500]
    if long_lines:
        findings.append(Finding(
            check_id=58,
            name=f"Extremely long lines detected (>{500} chars) — obfuscation indicator",
            category=Category.SOURCE,
            severity=Severity.HIGH,
            detail=(
                "Source files contain lines exceeding 500 characters. While not impossible "
                "in legitimate code (e.g. generated files, SVGs), extremely long lines in "
                "logic files are a strong indicator of code obfuscation — deliberately "
                "formatting code to make static analysis and human review difficult. "
                "Obfuscated code in open-source projects should be treated as suspicious."
            ),
            evidence=f"File: {filename}  Long lines at: {long_lines[:10]}",
            check_name="OBFUSCATED_LONG_LINES",
        ))

    # Base64-encoded strings being decoded and used
    b64_exec = re.findall(
        r'(?:base64|b64|atob)\s*(?:\.decode|\.b64decode)?\s*\(["\'][A-Za-z0-9+/=]{40,}["\']\)',
        text, re.IGNORECASE
    )
    if b64_exec:
        findings.append(Finding(
            check_id=59,
            name="Base64-encoded payload decoded at runtime",
            category=Category.SOURCE,
            severity=Severity.HIGH,
            detail=(
                "Source code decodes a base64-encoded string at runtime. While base64 has "
                "legitimate uses (encoding binary data), decoding base64 in a code execution "
                "path is a classic obfuscation technique used to hide malicious payloads from "
                "static analysis tools. The encoded content should be decoded and inspected."
            ),
            evidence=f"File: {filename}  Instances: {len(b64_exec)}",
            check_name="BASE64_RUNTIME_DECODE",
        ))

    # String concatenation obfuscation
    concat_obfuscation = re.findall(
        r'(?:["\']\s*\+\s*["\']){4,}',
        text
    )
    if concat_obfuscation:
        findings.append(Finding(
            check_id=60,
            name="Excessive string concatenation — possible obfuscation",
            category=Category.SOURCE,
            severity=Severity.MEDIUM,
            detail=(
                "Multiple instances of strings split and reassembled via concatenation. "
                "This technique fragments identifiable strings (URLs, commands, malware "
                "signatures) into pieces that each look harmless, assembled only at runtime "
                "to avoid keyword-based detection. Common in malicious browser extensions, "
                "npm packages, and Python packages."
            ),
            evidence=f"File: {filename}  Patterns: {len(concat_obfuscation)}",
            check_name="STRING_CONCAT_OBFUSCATION",
        ))

    return findings


def run_source_checks(source_files: dict) -> list:
    """
    Run all source code checks across all provided source files.
    Never executes any code — pure static text analysis.

    Args:
        source_files: dict of {filepath: file_content_text}

    Returns:
        List of Finding objects.
    """
    findings = []

    # Track which checks have already fired to avoid duplicate findings
    fired_checks = set()

    for filepath, content in source_files.items():
        if not content:
            continue

        ext = Path(filepath).suffix.lower()
        if ext not in _SOURCE_EXTENSIONS:
            continue

        # ── Unicode attacks ────────────────────────────────────────────────
        for f in _scan_text_for_bidi(content, filepath):
            if "BIDI" not in fired_checks:
                findings.append(f)
                fired_checks.add("BIDI")

        for f in _scan_text_for_invisible(content, filepath):
            if "INVISIBLE" not in fired_checks:
                findings.append(f)
                fired_checks.add("INVISIBLE")

        # ── Obfuscation ────────────────────────────────────────────────────
        for f in _check_obfuscation(content, filepath):
            key = f.check_name
            if key not in fired_checks:
                findings.append(f)
                fired_checks.add(key)

        # ── Secret patterns ────────────────────────────────────────────────
        for pattern, label, sev in _SECRET_PATTERNS:
            if f"SECRET_{label}" in fired_checks:
                continue
            matches = re.findall(pattern, content)
            if matches:
                # Don't include actual secret values in output
                findings.append(Finding(
                    check_id=67,
                    name=f"Hardcoded secret detected: {label}",
                    category=Category.SOURCE,
                    severity=sev,
                    detail=(
                        f"A hardcoded {label} was found in source code. Hardcoded credentials "
                        "in source files are exposed to anyone who clones the repository, "
                        "including in git history after deletion. This credential may be used "
                        "to access external services, cloud infrastructure, or databases. "
                        "Credentials must never be committed to source control."
                    ),
                    evidence=f"File: {filepath}  Pattern: {label}  (value redacted for safety)",
                    check_name=f"HARDCODED_SECRET",
                ))
                fired_checks.add(f"SECRET_{label}")
                break  # One finding per file is enough for secrets

        # ── Dangerous code patterns ────────────────────────────────────────
        for pattern, label, sev in _DANGEROUS_CODE_PATTERNS:
            check_key = f"CODE_{label[:20]}"
            if check_key in fired_checks:
                continue
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                check_id_map = {
                    "eval()": 58, "exec()": 59, "subprocess": 70, "os.system": 71,
                    "os.popen": 72, "/etc/passwd": 80, "/etc/shadow": 80,
                    "~/.ssh": 85, "~/.aws": 87, "crontab": 73, "systemctl": 74,
                    "HKEY_": 75, "LaunchAgent": 76, "keylogging": 85,
                    "reverse shell": 79, "curl pipe": 80, "wget pipe": 80,
                    "cryptomining": 81, "clipboard": 84, "screen capture": 83,
                }
                cid = 70  # Default
                for key, val in check_id_map.items():
                    if key.lower() in label.lower():
                        cid = val
                        break

                findings.append(Finding(
                    check_id=cid,
                    name=f"Dangerous code pattern: {label}",
                    category=Category.SOURCE,
                    severity=sev,
                    detail=(
                        f"Source code contains a dangerous pattern: {label}. "
                        "This pattern is associated with malicious behavior including "
                        "credential theft, system compromise, persistence installation, "
                        "or arbitrary code execution. The presence of this pattern in "
                        "open-source code warrants manual review before installation."
                    ),
                    evidence=f"File: {filepath}  Matches: {len(matches)}",
                    check_name=f"DANGEROUS_PATTERN_{label[:30].upper().replace(' ', '_')}",
                ))
                fired_checks.add(check_key)

        # ── Hardcoded IP addresses ─────────────────────────────────────────
        if "HARDCODED_IP" not in fired_checks:
            ips = re.findall(
                r'(?<![.\d])(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}(?![.\d])',
                content
            )
            # Filter out common non-malicious IPs
            real_ips = [ip for ip in ips if ip not in (
                "127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.0.0",
                "10.0.0.0", "172.16.0.0", "8.8.8.8", "1.1.1.1"
            )]
            if real_ips:
                findings.append(Finding(
                    check_id=63,
                    name=f"Hardcoded IP addresses in source ({len(real_ips)} found)",
                    category=Category.SOURCE,
                    severity=Severity.MEDIUM,
                    detail=(
                        "Source code contains hardcoded IP addresses. Malicious code "
                        "frequently hardcodes command-and-control server IPs, exfiltration "
                        "endpoints, or malicious download sources. Legitimate applications "
                        "typically use domain names or configuration — not raw IPs."
                    ),
                    evidence=f"File: {filepath}  IPs: {', '.join(set(real_ips[:5]))}",
                    check_name="HARDCODED_IP_ADDRESSES",
                ))
                fired_checks.add("HARDCODED_IP")

    return findings
