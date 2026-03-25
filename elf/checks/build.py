"""
Elf 🧝 — Build System Checks (89–100)
Analyses build scripts for install-time execution risks.
Never executes any build script — pure static text analysis.
"""

import re
from ..models import Finding, Severity, Category


_DOWNLOAD_EXECUTE_PATTERNS = [
    r'curl\s+[^\n]*\|\s*(?:bash|sh|python|perl|ruby|node)',
    r'wget\s+[^\n]*\|\s*(?:bash|sh|python)',
    r'fetch\s+[^\n]*\|\s*(?:bash|sh)',
    r'powershell.*DownloadString.*iex',
    r'Invoke-Expression.*DownloadString',
    r'iex\s*\(\s*New-Object.*WebClient\)',
]

_NETWORK_PATTERNS = [
    r'https?://[^\s"\']+',
    r'curl\s+', r'wget\s+', r'fetch\s+',
    r'urllib\.request', r'requests\.get',
    r'net/http', r'HttpClient', r'WebClient',
]

_PERSISTENCE_PATTERNS = [
    r'crontab', r'/etc/cron\.', r'at\s+-f',
    r'systemctl\s+enable', r'service\s+\w+\s+start',
    r'HKEY_.*\\Run', r'reg\s+add.*Run',
    r'LaunchAgent', r'LaunchDaemon',
    r'~/.bashrc', r'~/.bash_profile', r'~/.zshrc', r'~/.profile',
    r'/etc/profile', r'/etc/rc\.local',
]


def run_build_checks(package_files: dict) -> list:
    """
    Run all 12 build system checks.
    Never executes any build script.

    Args:
        package_files: dict of {filename: content}

    Returns:
        List of Finding objects.
    """
    findings = []
    fired = set()

    setup_py      = package_files.get("setup.py", "")
    makefile      = package_files.get("Makefile", "")
    cmake         = package_files.get("CMakeLists.txt", "")
    package_json  = package_files.get("package.json", "")
    cargo_toml    = package_files.get("Cargo.toml", "")
    dockerfile    = package_files.get("Dockerfile", "")
    docker_compose = package_files.get("docker-compose.yml", "") or package_files.get("docker-compose.yaml", "")

    # ── CHECK 89: setup.py with network calls or shell execution ─────────

    if setup_py:
        for pattern in _NETWORK_PATTERNS + _DOWNLOAD_EXECUTE_PATTERNS:
            if re.search(pattern, setup_py, re.IGNORECASE):
                findings.append(Finding(
                    check_id=89,
                    name="setup.py makes network calls or shell execution during install",
                    category=Category.BUILD,
                    severity=Severity.CRITICAL,
                    detail=(
                        "The setup.py file contains code that makes network requests or "
                        "executes shell commands. Python's setup.py runs automatically during "
                        "'pip install' — before the user has any opportunity to inspect the "
                        "code being executed. Any network call in setup.py can be used to "
                        "download and execute a second-stage payload, exfiltrate environment "
                        "variables or credentials, or install persistence. This is one of the "
                        "most common real-world PyPI supply-chain attack vectors."
                    ),
                    evidence=f"Pattern found: {pattern}",
                    check_name="SETUP_PY_NETWORK_OR_EXEC",
                ))
                fired.add("SETUP_PY")
                break

    # ── CHECK 90: Makefile download and execute pattern ───────────────────

    if makefile:
        for pattern in _DOWNLOAD_EXECUTE_PATTERNS:
            if re.search(pattern, makefile, re.IGNORECASE) and "MAKEFILE" not in fired:
                findings.append(Finding(
                    check_id=90,
                    name="Makefile contains download-and-execute pattern",
                    category=Category.BUILD,
                    severity=Severity.HIGH,
                    detail=(
                        "The Makefile contains a pattern that downloads content from a "
                        "remote URL and pipes it directly to a shell interpreter. This "
                        "is a well-known dangerous pattern ('curl | bash') that executes "
                        "arbitrary remote code with no integrity verification, no sandboxing, "
                        "and no audit trail. The downloaded script runs with full user "
                        "privileges and full network access."
                    ),
                    evidence=f"Pattern: {pattern}",
                    check_name="MAKEFILE_DOWNLOAD_EXECUTE",
                ))
                fired.add("MAKEFILE")
                break

        # Network calls in Makefile (lower severity if no pipe-to-shell)
        if "MAKEFILE" not in fired:
            for pattern in _NETWORK_PATTERNS[:4]:
                if re.search(pattern, makefile, re.IGNORECASE):
                    findings.append(Finding(
                        check_id=90,
                        name="Makefile makes network calls during build",
                        category=Category.BUILD,
                        severity=Severity.MEDIUM,
                        detail=(
                            "The Makefile fetches content from external URLs during the "
                            "build process. Build-time network calls can be used to pull "
                            "in malicious second-stage payloads or to phone home with "
                            "build environment information. Build processes should be "
                            "deterministic and offline wherever possible."
                        ),
                        evidence=f"Pattern: {pattern}",
                        check_name="MAKEFILE_NETWORK_CALL",
                    ))
                    fired.add("MAKEFILE")
                    break

    # ── CHECK 91: CMakeLists.txt fetches external content ─────────────────

    if cmake:
        cmake_fetch_patterns = [
            r'FetchContent_Declare', r'ExternalProject_Add',
            r'file\s*\(\s*DOWNLOAD', r'execute_process.*curl',
        ]
        for pattern in cmake_fetch_patterns:
            if re.search(pattern, cmake, re.IGNORECASE) and "CMAKE" not in fired:
                findings.append(Finding(
                    check_id=91,
                    name="CMakeLists.txt fetches external content at build time",
                    category=Category.BUILD,
                    severity=Severity.MEDIUM,
                    detail=(
                        "The CMakeLists.txt uses FetchContent, ExternalProject_Add, or "
                        "file(DOWNLOAD) to pull external content during the build. "
                        "This means the build is non-hermetic and depends on the "
                        "availability and integrity of external sources. An attacker "
                        "who compromises those sources can inject malicious code into "
                        "the build without any change to this repository."
                    ),
                    evidence=f"Pattern: {pattern}",
                    check_name="CMAKE_EXTERNAL_FETCH",
                ))
                fired.add("CMAKE")
                break

    # ── CHECK 92: Dockerfile analysis ────────────────────────────────────

    if dockerfile:
        # RUN with download-and-execute
        for pattern in _DOWNLOAD_EXECUTE_PATTERNS:
            if re.search(pattern, dockerfile, re.IGNORECASE) and "DOCKER_EXEC" not in fired:
                findings.append(Finding(
                    check_id=95,
                    name="Dockerfile RUN instruction downloads and executes remote code",
                    category=Category.BUILD,
                    severity=Severity.CRITICAL,
                    detail=(
                        "A Dockerfile RUN instruction downloads content from a remote URL "
                        "and pipes it to a shell interpreter. This executes arbitrary remote "
                        "code during the container build process with root privileges inside "
                        "the build container. The downloaded script is not version-controlled, "
                        "not integrity-checked, and can change between builds."
                    ),
                    evidence=f"Pattern: {pattern}",
                    check_name="DOCKERFILE_DOWNLOAD_EXECUTE",
                ))
                fired.add("DOCKER_EXEC")
                break

        # Running as root
        if not re.search(r'^USER\s+(?!root)', dockerfile, re.MULTILINE) and "DOCKER_ROOT" not in fired:
            if "FROM" in dockerfile:  # Only flag real Dockerfiles
                findings.append(Finding(
                    check_id=96,
                    name="Dockerfile runs as root — no non-root USER instruction",
                    category=Category.BUILD,
                    severity=Severity.MEDIUM,
                    detail=(
                        "The Dockerfile does not include a USER instruction to switch to a "
                        "non-root user. Container processes running as root have elevated "
                        "privileges inside the container and can escape to the host system "
                        "through container breakout vulnerabilities. All production container "
                        "images should run as a non-root user."
                    ),
                    evidence="No 'USER <non-root>' instruction found in Dockerfile",
                    check_name="DOCKERFILE_RUNS_AS_ROOT",
                ))
                fired.add("DOCKER_ROOT")

    # ── CHECK 97-98: docker-compose analysis ─────────────────────────────

    if docker_compose:
        if re.search(r'privileged\s*:\s*true', docker_compose, re.IGNORECASE):
            findings.append(Finding(
                check_id=97,
                name="docker-compose uses privileged: true",
                category=Category.BUILD,
                severity=Severity.HIGH,
                detail=(
                    "The docker-compose configuration runs one or more containers in "
                    "privileged mode. A privileged container has nearly full access to "
                    "the host system — it can access all devices, modify kernel parameters, "
                    "and escape the container namespace. This setting should never be used "
                    "in production and its presence in a public repository is a serious "
                    "red flag."
                ),
                evidence="privileged: true found in docker-compose file",
                check_name="DOCKER_COMPOSE_PRIVILEGED",
            ))

        sensitive_mounts = re.findall(
            r'volumes:.*?(?=\n\S|\Z)',
            docker_compose, re.DOTALL
        )
        host_mounts = re.findall(
            r'[-\s]+(/etc|/var|/root|/home|/proc|/sys|/dev|/run)\b',
            docker_compose
        )
        if host_mounts:
            findings.append(Finding(
                check_id=98,
                name=f"docker-compose mounts sensitive host paths into container",
                category=Category.BUILD,
                severity=Severity.HIGH,
                detail=(
                    "The docker-compose configuration mounts sensitive host system "
                    "directories (/etc, /var, /root, /proc, etc.) into the container. "
                    "This gives the container process direct access to host system files, "
                    "credentials, configuration, and runtime data. A compromised container "
                    "process can read SSH keys, modify system configuration, or access "
                    "other users' data."
                ),
                evidence=f"Sensitive mounts: {', '.join(set(host_mounts[:5]))}",
                check_name="DOCKER_COMPOSE_SENSITIVE_MOUNTS",
            ))

    # ── CHECK 99: Conditional behavior based on environment ───────────────

    all_build_text = "\n".join(v for k, v in package_files.items()
                               if k in ("setup.py", "Makefile", "CMakeLists.txt"))
    env_conditional_patterns = [
        r'os\.environ\.get\s*\(\s*["\']CI["\']',
        r'if\s+\[?\s*"\$CI"',
        r'if\s+\$ENV{CI}',
        r'process\.env\.CI',
        r'if.*GITHUB_ACTIONS.*then',
        r'if.*TRAVIS.*then',
    ]
    for pattern in env_conditional_patterns:
        if re.search(pattern, all_build_text, re.IGNORECASE) and "ENV_CONDITIONAL" not in fired:
            findings.append(Finding(
                check_id=99,
                name="Build script has conditional behavior based on CI/CD environment",
                category=Category.BUILD,
                severity=Severity.MEDIUM,
                detail=(
                    "The build system checks for CI-specific environment variables and "
                    "behaves differently based on them. This pattern has been observed in "
                    "real supply-chain attacks where malware is only active when running in "
                    "CI/CD environments (where secrets are available) but behaves cleanly "
                    "on developer machines — making local testing appear safe while the "
                    "actual attack occurs in the pipeline."
                ),
                evidence=f"Pattern: {pattern}",
                check_name="CI_CONDITIONAL_BEHAVIOR",
            ))
            fired.add("ENV_CONDITIONAL")
            break

    # ── CHECK 100: Build script overwrites files outside project ──────────

    destructive_patterns = [
        r'rm\s+-[rf]+\s+/',
        r'shutil\.rmtree\s*\(\s*["\']/',
        r'del\s*/[sq]\s+[A-Z]:\\',
        r'Format-Volume',
        r'>\s*/etc/', r'>\s*/usr/',
        r'os\.remove\s*\(\s*["\']/(?!tmp)',
    ]
    for pattern in destructive_patterns:
        if re.search(pattern, all_build_text, re.IGNORECASE) and "DESTRUCTIVE" not in fired:
            findings.append(Finding(
                check_id=100,
                name="Build script contains destructive file operations outside project",
                category=Category.BUILD,
                severity=Severity.CRITICAL,
                detail=(
                    "The build system contains commands that delete or overwrite files "
                    "outside the project directory tree. Legitimate build scripts never "
                    "modify system directories or other users' files. This pattern is "
                    "consistent with wiper malware or sabotage payloads embedded in "
                    "build scripts."
                ),
                evidence=f"Pattern: {pattern}",
                check_name="DESTRUCTIVE_FILE_OPERATIONS",
            ))
            fired.add("DESTRUCTIVE")
            break

    return findings
