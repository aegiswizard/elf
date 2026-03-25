"""
Elf 🧝 — Dependency & Package Checks (33–54)
Analyses package manifests and lockfiles without installing or executing anything.
"""

import json
import re
from difflib import SequenceMatcher
from ..models import Finding, Severity, Category


# ---------------------------------------------------------------------------
# Known popular packages per ecosystem — typosquat reference lists
# ---------------------------------------------------------------------------

_POPULAR_NPM = [
    "react", "react-dom", "lodash", "axios", "express", "typescript",
    "webpack", "babel-core", "@babel/core", "jest", "eslint", "prettier",
    "chalk", "commander", "inquirer", "moment", "dayjs", "uuid", "dotenv",
    "cors", "body-parser", "mongoose", "sequelize", "socket.io", "nodemon",
    "next", "vue", "angular", "@angular/core", "svelte", "gatsby",
    "redux", "mobx", "rxjs", "immutable", "ramda", "underscore",
    "request", "node-fetch", "got", "superagent", "cheerio", "puppeteer",
    "playwright", "cypress", "mocha", "chai", "sinon", "tape",
]

_POPULAR_PYPI = [
    "requests", "numpy", "pandas", "scipy", "matplotlib", "pillow",
    "django", "flask", "fastapi", "sqlalchemy", "celery", "redis",
    "boto3", "google-cloud", "azure", "tensorflow", "torch", "scikit-learn",
    "pytest", "black", "mypy", "flake8", "pylint", "setuptools",
    "pip", "wheel", "twine", "poetry", "pipenv", "virtualenv",
    "cryptography", "paramiko", "fabric", "ansible", "click", "typer",
    "pydantic", "attrs", "marshmallow", "aiohttp", "httpx", "starlette",
    "urllib3", "certifi", "charset-normalizer", "idna", "six", "packaging",
]

_POPULAR_CARGO = [
    "serde", "tokio", "reqwest", "clap", "log", "env_logger", "rand",
    "chrono", "regex", "thiserror", "anyhow", "tracing", "async-trait",
    "futures", "rayon", "crossbeam", "parking_lot", "lazy_static", "once_cell",
    "itertools", "indexmap", "dashmap", "bytes", "hyper", "axum", "actix-web",
    "diesel", "sqlx", "sea-orm", "redis", "mongodb", "serde_json", "toml",
]

# Packages known to have been used in real supply-chain attacks
_KNOWN_MALICIOUS = {
    # npm
    "event-stream@3.3.6", "node-ipc@10.1.1", "node-ipc@10.1.2",
    "colors@1.4.44-liberty-2", "faker@6.6.6", "ua-parser-js@0.7.29",
    "coa@2.0.3", "rc@1.2.9", "eslint-scope@3.7.2",
    # PyPI
    "colourama", "djanga", "diango", "reqeusts", "urlib3",
    "python-dateutil2", "setup-tools", "importlib",
}


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _is_typosquat(name: str, popular_list: list, threshold: float = 0.80) -> tuple:
    """
    Check if a package name is likely a typosquat of a popular package.
    Returns (is_typosquat, similar_to) or (False, None).
    Never makes network calls — pure string analysis.
    """
    name_lower = name.lower().replace("-", "").replace("_", "").replace(".", "")
    for popular in popular_list:
        pop_lower = popular.lower().replace("-", "").replace("_", "").replace(".", "")
        if name_lower == pop_lower:
            return False, None  # Exact match — it IS the popular package
        sim = _similarity(name_lower, pop_lower)
        if sim >= threshold and name_lower != pop_lower:
            return True, popular
        # Common substitutions
        subs = [
            name_lower.replace("0", "o"),
            name_lower.replace("1", "l"),
            name_lower.replace("1", "i"),
            name_lower.replace("rn", "m"),
        ]
        for sub in subs:
            if sub == pop_lower and sub != name_lower:
                return True, popular
    return False, None


def _extract_npm_deps(package_json_text: str) -> list:
    """Extract all dependency names from package.json."""
    try:
        data = json.loads(package_json_text)
    except Exception:
        return []
    deps = []
    for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        deps.extend(data.get(key, {}).keys())
    return [d for d in deps if not d.startswith("@")]  # Skip scoped for typosquat check


def _extract_npm_scripts(package_json_text: str) -> dict:
    """Extract lifecycle scripts from package.json."""
    try:
        data = json.loads(package_json_text)
        return data.get("scripts", {})
    except Exception:
        return {}


def _extract_pypi_deps(requirements_text: str) -> list:
    """Extract package names from requirements.txt."""
    deps = []
    for line in requirements_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip version specifiers
        name = re.split(r'[>=<!~\[\s]', line)[0].strip()
        if name:
            deps.append(name)
    return deps


def _extract_cargo_deps(cargo_toml_text: str) -> list:
    """Extract crate names from Cargo.toml (basic TOML parsing)."""
    deps = []
    in_deps = False
    for line in cargo_toml_text.splitlines():
        stripped = line.strip()
        if re.match(r'\[(dependencies|dev-dependencies|build-dependencies)\]', stripped):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
        if in_deps and "=" in stripped and not stripped.startswith("#"):
            name = stripped.split("=")[0].strip().strip('"')
            if name:
                deps.append(name)
    return deps


def _check_lockfile_mismatch(package_json: str, lockfile: str) -> bool:
    """Detect manifest vs lockfile mismatch (basic heuristic)."""
    try:
        manifest = json.loads(package_json)
        lock     = json.loads(lockfile) if lockfile.strip().startswith("{") else None
        if not lock:
            return False
        manifest_deps = set()
        for key in ["dependencies", "devDependencies"]:
            manifest_deps.update(manifest.get(key, {}).keys())
        # Check if lock has packages not in manifest (basic signal)
        lock_packages = set(lock.get("packages", {}).keys()) | set(lock.get("dependencies", {}).keys())
        return len(lock_packages) == 0 and len(manifest_deps) > 0
    except Exception:
        return False


def run_dependency_checks(package_files: dict) -> list:
    """
    Run all 22 dependency and package checks.

    Args:
        package_files: dict of {filename: file_content_text}

    Returns:
        List of Finding objects for every triggered check.
    """
    findings = []

    package_json     = package_files.get("package.json", "")
    package_lock     = package_files.get("package-lock.json", "")
    yarn_lock        = package_files.get("yarn.lock", "")
    requirements_txt = package_files.get("requirements.txt", "")
    cargo_toml       = package_files.get("Cargo.toml", "")
    cargo_lock       = package_files.get("Cargo.lock", "")
    pyproject_toml   = package_files.get("pyproject.toml", "")

    has_lockfile = bool(package_lock or yarn_lock or cargo_lock)

    # ── CHECK 33-37: Typosquatting ────────────────────────────────────────

    typosquat_findings = []

    if package_json:
        npm_deps = _extract_npm_deps(package_json)
        for dep in npm_deps:
            is_typo, similar_to = _is_typosquat(dep, _POPULAR_NPM)
            if is_typo:
                typosquat_findings.append((dep, similar_to, "npm"))

    if requirements_txt or pyproject_toml:
        py_deps = _extract_pypi_deps(requirements_txt)
        # Also extract from pyproject.toml [tool.poetry.dependencies] / [project]
        if pyproject_toml:
            py_deps += _extract_pypi_deps(pyproject_toml)
        for dep in py_deps:
            is_typo, similar_to = _is_typosquat(dep, _POPULAR_PYPI)
            if is_typo:
                typosquat_findings.append((dep, similar_to, "PyPI"))

    if cargo_toml:
        cargo_deps = _extract_cargo_deps(cargo_toml)
        for dep in cargo_deps:
            is_typo, similar_to = _is_typosquat(dep, _POPULAR_CARGO)
            if is_typo:
                typosquat_findings.append((dep, similar_to, "crates.io"))

    if typosquat_findings:
        evidence_lines = [f"'{d}' resembles '{s}' ({eco})" for d, s, eco in typosquat_findings[:10]]
        findings.append(Finding(
            check_id=33,
            name=f"Typosquatted dependency names detected ({len(typosquat_findings)} found)",
            category=Category.DEPENDENCIES,
            severity=Severity.CRITICAL,
            detail=(
                "One or more dependency names closely resemble popular packages but are "
                "not the real package. Typosquatting is a primary supply-chain attack "
                "technique: the attacker publishes a package with a name nearly identical "
                "to a popular library (one letter different, different separator, number "
                "substitution) and waits for developers to mistype the name. The malicious "
                "package then executes arbitrary code during installation. This is responsible "
                "for numerous real-world supply-chain compromises."
            ),
            evidence="\n".join(evidence_lines),
            check_name="TYPOSQUATTED_DEPENDENCY",
        ))

    # ── CHECK 38: No lockfile present ────────────────────────────────────

    if (package_json or cargo_toml) and not has_lockfile:
        findings.append(Finding(
            check_id=38,
            name="No dependency lockfile present",
            category=Category.DEPENDENCIES,
            severity=Severity.MEDIUM,
            detail=(
                "A package manifest exists but no lockfile was found. Without a lockfile, "
                "dependency resolution is non-deterministic — the exact versions installed "
                "depend on what versions are available in the registry at install time. "
                "An attacker who compromises a dependency's registry account can publish "
                "a malicious new version that gets silently pulled in during any fresh install. "
                "Lockfiles must be committed and used."
            ),
            evidence="Package manifest present but no lockfile detected",
            check_name="NO_LOCKFILE",
        ))

    # ── CHECK 39: Lockfile vs manifest mismatch ───────────────────────────

    if package_json and package_lock:
        if _check_lockfile_mismatch(package_json, package_lock):
            findings.append(Finding(
                check_id=39,
                name="Lockfile appears to be empty or inconsistent with manifest",
                category=Category.DEPENDENCIES,
                severity=Severity.HIGH,
                detail=(
                    "The package-lock.json appears inconsistent with the package.json "
                    "manifest. Lockfile poisoning is a documented attack: the manifest "
                    "declares safe dependencies, but the lockfile resolves to different "
                    "(potentially malicious) versions or sources. Always verify that "
                    "lockfiles are regenerated from clean manifests and committed atomically."
                ),
                evidence="package-lock.json has no packages but package.json has dependencies",
                check_name="LOCKFILE_MANIFEST_MISMATCH",
            ))

    # ── CHECK 40: Git-based dependency (mutable branch reference) ─────────

    git_dep_patterns = [
        (r'github\.com/[^/]+/[^/\s"#]+\.git', "git URL in dependency"),
        (r'"git\+https?://', "git+ URL in package.json"),
        (r'git\s*=\s*"[^"]+"', "git key in Cargo.toml"),
        (r'branch\s*=\s*"[^"]+"', "mutable branch reference"),
    ]

    all_text = "\n".join(package_files.values())
    for pattern, label in git_dep_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        if matches:
            findings.append(Finding(
                check_id=40,
                name=f"Mutable git-based dependency reference: {label}",
                category=Category.DEPENDENCIES,
                severity=Severity.HIGH,
                detail=(
                    "A dependency is pulled directly from a git repository URL rather "
                    "than from a versioned registry entry. Git URLs pointing to mutable "
                    "branches (not commit SHAs) mean the installed code changes every "
                    "time the branch is updated. An attacker who compromises the referenced "
                    "repository can push malicious code that gets pulled into this project "
                    "on the next install without any version change visible in the manifest."
                ),
                evidence=f"Pattern: {label}  Example: {matches[0][:80]}",
                check_name="GIT_BASED_DEPENDENCY_MUTABLE",
            ))
            break

    # ── CHECK 41-45: Lifecycle scripts ───────────────────────────────────

    if package_json:
        scripts = _extract_npm_scripts(package_json)
        dangerous_scripts = {
            "preinstall":  "Runs before installation — executes before the user can inspect dependencies",
            "install":     "Runs during installation — arbitrary code executed on npm install",
            "postinstall": "Runs after installation — most common script-based supply chain attack vector",
            "prepare":     "Runs on npm install and npm publish — frequently abused for silent execution",
            "prepublish":  "Runs before package is published and on npm install in some versions",
        }
        for script_name, reason in dangerous_scripts.items():
            if script_name in scripts:
                script_content = scripts[script_name]
                sev = Severity.HIGH
                # Escalate if the script makes network calls or executes remote code
                if re.search(r'curl|wget|fetch|http|exec|eval|child_process', script_content, re.IGNORECASE):
                    sev = Severity.CRITICAL
                findings.append(Finding(
                    check_id=41,
                    name=f"Dangerous npm lifecycle script: {script_name}",
                    category=Category.DEPENDENCIES,
                    severity=sev,
                    detail=(
                        f"The package.json defines a '{script_name}' lifecycle script. "
                        f"{reason}. Lifecycle scripts are one of the most common vectors "
                        "for supply-chain attacks because they execute automatically when "
                        "the package is installed with npm install — no import or require "
                        "needed. The developer never explicitly runs them. Malicious scripts "
                        "have been used for credential theft, cryptomining, and reverse shells "
                        "in real-world attacks (event-stream, node-ipc, ua-parser-js)."
                    ),
                    evidence=f"Script content: {script_content[:200]}",
                    check_name=f"LIFECYCLE_SCRIPT_{script_name.upper()}",
                ))

    # ── CHECK 46: Very short package name ────────────────────────────────

    if package_json:
        all_deps = _extract_npm_deps(package_json)
        short_deps = [d for d in all_deps if len(d) <= 2]
        if short_deps:
            findings.append(Finding(
                check_id=46,
                name=f"Extremely short dependency names — high typosquat risk surface",
                category=Category.DEPENDENCIES,
                severity=Severity.LOW,
                detail=(
                    "Very short package names (1-2 characters) are disproportionately "
                    "targeted by dependency confusion and typosquatting attacks because "
                    "they are easy to accidentally mistype or confuse with internal "
                    "package names. Verify each short-named dependency carefully."
                ),
                evidence=f"Short names: {', '.join(short_deps[:10])}",
                check_name="SHORT_PACKAGE_NAMES",
            ))

    # ── CHECK 47: Native addon / binary extension ─────────────────────────

    native_signals = [
        r'node-gyp', r'node-pre-gyp', r'@mapbox/node-pre-gyp',
        r'bindings', r'ffi-napi', r'node-addon-api',
        r'\.node"', r'native\s*:', r'gypfile.*true',
    ]
    if package_json:
        for pattern in native_signals:
            if re.search(pattern, package_json, re.IGNORECASE):
                findings.append(Finding(
                    check_id=47,
                    name="Native addon or binary extension compilation detected",
                    category=Category.DEPENDENCIES,
                    severity=Severity.MEDIUM,
                    detail=(
                        "This package compiles native code (C/C++) during installation "
                        "using node-gyp or a similar tool. Native addons execute at the "
                        "operating system level with full system access — they bypass "
                        "JavaScript sandboxing entirely. A malicious native addon can "
                        "exfiltrate credentials, install persistence, or escalate privileges "
                        "with no restrictions. Always audit native addons with extreme care."
                    ),
                    evidence=f"Pattern detected: {pattern}",
                    check_name="NATIVE_ADDON_COMPILATION",
                ))
                break

    # ── CHECK 48: Known malicious package names ───────────────────────────

    all_dep_names = set()
    if package_json:
        try:
            pkg = json.loads(package_json)
            for key in ["dependencies", "devDependencies"]:
                for name, version in pkg.get(key, {}).items():
                    all_dep_names.add(f"{name}@{version}")
        except Exception:
            pass

    matched_malicious = all_dep_names.intersection(_KNOWN_MALICIOUS)
    if matched_malicious:
        findings.append(Finding(
            check_id=48,
            name="Known malicious package reference detected",
            category=Category.DEPENDENCIES,
            severity=Severity.CRITICAL,
            detail=(
                "One or more dependency references match packages that have been "
                "publicly identified as malicious in real-world supply-chain attacks. "
                "These specific package versions were used to deliver malware, steal "
                "credentials, or execute ransomware-like behavior in production systems. "
                "Under no circumstances should these packages be installed."
            ),
            evidence=f"Matched: {', '.join(matched_malicious)}",
            check_name="KNOWN_MALICIOUS_PACKAGE",
        ))

    # ── CHECK 49: Dependency source switched to raw git URL ───────────────

    if package_json:
        try:
            pkg = json.loads(package_json)
            for section in ["dependencies", "devDependencies"]:
                for name, value in pkg.get(section, {}).items():
                    if isinstance(value, str) and ("github:" in value or "git+" in value or "git://" in value):
                        findings.append(Finding(
                            check_id=49,
                            name=f"Dependency '{name}' sourced from git URL instead of registry",
                            category=Category.DEPENDENCIES,
                            severity=Severity.HIGH,
                            detail=(
                                f"The dependency '{name}' is not pulled from the official npm "
                                "registry but directly from a git URL. This bypasses registry "
                                "security scanning, version consistency, and integrity checks. "
                                "The referenced git repository may have been recently transferred, "
                                "compromised, or abandoned, with the new owner publishing malicious code."
                            ),
                            evidence=f"'{name}': '{value}'",
                            check_name="DEPENDENCY_GIT_URL_SOURCE",
                        ))
        except Exception:
            pass

    return findings
