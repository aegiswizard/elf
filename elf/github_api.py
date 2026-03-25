"""
Elf 🧝 — GitHub API Client
All GitHub REST API calls. Read-only. Rate-limit aware.
"""

import re
import time
from typing import Optional
import urllib.request
import urllib.error
import json


GITHUB_API = "https://api.github.com"


def _parse_repo_url(url: str) -> tuple:
    url = url.strip().rstrip("/").rstrip(".git")
    if "github.com" in url:
        path = url.split("github.com/", 1)[-1]
    else:
        path = url
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(
            f"Cannot parse GitHub repo from '{url}'. "
            "Expected: https://github.com/owner/repo"
        )
    return parts[0], parts[1]


def _get(url: str, token: Optional[str] = None, accept: str = "application/vnd.github+json") -> Optional[dict]:
    headers = {
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "elf-security-scanner/1.0.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                remaining = resp.headers.get("X-RateLimit-Remaining", "60")
                if int(remaining) < 5:
                    reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                    wait = max(reset - time.time(), 1) + 2
                    time.sleep(wait)
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429):
                time.sleep(2 ** attempt * 5)
                continue
            if e.code == 401:
                raise ValueError("GitHub token invalid or expired.") from e
            return None
        except Exception:
            time.sleep(2 ** attempt)
    return None


def _get_list(url: str, token: Optional[str] = None, max_pages: int = 5) -> list:
    """Paginate through list endpoints."""
    results = []
    page = 1
    while page <= max_pages:
        paged = f"{url}{'&' if '?' in url else '?'}per_page=100&page={page}"
        data = _get(paged, token)
        if not data or not isinstance(data, list) or len(data) == 0:
            break
        results.extend(data)
        if len(data) < 100:
            break
        page += 1
    return results


def _get_raw(url: str, token: Optional[str] = None) -> Optional[str]:
    """Fetch raw text content (e.g. file contents, workflow files)."""
    headers = {
        "Accept": "application/vnd.github.raw+json",
        "User-Agent": "elf-security-scanner/1.0.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


class GitHubAPI:
    def __init__(self, token: Optional[str] = None):
        self.token = token

    # ── Repo ────────────────────────────────────────────────────────────────

    def get_repo(self, owner: str, repo: str) -> Optional[dict]:
        return _get(f"{GITHUB_API}/repos/{owner}/{repo}", self.token)

    def get_owner(self, username: str) -> Optional[dict]:
        return _get(f"{GITHUB_API}/users/{username}", self.token)

    def get_org(self, org: str) -> Optional[dict]:
        return _get(f"{GITHUB_API}/orgs/{org}", self.token)

    # ── Contributors / collaborators ────────────────────────────────────────

    def get_contributors(self, owner: str, repo: str) -> list:
        return _get_list(f"{GITHUB_API}/repos/{owner}/{repo}/contributors", self.token)

    def get_collaborators(self, owner: str, repo: str) -> list:
        return _get_list(f"{GITHUB_API}/repos/{owner}/{repo}/collaborators", self.token)

    # ── Commits ─────────────────────────────────────────────────────────────

    def get_commits(self, owner: str, repo: str, max_pages: int = 2) -> list:
        return _get_list(f"{GITHUB_API}/repos/{owner}/{repo}/commits", self.token, max_pages)

    def get_commit(self, owner: str, repo: str, sha: str) -> Optional[dict]:
        return _get(f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}", self.token)

    # ── Releases ────────────────────────────────────────────────────────────

    def get_releases(self, owner: str, repo: str) -> list:
        return _get_list(f"{GITHUB_API}/repos/{owner}/{repo}/releases", self.token, max_pages=2)

    def get_latest_release(self, owner: str, repo: str) -> Optional[dict]:
        return _get(f"{GITHUB_API}/repos/{owner}/{repo}/releases/latest", self.token)

    # ── Tags ────────────────────────────────────────────────────────────────

    def get_tags(self, owner: str, repo: str) -> list:
        return _get_list(f"{GITHUB_API}/repos/{owner}/{repo}/tags", self.token, max_pages=1)

    # ── Contents ────────────────────────────────────────────────────────────

    def get_contents(self, owner: str, repo: str, path: str = "") -> Optional[list]:
        return _get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", self.token)

    def get_file_text(self, owner: str, repo: str, path: str) -> Optional[str]:
        return _get_raw(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", self.token)

    def file_exists(self, owner: str, repo: str, path: str) -> bool:
        result = _get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", self.token)
        return result is not None

    # ── Workflows ───────────────────────────────────────────────────────────

    def get_workflows(self, owner: str, repo: str) -> list:
        data = _get(f"{GITHUB_API}/repos/{owner}/{repo}/actions/workflows", self.token)
        return data.get("workflows", []) if data else []

    def get_workflow_runs(self, owner: str, repo: str) -> list:
        data = _get(f"{GITHUB_API}/repos/{owner}/{repo}/actions/runs", self.token)
        return data.get("workflow_runs", []) if data else []

    # ── Security ────────────────────────────────────────────────────────────

    def get_vulnerability_alerts(self, owner: str, repo: str) -> list:
        data = _get(
            f"{GITHUB_API}/repos/{owner}/{repo}/vulnerability-alerts",
            self.token,
            accept="application/vnd.github+json",
        )
        return data if isinstance(data, list) else []

    # ── Stars / stargazers ──────────────────────────────────────────────────

    def get_stargazers_sample(self, owner: str, repo: str, limit: int = 100) -> list:
        """Sample stargazers with starred_at timestamp."""
        headers_accept = "application/vnd.github.star+json"
        url = f"{GITHUB_API}/repos/{owner}/{repo}/stargazers?per_page={min(limit, 100)}"
        result = _get(url, self.token, accept=headers_accept)
        return result if isinstance(result, list) else []

    # ── Submodules ──────────────────────────────────────────────────────────

    def get_submodules_file(self, owner: str, repo: str) -> Optional[str]:
        return self.get_file_text(owner, repo, ".gitmodules")

    # ── Raw workflow files ──────────────────────────────────────────────────

    def get_workflow_files(self, owner: str, repo: str) -> list:
        """Return list of (filename, content) for all workflow YAML files."""
        contents = self.get_contents(owner, repo, ".github/workflows")
        if not contents or not isinstance(contents, list):
            return []
        results = []
        for item in contents:
            name = item.get("name", "")
            if name.endswith(".yml") or name.endswith(".yaml"):
                text = self.get_file_text(owner, repo, item.get("path", ""))
                if text:
                    results.append((name, text))
        return results

    # ── Package files ───────────────────────────────────────────────────────

    def get_package_files(self, owner: str, repo: str) -> dict:
        """Fetch all relevant package/dependency files as text."""
        files = {}
        targets = [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg",
            "Cargo.toml", "Cargo.lock",
            "go.mod", "go.sum",
            "Gemfile", "Gemfile.lock",
            "composer.json", "composer.lock",
            "pom.xml", "build.gradle", "build.gradle.kts",
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
            "Makefile", "CMakeLists.txt",
        ]
        for fname in targets:
            text = self.get_file_text(owner, repo, fname)
            if text:
                files[fname] = text
        return files

    # ── README and docs ─────────────────────────────────────────────────────

    def get_readme(self, owner: str, repo: str) -> Optional[str]:
        for name in ["README.md", "README.rst", "README.txt", "README", "readme.md"]:
            text = self.get_file_text(owner, repo, name)
            if text:
                return text
        return None

    def get_doc_files(self, owner: str, repo: str) -> dict:
        """Fetch documentation files for agent safety scanning."""
        files = {}
        targets = [
            "README.md", "CONTRIBUTING.md", "SECURITY.md",
            "INSTALL.md", "USAGE.md", "docs/README.md",
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/pull_request_template.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
        ]
        for fname in targets:
            text = self.get_file_text(owner, repo, fname)
            if text:
                files[fname] = text
        return files

    # ── Attestations ────────────────────────────────────────────────────────

    def get_attestations(self, owner: str, repo: str) -> list:
        data = _get(f"{GITHUB_API}/repos/{owner}/{repo}/attestations", self.token)
        return data.get("attestations", []) if data and isinstance(data, dict) else []

    # ── Recent events / activity ────────────────────────────────────────────

    def get_events(self, owner: str, repo: str) -> list:
        return _get_list(f"{GITHUB_API}/repos/{owner}/{repo}/events", self.token, max_pages=1)

    # ── Transfer history (indirect signals) ─────────────────────────────────

    def get_repo_topics(self, owner: str, repo: str) -> list:
        data = _get(
            f"{GITHUB_API}/repos/{owner}/{repo}/topics", self.token,
            accept="application/vnd.github+json"
        )
        return data.get("names", []) if data else []

    @staticmethod
    def parse_url(url: str) -> tuple:
        return _parse_repo_url(url)
