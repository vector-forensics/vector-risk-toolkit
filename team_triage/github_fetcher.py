"""Vector (SG) — Public GitHub REST API Snapshot Fetcher (Stdlib Only).

Fetches strictly public GitHub metadata (org/user profiles, public repos, recent commits,
recent pull requests) and freezes them into a deterministic snapshot JSON with immediate
PII email scrubbing (domain + SHA-256 hash only; raw email strings are NEVER written to disk).
"""
from __future__ import annotations

import datetime
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .signals import scrub_email

GITHUB_API = "https://api.github.com"


def _gh_get(path: str, token: Optional[str] = None, timeout: int = 15) -> Any:
    url = path if path.startswith("http") else f"{GITHUB_API}{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Vector-SG-TrackB-Triage/1.0",
    }
    tok = token or os.environ.get("GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_public_github_snapshot(
    target_name: str,
    repos: List[str],
    declared_addresses: Optional[List[Dict[str, str]]] = None,
    max_commits_per_repo: int = 25,
    max_prs_per_repo: int = 20,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch public GitHub metadata for declared `owner/repo` targets and freeze snapshot."""
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    repo_records: List[Dict[str, Any]] = []
    commit_records: List[Dict[str, Any]] = []
    pr_records: List[Dict[str, Any]] = []
    contributor_logins: set = set()
    fetch_warnings: List[str] = []

    for full_name in repos:
        fn = full_name.strip().strip("/")
        if "/" not in fn:
            fetch_warnings.append(f"Skipped invalid repo format: {fn}")
            continue
        try:
            r = _gh_get(f"/repos/{fn}", token=token)
        except Exception as exc:
            fetch_warnings.append(f"Failed fetching repo {fn}: {exc}")
            continue

        # Pull requests (state=all)
        prs_raw: List[Dict[str, Any]] = []
        try:
            prs_raw = _gh_get(f"/repos/{fn}/pulls?state=all&per_page={max_prs_per_repo}", token=token)
        except Exception as exc:
            fetch_warnings.append(f"Failed fetching PRs for {fn}: {exc}")

        for pr in prs_raw:
            pr_records.append({
                "repo": fn,
                "number": pr.get("number"),
                "url": pr.get("html_url", ""),
                "created_at": pr.get("created_at", ""),
                "approved_at": pr.get("merged_at") or "",
                "author_login": ((pr.get("user") or {}).get("login") or "").lower(),
            })

        repo_records.append({
            "full_name": r.get("full_name", fn),
            "html_url": r.get("html_url", f"https://github.com/{fn}"),
            "created_at": r.get("created_at", ""),
            "is_fork": bool(r.get("fork", False)),
            "stargazers_count": int(r.get("stargazers_count", 0)),
            "open_issues_count": int(r.get("open_issues_count", 0)),
            "closed_issues_count": 0,
            "pr_count": len(prs_raw),
            "is_core_claimed": True,
        })

        # Recent commits
        try:
            commits_raw = _gh_get(f"/repos/{fn}/commits?per_page={max_commits_per_repo}", token=token)
        except Exception as exc:
            fetch_warnings.append(f"Failed fetching commits for {fn}: {exc}")
            commits_raw = []

        for c in commits_raw:
            cm = c.get("commit") or {}
            author_obj = cm.get("author") or {}
            committer_obj = cm.get("committer") or {}
            ae = scrub_email(author_obj.get("email"))
            ce = scrub_email(committer_obj.get("email"))
            a_login = ((c.get("author") or {}).get("login") or "").lower()
            c_login = ((c.get("committer") or {}).get("login") or "").lower()
            if a_login:
                contributor_logins.add(a_login)
            commit_records.append({
                "repo": fn,
                "sha": c.get("sha", ""),
                "url": c.get("html_url", ""),
                "author_login": a_login,
                "committer_login": c_login,
                "author_email_hash": ae["email_hash"],
                "author_email_domain": ae["email_domain"],
                "committer_email_hash": ce["email_hash"],
                "committer_email_domain": ce["email_domain"],
                "timestamp": author_obj.get("date") or committer_obj.get("date") or "",
                "verified": bool(((cm.get("verification") or {}).get("verified"))),
                "additions": 0,
                "deletions": 0,
                "message": (cm.get("message") or "")[:400],
            })

    contributor_records: List[Dict[str, Any]] = []
    for login in sorted(contributor_logins)[:15]:
        try:
            u = _gh_get(f"/users/{login}", token=token)
            ext_repos: List[str] = []
            try:
                urepos = _gh_get(f"/users/{login}/repos?per_page=15&sort=updated", token=token)
                ext_repos = [ur.get("full_name", "") for ur in urepos if ur.get("full_name")]
            except Exception:
                pass
            contributor_records.append({
                "login": login,
                "html_url": u.get("html_url", f"https://github.com/{login}"),
                "created_at": u.get("created_at", ""),
                "public_repos": int(u.get("public_repos", 0)),
                "followers": int(u.get("followers", 0)),
                "external_repos": ext_repos,
            })
        except Exception as exc:
            fetch_warnings.append(f"Failed fetching user {login}: {exc}")

    return {
        "target_name": target_name,
        "snapshot_utc": now_utc,
        "source_mode": "public_github_rest_api",
        "fetch_warnings": fetch_warnings,
        "repos": repo_records,
        "contributors": contributor_records,
        "commits": commit_records,
        "pull_requests": pr_records,
        "declared_addresses": declared_addresses or [],
    }
