import asyncio
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from git import Repo
from urllib.parse import quote

logger = logging.getLogger(__name__)


class PRAgent:
    """Optional PR creation.

    Uses GitPython to branch/commit/push and GitHub REST API to open PR.
    Requires GITHUB_TOKEN.
    """

    async def create_pr_if_possible(
        self,
        local_repo_path: str,
        repo_url: str,
        base_branch: str,
        branch_name: str,
        title: str,
        body: str,
    ) -> Optional[Dict[str, Any]]:
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            return None

        owner, repo = self._parse_owner_repo(repo_url)
        if not owner or not repo:
            logger.warning("Could not parse owner/repo from %s; skipping PR", repo_url)
            return None

        repo_obj = Repo(local_repo_path)
        await asyncio.to_thread(self._git_commit_and_push, repo_obj, repo_url, token, branch_name)

        pr = await asyncio.to_thread(
            self._open_pr,
            token,
            owner,
            repo,
            title,
            body,
            head=branch_name,
            base=base_branch,
        )
        return pr

    def _git_commit_and_push(self, repo_obj: Repo, repo_url: str, token: str, branch_name: str) -> None:
        # Create branch
        if branch_name in [h.name for h in repo_obj.heads]:
            repo_obj.git.checkout(branch_name)
        else:
            repo_obj.git.checkout("-b", branch_name)

        repo_obj.git.add(A=True)
        if not repo_obj.is_dirty():
            logger.info("No changes to commit")
            return

        repo_obj.index.commit("Automated security remediation")

        # Ensure the push uses token-based HTTPS auth (avoids relying on local
        # credential helpers, which can cause confusing 403s in CI/demo envs).
        self._ensure_origin_uses_token(repo_obj, repo_url, token)

        # Push
        try:
            repo_obj.git.push("-u", "origin", branch_name)
        except Exception:
            logger.exception("Failed to push branch")
            raise

    def _ensure_origin_uses_token(self, repo_obj: Repo, repo_url: str, token: str) -> None:
        """Force the `origin` remote to use an x-access-token HTTPS URL.

        GitHub accepts the form:
        https://x-access-token:<TOKEN>@github.com/<owner>/<repo>.git
        """

        origin = None
        try:
            origin = repo_obj.remotes.origin
        except Exception:
            origin = None

        owner, repo = self._parse_owner_repo(repo_url)
        if not owner or not repo:
            logger.warning("Could not parse owner/repo from %s; leaving origin unchanged", repo_url)
            return

        # Token may contain characters that must be URL-encoded for basic auth.
        safe_token = quote(token, safe="")
        token_remote = f"https://x-access-token:{safe_token}@github.com/{owner}/{repo}.git"

        if origin is None:
            repo_obj.create_remote("origin", token_remote)
            return

        current_urls = list(origin.urls)
        if current_urls and any(u.startswith("https://x-access-token:") for u in current_urls):
            return

        # Replace existing URL(s) with token remote.
        repo_obj.git.remote("set-url", "origin", token_remote)

    def _open_pr(self, token: str, owner: str, repo: str, title: str, body: str, head: str, base: str) -> Dict[str, Any]:
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        }
        payload = {"title": title, "body": body, "head": head, "base": base}
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        # If a PR already exists for the same head/base, GitHub returns 422.
        # Make this idempotent by fetching and returning the existing PR.
        if resp.status_code == 422:
            existing = self._find_existing_pr(token, owner, repo, head=head, base=base)
            if existing:
                return existing
        if resp.status_code >= 400:
            raise RuntimeError(f"Failed to create PR: {resp.status_code} {resp.text}")
        return resp.json()

    def _find_existing_pr(self, token: str, owner: str, repo: str, head: str, base: str) -> Optional[Dict[str, Any]]:
        """Return existing open PR matching head/base, if any."""
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        }
        params = {"state": "open", "base": base, "per_page": 100}
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code >= 400:
            return None

        # GitHub returns head.ref (branch name) and head.label (owner:branch).
        for pr in resp.json():
            if pr.get("head", {}).get("ref") == head and pr.get("base", {}).get("ref") == base:
                return pr
        return None

    def _parse_owner_repo(self, repo_url: str) -> Tuple[Optional[str], Optional[str]]:
        # Supports https://github.com/owner/repo(.git)
        m = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
        if not m:
            return None, None
        return m.group(1), m.group(2)
