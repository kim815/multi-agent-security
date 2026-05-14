import asyncio
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from git import Repo

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
        await asyncio.to_thread(self._git_commit_and_push, repo_obj, branch_name)

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

    def _git_commit_and_push(self, repo_obj: Repo, branch_name: str) -> None:
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

        # Push
        try:
            repo_obj.git.push("-u", "origin", branch_name)
        except Exception:
            logger.exception("Failed to push branch")
            raise

    def _open_pr(self, token: str, owner: str, repo: str, title: str, body: str, head: str, base: str) -> Dict[str, Any]:
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        }
        payload = {"title": title, "body": body, "head": head, "base": base}
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"Failed to create PR: {resp.status_code} {resp.text}")
        return resp.json()

    def _parse_owner_repo(self, repo_url: str) -> Tuple[Optional[str], Optional[str]]:
        # Supports https://github.com/owner/repo(.git)
        m = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
        if not m:
            return None, None
        return m.group(1), m.group(2)
