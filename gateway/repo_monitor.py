from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from pathlib import Path
import subprocess
import time
from typing import Dict, Optional

LOGGER = logging.getLogger(__name__)

REPO_CHECK_INTERVAL_SECONDS = 900


class GitRepoMonitor:
    """Cache local/upstream git state for the admin dashboard."""

    def __init__(
        self,
        repo_path: str,
        remote_name: str = "origin",
        check_interval_s: int = REPO_CHECK_INTERVAL_SECONDS,
    ) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.remote_name = str(remote_name or "origin").strip() or "origin"
        self.check_interval_s = max(60, int(check_interval_s or REPO_CHECK_INTERVAL_SECONDS))
        self._lock = asyncio.Lock()
        self._refresh_task: Optional[asyncio.Task] = None
        self._startup_task: Optional[asyncio.Task] = None
        self._last_update_at = 0.0
        self._last_update_message = ""
        self._restart_required = False
        self._snapshot_cache = self._finalize_snapshot(
            {
                "available": False,
                "repo_path": str(self.repo_path),
                "remote_name": self.remote_name,
                "remote_url": "",
                "branch": "",
                "upstream": "",
                "local_commit": "",
                "local_short": "",
                "local_version": "",
                "remote_commit": "",
                "remote_short": "",
                "remote_version": "",
                "ahead": 0,
                "behind": 0,
                "dirty": False,
                "can_update": False,
                "update_available": False,
                "status": "pending",
                "last_checked_at": 0.0,
                "last_error": "",
            }
        )

    def _finalize_snapshot(self, snapshot: Dict[str, object]) -> Dict[str, object]:
        snapshot["check_interval_seconds"] = self.check_interval_s
        snapshot["last_update_at"] = float(self._last_update_at)
        snapshot["last_update_message"] = self._last_update_message
        snapshot["restart_required"] = bool(self._restart_required)
        return snapshot

    def snapshot(self) -> Dict[str, object]:
        return dict(self._snapshot_cache)

    def start_background_tasks(self) -> None:
        if self._startup_task is None or self._startup_task.done():
            self._startup_task = asyncio.create_task(self.force_refresh())
        if self._refresh_task is None:
            self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def stop_background_tasks(self) -> None:
        tasks = [self._startup_task, self._refresh_task]
        self._startup_task = None
        self._refresh_task = None
        for task in tasks:
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _refresh_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.check_interval_s)
                try:
                    await self.force_refresh()
                except Exception as exc:
                    LOGGER.warning("Dashboard(repo): background refresh failed: %s", exc)
        except asyncio.CancelledError:
            raise

    def _run_git(self, *args: str, timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.setdefault("GIT_TERMINAL_PROMPT", "0")
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            check=False,
        )

    def _git_text(self, *args: str, timeout: float = 20.0) -> str:
        result = self._run_git(*args, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"git {' '.join(args)} failed")
        return result.stdout.strip()

    def _collect_snapshot_sync(self, fetch_remote: bool = True) -> Dict[str, object]:
        snapshot: Dict[str, object] = {
            "available": False,
            "repo_path": str(self.repo_path),
            "remote_name": self.remote_name,
            "remote_url": "",
            "branch": "",
            "upstream": "",
            "local_commit": "",
            "local_short": "",
            "local_version": "",
            "remote_commit": "",
            "remote_short": "",
            "remote_version": "",
            "ahead": 0,
            "behind": 0,
            "dirty": False,
            "can_update": False,
            "update_available": False,
            "status": "unavailable",
            "last_checked_at": time.time(),
            "last_error": "",
        }
        try:
            inside = self._git_text("rev-parse", "--is-inside-work-tree")
            if inside.lower() != "true":
                snapshot["last_error"] = "not a git work tree"
                return self._finalize_snapshot(snapshot)

            snapshot["available"] = True
            snapshot["status"] = "up_to_date"
            snapshot["repo_path"] = self._git_text("rev-parse", "--show-toplevel")
            snapshot["branch"] = self._git_text("rev-parse", "--abbrev-ref", "HEAD")
            snapshot["local_commit"] = self._git_text("rev-parse", "HEAD")
            snapshot["local_short"] = str(snapshot["local_commit"])[:12]
            with contextlib.suppress(Exception):
                snapshot["local_version"] = self._git_text("describe", "--tags", "--always", "--dirty")
            with contextlib.suppress(Exception):
                snapshot["remote_url"] = self._git_text("remote", "get-url", self.remote_name)

            status_lines = self._git_text("status", "--porcelain").splitlines()
            snapshot["dirty"] = bool(status_lines)

            fetch_error = ""
            if fetch_remote and snapshot["remote_url"]:
                fetch = self._run_git("fetch", "--quiet", "--tags", self.remote_name, timeout=60.0)
                if fetch.returncode != 0:
                    fetch_error = fetch.stderr.strip() or fetch.stdout.strip() or "git fetch failed"

            upstream = self._run_git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
            if upstream.returncode == 0:
                upstream_ref = upstream.stdout.strip()
                snapshot["upstream"] = upstream_ref
                with contextlib.suppress(Exception):
                    snapshot["remote_commit"] = self._git_text("rev-parse", "@{u}")
                snapshot["remote_short"] = str(snapshot["remote_commit"])[:12] if snapshot["remote_commit"] else ""
                with contextlib.suppress(Exception):
                    snapshot["remote_version"] = self._git_text("describe", "--tags", "--always", "@{u}")
                counts = self._git_text("rev-list", "--left-right", "--count", "HEAD...@{u}")
                ahead_str, behind_str = (counts.split() + ["0", "0"])[:2]
                snapshot["ahead"] = int(ahead_str or "0")
                snapshot["behind"] = int(behind_str or "0")
                snapshot["update_available"] = int(snapshot["behind"]) > 0 and int(snapshot["ahead"]) == 0
                if int(snapshot["ahead"]) > 0 and int(snapshot["behind"]) > 0:
                    snapshot["status"] = "diverged"
                elif int(snapshot["behind"]) > 0:
                    snapshot["status"] = "update_available"
                elif int(snapshot["ahead"]) > 0:
                    snapshot["status"] = "ahead"
                else:
                    snapshot["status"] = "up_to_date"
            else:
                snapshot["status"] = "no_upstream"

            snapshot["can_update"] = bool(
                snapshot["available"]
                and snapshot["upstream"]
                and not snapshot["dirty"]
                and int(snapshot["behind"]) > 0
                and int(snapshot["ahead"]) == 0
            )
            if fetch_error:
                snapshot["last_error"] = fetch_error
        except FileNotFoundError:
            snapshot["last_error"] = "git is not installed in this environment"
        except subprocess.TimeoutExpired:
            snapshot["last_error"] = "git command timed out"
            snapshot["status"] = "error"
        except Exception as exc:
            snapshot["last_error"] = str(exc)
            snapshot["status"] = "error"
        return self._finalize_snapshot(snapshot)

    async def force_refresh(self, fetch_remote: bool = True) -> Dict[str, object]:
        async with self._lock:
            snapshot = await asyncio.to_thread(self._collect_snapshot_sync, fetch_remote)
            self._snapshot_cache = snapshot
            return dict(snapshot)

    async def update_from_upstream(self) -> Dict[str, object]:
        async with self._lock:
            result = await asyncio.to_thread(self._update_from_upstream_sync)
            self._snapshot_cache = dict(result.get("git") or self._snapshot_cache)
            return result

    def _update_from_upstream_sync(self) -> Dict[str, object]:
        before = self._collect_snapshot_sync(fetch_remote=True)
        if not before.get("available"):
            return {"ok": False, "error": before.get("last_error") or "git repo unavailable", "git": before}
        if before.get("last_error"):
            return {"ok": False, "error": before["last_error"], "git": before}
        if not before.get("upstream"):
            return {"ok": False, "error": "no upstream branch configured", "git": before}
        if before.get("dirty"):
            return {"ok": False, "error": "working tree has local changes", "git": before}
        if int(before.get("ahead") or 0) > 0 and int(before.get("behind") or 0) > 0:
            return {"ok": False, "error": "branch has diverged from upstream", "git": before}
        if int(before.get("ahead") or 0) > 0:
            return {"ok": False, "error": "local branch is ahead of upstream", "git": before}
        if int(before.get("behind") or 0) <= 0:
            return {"ok": True, "updated": False, "message": "Already up to date.", "git": before}

        old_commit = str(before.get("local_commit") or "")
        old_label = str(before.get("local_version") or before.get("local_short") or old_commit[:12])
        merge = self._run_git("merge", "--ff-only", str(before["upstream"]), timeout=60.0)
        if merge.returncode != 0:
            after_fail = self._collect_snapshot_sync(fetch_remote=False)
            error = merge.stderr.strip() or merge.stdout.strip() or "git merge --ff-only failed"
            after_fail["last_error"] = error
            after_fail = self._finalize_snapshot(after_fail)
            return {"ok": False, "error": error, "git": after_fail}

        self._last_update_at = time.time()
        self._restart_required = True

        after = self._collect_snapshot_sync(fetch_remote=False)
        new_commit = str(after.get("local_commit") or "")
        new_label = str(after.get("local_version") or after.get("local_short") or new_commit[:12])
        diff = self._run_git("diff", "--name-only", f"{old_commit}..{new_commit}", timeout=20.0)
        changed_files = [line.strip() for line in diff.stdout.splitlines() if line.strip()]
        self._last_update_message = (
            f"Updated from {old_label} to {new_label}. Restart the gateway to load the new code."
        )
        after = self._finalize_snapshot(after)
        return {
            "ok": True,
            "updated": old_commit != new_commit,
            "message": self._last_update_message,
            "changed_files": changed_files,
            "git": after,
        }
