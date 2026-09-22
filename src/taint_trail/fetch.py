"""Optional, explicit network step: vendor actions into the local directory.

Never called by the analyser or the tests. ``taint-trail --fetch`` runs it once
before scanning, and it only runs ``git``; the command runner is injectable so
the sequence can be checked without a network.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from .actions import ActionRef, find_manifest, parse_uses

Runner = Callable[[list[str]], int]


class FetchError(ValueError):
    """A destination that would land outside the actions directory."""


def run_git(argv: list[str]) -> int:
    return subprocess.run(argv, check=False).returncode


def ensure_inside(dest: Path, actions_dir: Path) -> None:
    """Refuse any destination that does not resolve under ``actions_dir``."""
    root = actions_dir.resolve()
    target = dest.resolve()
    if not target.is_relative_to(root):
        raise FetchError(
            f"refusing to write {dest}: it resolves to {target}, outside the actions "
            f"directory {root}"
        )


def clone_commands(ref: ActionRef, dest: Path) -> list[list[str]]:
    url = f"https://github.com/{ref.owner}/{ref.repo}.git"
    at = str(dest)
    return [
        ["git", "init", "--quiet", at],
        ["git", "-C", at, "remote", "add", "origin", url],
        ["git", "-C", at, "fetch", "--quiet", "--depth", "1", "origin", "--", ref.ref],
        ["git", "-C", at, "checkout", "--quiet", "FETCH_HEAD"],
    ]


def fetch_missing(
    uses: list[str], actions_dir: Path, runner: Runner = run_git
) -> tuple[list[str], list[str]]:
    """Clone every ``owner/repo@ref`` not yet present. Returns (fetched, failed) slugs.

    References that fail ``parse_uses`` validation are skipped here and reported
    by the analyser as unparseable; a destination that resolves outside
    ``actions_dir`` raises ``FetchError`` before any directory is created.
    """
    fetched: list[str] = []
    failed: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for text in uses:
        ref = parse_uses(text)
        if ref.kind != "repo":
            continue
        key = (ref.owner, ref.repo, ref.ref)
        if key in seen:
            continue
        seen.add(key)
        dest = actions_dir / ref.owner / ref.repo / ref.ref
        ensure_inside(dest, actions_dir)
        probe = dest / ref.path if ref.path else dest
        if find_manifest(probe) is not None or (dest / ".git").exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        ok = all(runner(argv) == 0 for argv in clone_commands(ref, dest))
        (fetched if ok else failed).append(f"{ref.owner}/{ref.repo}@{ref.ref}")
    return fetched, failed
