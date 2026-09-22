"""``taint-trail <workflow.yml or dir> [--actions-dir D] [--json] [--strict] [--max-depth N]``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .actions import LocalDirResolver
from .fetch import FetchError, fetch_missing
from .model import Chain
from .propagate import Analyzer
from .report import render_json, render_text, summarise
from .workflow import WorkflowError, load_workflow, uses_refs
from .yamlload import YamlError

EXIT_USAGE = 2


def collect_files(paths: list[Path]) -> list[Path]:
    """Workflow files: a file as given; a dir's ``.github/workflows``, else its ``*.yml``."""
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
            continue
        if not path.is_dir():
            raise FileNotFoundError(str(path))
        base = path / ".github" / "workflows"
        if not base.is_dir():
            base = path
        files.extend(sorted(p for p in base.iterdir() if p.suffix in (".yml", ".yaml")))
    return files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="taint-trail",
        description=(
            "Follow an untrusted value through a GitHub Actions workflow after it leaves the "
            "run: block, and say where it ends: SHELL, SPOOF, SUSPECT, DIES or UNKNOWN."
        ),
    )
    parser.add_argument("paths", nargs="+", type=Path, help="workflow file(s) or directories")
    parser.add_argument(
        "--actions-dir",
        type=Path,
        default=None,
        help="local copies of actions as owner/repo/ref/action.yml (or env TAINT_TRAIL_ACTIONS)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--strict", action="store_true", help="also exit 1 on SUSPECT and UNKNOWN")
    parser.add_argument("--max-depth", type=int, default=5, help="action/script nesting limit")
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="git clone --depth 1 every missing owner/repo@ref into --actions-dir (network)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    actions_dir: Path | None = args.actions_dir
    if actions_dir is None:
        from_env = os.environ.get("TAINT_TRAIL_ACTIONS")
        actions_dir = Path(from_env) if from_env else None
    try:
        files = collect_files(args.paths)
    except FileNotFoundError as exc:
        print(f"taint-trail: no such file or directory: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if not files:
        print("taint-trail: no workflow files found", file=sys.stderr)
        return EXIT_USAGE
    workflows = []
    unreadable = 0
    for path in files:
        try:
            workflows.append(load_workflow(path))
        except (WorkflowError, YamlError) as exc:
            print(f"taint-trail: {exc}", file=sys.stderr)
            unreadable += 1
    if not workflows:
        print(f"taint-trail: none of the {unreadable} file(s) could be read", file=sys.stderr)
        return EXIT_USAGE
    if unreadable:
        print(f"taint-trail: skipped {unreadable} unreadable file(s)", file=sys.stderr)
    if args.fetch:
        if actions_dir is None:
            print(
                "taint-trail: --fetch needs --actions-dir (or TAINT_TRAIL_ACTIONS)", file=sys.stderr
            )
            return EXIT_USAGE
        refs = [ref for workflow in workflows for ref in uses_refs(workflow)]
        try:
            fetched, failed = fetch_missing(refs, actions_dir)
        except FetchError as exc:
            print(f"taint-trail: {exc}", file=sys.stderr)
            return EXIT_USAGE
        for slug in fetched:
            print(f"fetched {slug}", file=sys.stderr)
        for slug in failed:
            print(f"could not fetch {slug}", file=sys.stderr)
    analyzer = Analyzer(resolver=LocalDirResolver(actions_dir), max_depth=args.max_depth)
    chains: list[Chain] = []
    for workflow in workflows:
        chains.extend(analyzer.analyse_workflow(workflow))
    summary = summarise(chains, [analyzer.display(workflow.path) for workflow in workflows])
    if args.json:
        print(json.dumps(render_json(chains, summary, args.strict), indent=2))
    else:
        sys.stdout.write(render_text(chains, summary))
    return summary.exit_code(args.strict)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
