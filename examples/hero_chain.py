"""Print the hero chain: an injection that moved out of ``run:`` and died in argv.

Runs entirely offline against the vendored fixtures in ``tests/fixtures``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from taint_trail import Analyzer, LocalDirResolver, render_text, summarise

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / "tests" / "fixtures" / "workflows" / "moved_and_died.yml"
ACTIONS = ROOT / "tests" / "fixtures" / "actions"


def hero_output() -> str:
    analyzer = Analyzer(resolver=LocalDirResolver(ACTIONS), cwd=ROOT)
    chains = analyzer.analyse_file(WORKFLOW)
    return render_text(chains, summarise(chains, [analyzer.display(WORKFLOW)]))


def main() -> int:
    sys.stdout.write(hero_output())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
