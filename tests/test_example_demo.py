"""The README pastes the demo output. This keeps the two identical."""

from __future__ import annotations

import re
import subprocess
import sys

from examples.hero_chain import hero_output

from .conftest import ROOT


def readme_hero_block() -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- hero:start -->\n```text\n(.*?)```\n<!-- hero:end -->", text, re.DOTALL)
    assert match is not None, "README is missing the hero block markers"
    return match.group(1)


def test_the_readme_hero_chain_is_the_demo_output_byte_for_byte() -> None:
    assert readme_hero_block() == hero_output()


def test_the_demo_runs_as_a_script_and_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "hero_chain.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == hero_output()


def test_the_readme_test_badge_matches_the_collected_count() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    badge = re.search(r"tests-(\d+)%20passing", text)
    assert badge is not None
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    per_file = re.findall(r"^tests/\S+: (\d+)$", result.stdout, re.MULTILINE)
    assert per_file, result.stdout[-500:]
    assert int(badge.group(1)) == sum(int(n) for n in per_file)
