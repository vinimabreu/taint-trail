from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from taint_trail.actions import parse_uses
from taint_trail.fetch import FetchError, clone_commands, ensure_inside, fetch_missing


def test_clone_commands_fetch_exactly_one_commit_at_the_pinned_ref(tmp_path: Path) -> None:
    ref = parse_uses("example/thing@v2")
    commands = clone_commands(ref, tmp_path / "example" / "thing" / "v2")
    assert commands[0][:3] == ["git", "init", "--quiet"]
    assert commands[1][-1] == "https://github.com/example/thing.git"
    assert commands[2][-5:] == ["--depth", "1", "origin", "--", "v2"]
    assert commands[3][-1] == "FETCH_HEAD"


def recorder(calls: list[list[str]]) -> Callable[[list[str]], int]:
    def runner(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    return runner


def test_fetch_missing_skips_local_docker_and_already_vendored_refs(tmp_path: Path) -> None:
    vendored = tmp_path / "example" / "have" / "v1"
    vendored.mkdir(parents=True)
    (vendored / "action.yml").write_text("runs:\n  using: composite\n")
    calls: list[list[str]] = []
    fetched, failed = fetch_missing(
        ["./local", "docker://alpine", "example/have@v1", "example/need@v1", "example/need@v1"],
        tmp_path,
        recorder(calls),
    )
    assert fetched == ["example/need@v1"]
    assert failed == []
    assert len(calls) == 4


def test_fetch_missing_reports_a_failed_clone(tmp_path: Path) -> None:
    fetched, failed = fetch_missing(["example/broken@v1"], tmp_path, lambda argv: 1)
    assert fetched == []
    assert failed == ["example/broken@v1"]


def test_fetch_missing_treats_a_subdirectory_action_as_one_repository(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    fetched, _ = fetch_missing(
        ["owner/mono/a@main", "owner/mono/b@main"], tmp_path, recorder(calls)
    )
    assert fetched == ["owner/mono@main"]
    assert len(calls) == 4


def test_clone_commands_put_a_double_dash_before_the_ref(tmp_path: Path) -> None:
    ref = parse_uses("example/thing@v2")
    commands = clone_commands(ref, tmp_path / "example" / "thing" / "v2")
    assert commands[2][-3:] == ["origin", "--", "v2"]


def test_fetch_missing_never_runs_git_for_a_reference_that_fails_validation(
    tmp_path: Path,
) -> None:
    calls: list[list[str]] = []
    fetched, failed = fetch_missing(
        ["evil/repo@../../../../tmp/x", "evil/repo@-o", "evil/repo@/abs"], tmp_path, recorder(calls)
    )
    assert calls == []
    assert fetched == [] and failed == []
    assert list(tmp_path.iterdir()) == []


def test_fetch_missing_refuses_a_destination_outside_the_actions_directory(
    tmp_path: Path,
) -> None:
    actions = tmp_path / "actions"
    actions.mkdir()
    (actions / "evil").symlink_to(tmp_path / "elsewhere")
    calls: list[list[str]] = []
    with pytest.raises(FetchError) as info:
        fetch_missing(["evil/repo@v1"], actions, recorder(calls))
    assert calls == []
    assert "outside" in str(info.value)
    assert not (tmp_path / "elsewhere").exists()


def test_ensure_inside_accepts_a_child_and_rejects_a_sibling(tmp_path: Path) -> None:
    ensure_inside(tmp_path / "a" / "b", tmp_path)
    with pytest.raises(FetchError):
        ensure_inside(tmp_path.parent / "sibling", tmp_path)
