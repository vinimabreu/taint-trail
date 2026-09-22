from __future__ import annotations

import json
from pathlib import Path

import pytest

from taint_trail.cli import collect_files, main

from .conftest import ACTIONS, MALFORMED, REPO, WORKFLOWS


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_a_shell_finding_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, str(WORKFLOWS / "moved_not_fixed.yml"))
    assert code == 1
    assert "SHELL: eval re-parses the value as shell" in out


def test_a_spoof_finding_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, str(WORKFLOWS / "spoof_static_delimiter.yml"))
    assert code == 1
    assert "SPOOF:" in out


def test_a_dies_verdict_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, str(WORKFLOWS / "moved_and_died.yml"), "--actions-dir", str(ACTIONS))
    assert code == 0
    assert "DIES (heuristic):" in out


def test_unknown_exits_zero_by_default_and_one_under_strict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = str(WORKFLOWS / "unresolvable_action.yml")
    assert run(capsys, target)[0] == 0
    assert run(capsys, target, "--strict")[0] == 1


def test_suspect_exits_zero_by_default_and_one_under_strict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = str(WORKFLOWS / "js_execsync.yml")
    assert run(capsys, target, "--actions-dir", str(ACTIONS))[0] == 0
    assert run(capsys, target, "--actions-dir", str(ACTIONS), "--strict")[0] == 1


def test_semi_trusted_chains_never_affect_the_exit_code_even_under_strict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(capsys, str(WORKFLOWS / "workflow_dispatch_inputs.yml"), "--strict")
    assert code == 0
    assert "semi-trusted, not counted" in out


def test_a_clean_workflow_prints_the_empty_message_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(capsys, str(WORKFLOWS / "clean.yml"))
    assert code == 0
    assert "no untrusted value leaves an expression" in out


def test_text_output_prints_every_hop_as_file_line_and_carrier(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, out, _ = run(capsys, str(WORKFLOWS / "moved_and_died.yml"), "--actions-dir", str(ACTIONS))
    assert "moved_and_died.yml:13  env BODY" in out
    assert "moved_and_died.yml:16  with prompt" in out
    assert "action.yml:4  inputs.prompt" in out
    assert "action.yml:19  env HELPER_PROMPT" in out


def test_json_output_has_the_documented_shape(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys, str(WORKFLOWS / "moved_not_fixed.yml"), "--json", "--actions-dir", str(ACTIONS)
    )
    data = json.loads(out)
    assert code == 1
    assert data["version"] == 1
    assert data["exit_code"] == 1
    assert data["strict"] is False
    assert data["summary"] == {
        "chains": 1,
        "SHELL": 1,
        "SPOOF": 0,
        "SUSPECT": 0,
        "DIES": 0,
        "UNKNOWN": 0,
        "semi_trusted": 0,
    }
    chain = data["chains"][0]
    assert chain["source"] == "github.event.comment.body"
    assert chain["trust"] == "untrusted"
    assert chain["counts"] is True
    assert chain["verdict"] == {
        "kind": "SHELL",
        "heuristic": False,
        "reason": "eval re-parses the value as shell",
        "text": "SHELL: eval re-parses the value as shell",
    }
    assert [h["carrier"] for h in chain["hops"]] == ["env BODY", "run"]
    assert set(chain["hops"][0]) == {"file", "line", "carrier", "detail"}


def test_json_records_strict_in_the_payload(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, str(WORKFLOWS / "clean.yml"), "--json", "--strict")
    assert json.loads(out)["strict"] is True


def test_a_directory_with_github_workflows_scans_that_folder(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(capsys, str(REPO))
    assert code == 1
    assert "caller.yml" in out
    assert "local_action.yml" in out


def test_a_plain_directory_scans_its_yaml_files(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, str(WORKFLOWS), "--actions-dir", str(ACTIONS))
    assert code == 1
    assert "all_sources.yml" in out
    assert "moved_and_died.yml" in out


def test_collect_files_takes_files_as_given_and_sorts_directories(tmp_path: Path) -> None:
    (tmp_path / "b.yml").write_text("on: push\n")
    (tmp_path / "a.yaml").write_text("on: push\n")
    (tmp_path / "notes.txt").write_text("x")
    assert [p.name for p in collect_files([tmp_path])] == ["a.yaml", "b.yml"]
    assert collect_files([tmp_path / "b.yml"]) == [tmp_path / "b.yml"]


def test_a_missing_path_exits_two_with_a_message(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "/nonexistent/workflow.yml")
    assert code == 2
    assert "no such file" in err


def test_an_empty_directory_exits_two(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, str(tmp_path))
    assert code == 2
    assert "no workflow files" in err


def test_invalid_yaml_exits_two(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("on: [unclosed\n")
    code, _, err = run(capsys, str(bad))
    assert code == 2
    assert "bad.yml" in err


def test_the_actions_dir_can_come_from_the_environment(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TAINT_TRAIL_ACTIONS", str(ACTIONS))
    code, out, _ = run(capsys, str(WORKFLOWS / "moved_and_died.yml"))
    assert code == 0
    assert "DIES (heuristic)" in out


def test_max_depth_is_honoured_from_the_command_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, out, _ = run(
        capsys,
        str(WORKFLOWS / "moved_and_died.yml"),
        "--actions-dir",
        str(ACTIONS),
        "--max-depth",
        "0",
    )
    assert "UNKNOWN: depth limit 0 reached" in out


def test_fetch_without_an_actions_dir_exits_two(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TAINT_TRAIL_ACTIONS", raising=False)
    code, _, err = run(capsys, str(WORKFLOWS / "clean.yml"), "--fetch")
    assert code == 2
    assert "--fetch needs --actions-dir" in err


def test_fetch_uses_the_injected_git_runner_and_never_the_network(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_runner(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    from taint_trail import cli, fetch

    def fetch_with_fake_git(refs: list[str], directory: Path) -> tuple[list[str], list[str]]:
        return fetch.fetch_missing(refs, directory, fake_runner)

    monkeypatch.setattr(cli, "fetch_missing", fetch_with_fake_git)
    code, _, err = run(
        capsys,
        str(WORKFLOWS / "unresolvable_action.yml"),
        "--fetch",
        "--actions-dir",
        str(tmp_path),
    )
    assert code == 0
    assert "fetched someone/not-vendored@v3" in err
    assert calls[0][:2] == ["git", "init"]
    assert any("https://github.com/someone/not-vendored.git" in argv for argv in calls)


def test_the_console_script_entry_point_is_registered() -> None:
    import importlib.metadata

    scripts = importlib.metadata.entry_points(group="console_scripts")
    assert any(ep.name == "taint-trail" for ep in scripts)


# --- malformed input never tracebacks, and one bad file never aborts a directory ----


def test_a_non_utf8_workflow_exits_two_with_a_message(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, str(MALFORMED / "binary.yml"))
    assert code == 2
    assert "binary.yml" in err
    assert "Traceback" not in err


def test_a_utf16_workflow_exits_two_with_a_message(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, str(MALFORMED / "utf16.yml"))
    assert code == 2
    assert "utf16.yml" in err


def test_absurdly_nested_yaml_exits_two_with_a_message(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, str(MALFORMED / "deep_nesting.yml"))
    assert code == 2
    assert "deep_nesting.yml" in err


def test_a_directory_with_one_broken_file_still_scans_the_others(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "good.yml").write_text((WORKFLOWS / "moved_not_fixed.yml").read_text())
    (tmp_path / "empty.yml").write_text("")
    (tmp_path / "list.yml").write_text("- a\n- b\n")
    code, out, err = run(capsys, str(tmp_path))
    assert code == 1
    assert "SHELL:" in out
    assert "empty.yml" in err
    assert "list.yml" in err


def test_a_directory_with_one_broken_file_and_a_clean_one_exits_zero(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "clean.yml").write_text((WORKFLOWS / "clean.yml").read_text())
    (tmp_path / "empty.yml").write_text("")
    code, _, err = run(capsys, str(tmp_path))
    assert code == 0
    assert "empty.yml" in err


def test_a_directory_where_every_file_is_broken_exits_two(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, _, err = run(capsys, str(MALFORMED))
    assert code == 2
    assert "empty.yml" in err
    assert "binary.yml" in err


def test_a_fetch_destination_outside_the_actions_dir_exits_two(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from taint_trail import cli
    from taint_trail.fetch import FetchError

    def refuse(refs: list[str], directory: Path) -> tuple[list[str], list[str]]:
        raise FetchError("refusing to write outside the actions directory")

    monkeypatch.setattr(cli, "fetch_missing", refuse)
    code, _, err = run(
        capsys,
        str(WORKFLOWS / "unresolvable_action.yml"),
        "--fetch",
        "--actions-dir",
        str(tmp_path),
    )
    assert code == 2
    assert "outside" in err
