from __future__ import annotations

from pathlib import Path

import yaml

from taint_trail.workflow import parse_workflow
from taint_trail.yamlload import LineDict, LineStr, load_yaml

TEXT = """name: demo
on:
  issue_comment:
    types: [created]
jobs:
  a:
    steps:
      - name: one
        run: |
          echo first
          eval "$BODY"
      - run: echo single
"""


def test_pyyaml_itself_turns_the_top_level_on_key_into_the_boolean_true() -> None:
    assert True in yaml.safe_load(TEXT)
    assert "on" not in yaml.safe_load(TEXT)


def test_the_loader_keeps_on_as_the_string_key_github_expects() -> None:
    data = load_yaml(TEXT)
    assert "on" in data
    assert True not in data
    assert list(data["on"]) == ["issue_comment"]


def test_the_workflow_model_exposes_triggers_from_the_on_key() -> None:
    workflow = parse_workflow(TEXT, Path("demo.yml"))
    assert workflow.triggers == ["issue_comment"]


def test_other_yaml_1_1_boolean_words_stay_strings_as_keys() -> None:
    data = load_yaml("yes: 1\nno: 2\noff: 3\n")
    assert list(data) == ["yes", "no", "off"]


def test_a_block_scalar_reports_the_line_of_its_key_and_the_line_of_its_first_content_line() -> (
    None
):
    data = load_yaml(TEXT)
    run = data["jobs"]["a"]["steps"][0]["run"]
    assert isinstance(run, LineStr)
    assert run.line == 9
    assert run.body_line == 10


def test_an_inline_scalar_reports_the_same_line_for_key_and_body() -> None:
    data = load_yaml(TEXT)
    run = data["jobs"]["a"]["steps"][1]["run"]
    assert run.line == run.body_line == 12


def test_mappings_remember_the_line_of_each_key() -> None:
    data = load_yaml(TEXT)
    assert isinstance(data, LineDict)
    assert data.key_line("jobs") == 5
    assert data["jobs"]["a"]["steps"][0].key_line("run") == 9


def test_a_workflow_that_is_not_a_mapping_is_rejected() -> None:
    import pytest

    from taint_trail.workflow import WorkflowError

    with pytest.raises(WorkflowError):
        parse_workflow("- just\n- a list\n", Path("x.yml"))


def test_invalid_yaml_raises_a_named_error() -> None:
    import pytest

    from taint_trail.yamlload import YamlError

    with pytest.raises(YamlError):
        load_yaml("on: [unclosed\n")


def test_absurd_nesting_raises_the_named_error_not_recursion_error() -> None:
    import pytest

    from taint_trail.yamlload import YamlError

    with pytest.raises(YamlError):
        load_yaml("[" * 6000)
