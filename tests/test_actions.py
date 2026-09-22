from __future__ import annotations

import os
from pathlib import Path

import pytest

from taint_trail import Analyzer, LocalDirResolver, NoResolver
from taint_trail.actions import (
    ActionError,
    js_heuristic,
    js_references_env,
    load_action,
    parse_uses,
)
from taint_trail.workflow import parse_workflow

from .conftest import (
    ACTIONS,
    REPO,
    ROOT,
    TRAVERSAL,
    AnalyseText,
    analyse,
    carriers,
    kinds,
    workflow_with,
)

# --- uses: parsing --------------------------------------------------------------


def test_a_repo_reference_is_split_into_owner_repo_path_and_ref() -> None:
    ref = parse_uses("example/helper-action@v1")
    assert (ref.kind, ref.owner, ref.repo, ref.path, ref.ref) == (
        "repo",
        "example",
        "helper-action",
        "",
        "v1",
    )
    assert ref.slug == "example/helper-action@v1"


def test_a_subdirectory_action_keeps_its_path() -> None:
    ref = parse_uses("owner/monorepo/tools/lint@main")
    assert ref.path == "tools/lint"
    assert ref.slug == "owner/monorepo/tools/lint@main"


def test_a_local_reference_is_relative_to_the_repository() -> None:
    ref = parse_uses("./.github/actions/greet")
    assert ref.kind == "local"
    assert ref.path == ".github/actions/greet"


def test_a_docker_reference_is_docker() -> None:
    assert parse_uses("docker://alpine:3").kind == "docker"


def test_a_reference_without_a_version_is_invalid() -> None:
    assert parse_uses("owner/repo").kind == "invalid"


def test_github_script_is_recognised_at_any_version() -> None:
    assert parse_uses("actions/github-script@v7").is_github_script
    assert not parse_uses("actions/checkout@v4").is_github_script


# --- resolver ---------------------------------------------------------------------


def test_the_local_dir_resolver_finds_owner_repo_ref_action_yml() -> None:
    directory = LocalDirResolver(ACTIONS).action(parse_uses("example/composite-echo@v1"), None)
    assert directory == ACTIONS / "example" / "composite-echo" / "v1"


def test_the_local_dir_resolver_returns_none_for_a_missing_ref() -> None:
    assert LocalDirResolver(ACTIONS).action(parse_uses("example/composite-echo@v9"), None) is None


def test_the_local_dir_resolver_finds_local_actions_under_the_repo_root() -> None:
    directory = LocalDirResolver(None).action(parse_uses("./.github/actions/greet"), REPO)
    assert directory == REPO / ".github" / "actions" / "greet"


def test_the_local_dir_resolver_needs_a_repo_root_for_local_actions() -> None:
    assert LocalDirResolver(ACTIONS).action(parse_uses("./.github/actions/greet"), None) is None


def test_the_local_dir_resolver_finds_reusable_workflow_files() -> None:
    ref = parse_uses("./.github/workflows/called.yml")
    assert LocalDirResolver(None).workflow(ref, REPO) == REPO / ".github/workflows/called.yml"


def test_the_no_resolver_resolves_nothing() -> None:
    assert NoResolver().action(parse_uses("example/composite-echo@v1"), None) is None
    assert NoResolver().workflow(parse_uses("./x.yml"), REPO) is None


def test_loading_a_directory_without_a_manifest_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ActionError):
        load_action(tmp_path)


def test_a_manifest_exposes_inputs_outputs_and_kind() -> None:
    manifest = load_action(ACTIONS / "example" / "composite-outputs" / "v1")
    assert manifest.kind == "composite"
    assert list(manifest.inputs) == ["text"]
    assert manifest.inputs["text"].line == 4
    assert manifest.outputs["text"].value is not None


# --- composite recursion -------------------------------------------------------


def test_with_taint_flows_into_a_composite_input_and_reaches_eval_inside_the_action(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/composite-eval@v1\n        with:\n"
            "          command: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["SHELL"]
    assert carriers(chains[0]) == ["with command", "inputs.command", "env CMD", "run"]
    assert chains[0].hops[1].file.endswith("composite-eval/v1/action.yml")
    assert chains[0].hops[1].line == 4


def test_with_taint_that_only_gets_echoed_inside_the_action_dies(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/composite-echo@v1\n        with:\n"
            "          text: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["DIES"]


def test_a_job_env_is_inherited_by_composite_steps(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/composite-eval@v1\n        with:\n          command: plain",
            env="  CMD: ${{ github.event.comment.body }}",
        )
    )
    # The action's own step env sets CMD from the (clean) input, shadowing the
    # inherited one, so the inherited taint is never read inside.
    assert kinds(chains) == ["DIES"]
    assert "never read" in chains[0].verdict.reason


def test_a_composite_input_with_a_tainted_default_is_followed_when_not_provided(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    actions = tmp_path / "actions"
    action = actions / "x" / "defaulted" / "v1"
    action.mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: d\ndescription: d\ninputs:\n  cmd:\n    description: c\n"
        "    default: ${{ github.event.issue.title }}\nruns:\n  using: composite\n  steps:\n"
        '    - shell: bash\n      env:\n        C: ${{ inputs.cmd }}\n      run: eval "$C"\n'
    )
    chains = analyse_text(workflow_with("      - uses: x/defaulted@v1"), actions=actions)
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[0].detail == "default"


def test_composite_outputs_carry_taint_back_to_the_caller(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: e\n        uses: example/composite-outputs@v1\n        with:\n"
            "          text: ${{ github.event.issue.body }}\n"
            '      - run: eval "${{ steps.e.outputs.text }}"'
        )
    )
    assert kinds(chains) == ["DIES", "SHELL"]
    assert "outputs.text" in carriers(chains[1])


def test_a_cycle_between_composite_actions_is_reported_not_looped(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/cycle-a@v1\n        with:\n"
            "          text: ${{ github.event.issue.title }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert chains[0].verdict.reason == (
        "cycle: example/cycle-a@v1 -> example/cycle-b@v1 -> example/cycle-a@v1"
    )


def test_the_depth_limit_stops_recursion_with_the_reason_named(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/cycle-a@v1\n        with:\n"
            "          text: ${{ github.event.issue.title }}"
        ),
        max_depth=1,
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert chains[0].verdict.reason == "depth limit 1 reached at example/cycle-b@v1"


def test_depth_zero_refuses_every_action(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/composite-echo@v1\n        with:\n"
            "          text: ${{ github.event.issue.title }}"
        ),
        max_depth=0,
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "depth limit 0" in chains[0].verdict.reason


def test_an_action_missing_locally_is_unknown_with_the_fix_named(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: someone/not-vendored@v3\n        with:\n"
            "          text: ${{ github.event.issue.title }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "not available locally" in chains[0].verdict.reason
    assert "--fetch" in chains[0].verdict.reason


def test_without_any_actions_dir_every_action_is_unknown(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/composite-eval@v1\n        with:\n"
            "          command: ${{ github.event.comment.body }}"
        ),
        actions=None,
    )
    assert kinds(chains) == ["UNKNOWN"]


def test_an_unparseable_uses_reference_is_unknown(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: not-a-reference\n        with:\n"
            "          text: ${{ github.event.issue.title }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "could not be parsed" in chains[0].verdict.reason


def test_a_with_value_that_is_not_a_string_is_ignored(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with("      - uses: example/composite-echo@v1\n        with:\n          text: 42")
    )
    assert chains == []


def test_a_local_action_under_the_repo_is_followed() -> None:
    chains = analyse(REPO / ".github" / "workflows" / "local_action.yml")
    assert kinds(chains) == ["DIES"]
    assert chains[0].hops[1].file.endswith(".github/actions/greet/action.yml")


# --- docker and node actions ------------------------------------------------------


def test_a_docker_action_is_unknown_because_args_reach_the_entrypoint(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/docker-action@v1\n        with:\n"
            "          text: ${{ github.event.pull_request.title }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert chains[0].verdict.reason == "docker action, args reach entrypoint"


def test_a_docker_url_reference_is_unknown_the_same_way(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: docker://alpine:3\n        with:\n"
            "          args: ${{ github.event.pull_request.title }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "docker action" in chains[0].verdict.reason


def test_a_js_action_with_execsync_is_suspect_and_labelled_heuristic(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/js-shell-action@v1\n        with:\n"
            "          message: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["SUSPECT"]
    assert chains[0].verdict.heuristic
    assert "execSync(" in chains[0].verdict.reason
    assert chains[0].verdict.render().startswith("SUSPECT (heuristic):")
    assert carriers(chains[0]) == ["with message", "inputs.message", "getInput('message')"]


def test_a_js_action_with_execfile_and_an_argv_array_dies_and_is_labelled_heuristic(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/js-argv-action@v1\n        with:\n"
            "          target: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["DIES"]
    assert chains[0].verdict.render().startswith("DIES (heuristic):")
    assert "execFile(" in chains[0].verdict.reason


def test_a_js_action_with_exec_and_a_template_literal_on_the_input_is_suspect(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/js-exec-template@v1\n        with:\n"
            "          directory: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["SUSPECT"]
    assert "template literal" in chains[0].verdict.reason


def test_a_js_action_with_no_shell_pattern_is_unknown_with_the_documented_wording(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: example/js-opaque-action@v1\n        with:\n"
            "          note: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert chains[0].verdict.render() == "UNKNOWN: JavaScript action, no shell pattern matched"


def test_a_js_action_whose_main_file_is_missing_is_unknown(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    action = tmp_path / "x" / "nomain" / "v1"
    action.mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: n\ndescription: n\ninputs:\n  a:\n    description: a\nruns:\n"
        "  using: node20\n  main: dist/missing.js\n"
    )
    chains = analyse_text(
        workflow_with(
            "      - uses: x/nomain@v1\n        with:\n          a: ${{ github.event.issue.title }}"
        ),
        actions=tmp_path,
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "main file dist/missing.js not found" in chains[0].verdict.reason


def test_a_js_action_reading_a_tainted_env_var_by_name_is_analysed(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    action = tmp_path / "x" / "envreader" / "v1"
    (action / "dist").mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: e\ndescription: e\nruns:\n  using: node20\n  main: dist/index.js\n"
    )
    (action / "dist" / "index.js").write_text(
        'const { execSync } = require("node:child_process");\n'
        "const body = process.env.BODY;\nexecSync(`echo ${body}`);\n"
    )
    chains = analyse_text(
        workflow_with(
            "      - uses: x/envreader@v1", env="  BODY: ${{ github.event.comment.body }}"
        ),
        actions=tmp_path,
    )
    assert kinds(chains) == ["SUSPECT"]
    assert carriers(chains[0]) == ["env BODY", "process.env.BODY"]


def test_an_unsupported_runs_using_is_unknown(analyse_text: AnalyseText, tmp_path: Path) -> None:
    action = tmp_path / "x" / "weird" / "v1"
    action.mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: w\ndescription: w\ninputs:\n  a:\n    description: a\nruns:\n  using: perl\n"
    )
    chains = analyse_text(
        workflow_with(
            "      - uses: x/weird@v1\n        with:\n          a: ${{ github.event.issue.title }}"
        ),
        actions=tmp_path,
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "not supported" in chains[0].verdict.reason


# --- the JS heuristic on its own ------------------------------------------------------


def test_js_heuristic_flags_shell_true() -> None:
    verdict = js_heuristic('spawn("x", [a], { shell: true })', input_names=["a"])
    assert verdict.kind == "SUSPECT"
    assert "shell: true" in verdict.reason


def test_js_heuristic_leaves_exec_untied_to_the_input_as_unknown() -> None:
    verdict = js_heuristic(
        'const p = core.getInput("prompt");\nexec(`ls ${somethingElse}`);', input_names=["prompt"]
    )
    assert verdict.kind == "UNKNOWN"
    assert "could not be tied" in verdict.reason


def test_js_heuristic_ties_exec_to_a_process_env_read_inside_the_template() -> None:
    verdict = js_heuristic("exec(`ls ${process.env.DIR}`);", env_names=["DIR"])
    assert verdict.kind == "SUSPECT"


def test_js_heuristic_names_the_file_in_the_reason_when_asked() -> None:
    verdict = js_heuristic("execSync(`x`)", where="dist/index.js")
    assert "at dist/index.js:1" in verdict.reason


def test_js_heuristic_treats_argv_as_the_reference_when_arguments_are_tainted() -> None:
    verdict = js_heuristic('const a = process.argv[2];\nexecFile("ls", [a]);', argv=True)
    assert verdict.kind == "DIES"
    assert verdict.carrier == "process.argv"


def test_js_references_env_sees_dot_bracket_and_destructuring_forms() -> None:
    assert js_references_env("x = process.env.BODY", "BODY") == 1
    assert js_references_env('x = process.env["BODY"]', "BODY") == 1
    assert js_references_env("const { BODY } = process.env;", "BODY") == 1
    assert js_references_env("const { OTHER } = process.env;", "BODY") is None


# --- github-script ---------------------------------------------------------------------


def test_github_script_with_a_tainted_expression_in_script_is_shell(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: actions/github-script@v7\n        with:\n          script: |\n"
            '            const t = "${{ github.event.issue.title }}";\n            core.info(t);'
        )
    )
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[0].carrier == "with script"
    assert chains[0].hops[0].line == 11


def test_github_script_reading_a_tainted_env_var_goes_through_the_js_heuristic(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: actions/github-script@v7\n        with:\n          script: |\n"
            "            const body = process.env.BODY;\n"
            "            require('child_process').execSync(`echo ${body}`);",
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["SUSPECT"]
    assert chains[0].verdict.heuristic


def test_github_script_that_never_touches_the_taint_produces_nothing(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - uses: actions/github-script@v7\n        with:\n"
            "          script: core.info('hello')"
        )
    )
    assert chains == []


# --- following scripts ----------------------------------------------------------------


def test_the_hero_chain_follows_env_with_inputs_env_script_and_node_to_argv() -> None:
    chains = analyse(ROOT / "tests" / "fixtures" / "workflows" / "moved_and_died.yml")
    assert kinds(chains) == ["DIES"]
    assert carriers(chains[0]) == [
        "env BODY",
        "with prompt",
        "inputs.prompt",
        "env HELPER_PROMPT",
        "run",
        "script run-helper.sh",
        "process.env.HELPER_PROMPT",
    ]
    assert chains[0].verdict.heuristic
    assert "spawn(" in chains[0].verdict.reason


def test_a_script_that_cannot_be_located_is_unknown(analyse_text: AnalyseText) -> None:
    chains = analyse_text(
        workflow_with(
            "      - run: bash ./scripts/missing.sh", env="  BODY: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "could not be located" in chains[0].verdict.reason


def test_a_script_in_the_workspace_is_followed_with_positional_arguments(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "run.sh").write_text('#!/bin/bash\nCMD="$1"\neval "$CMD"\n')
    chains = analyse_text(
        workflow_with(
            '      - run: ./scripts/run.sh "$BODY"', env="  BODY: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[-1].carrier == "script run.sh"
    assert chains[0].hops[-1].line == 3


def test_a_script_that_only_uses_its_argument_as_a_value_dies(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "say.sh").write_text('echo "$1"\n')
    chains = analyse_text(
        workflow_with(
            '      - run: bash say.sh "$BODY"', env="  BODY: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["DIES"]


def test_a_python_script_is_not_followed_and_says_so(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "tool.py").write_text("import os\n")
    chains = analyse_text(
        workflow_with(
            '      - run: python tool.py "$BODY"', env="  BODY: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "not a shell or JavaScript file" in chains[0].verdict.reason


def test_a_script_that_invokes_itself_is_reported_as_a_cycle(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "loop.sh").write_text('bash loop.sh "$1"\n')
    chains = analyse_text(
        workflow_with(
            '      - run: bash loop.sh "$BODY"', env="  BODY: ${{ github.event.comment.body }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert chains[0].verdict.reason.startswith("cycle:")


def test_script_following_respects_the_depth_limit(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "a.sh").write_text('bash b.sh "$1"\n')
    (tmp_path / "b.sh").write_text('eval "$1"\n')
    chains = analyse_text(
        workflow_with(
            '      - run: bash a.sh "$BODY"', env="  BODY: ${{ github.event.comment.body }}"
        ),
        max_depth=1,
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "depth limit 1" in chains[0].verdict.reason


def test_a_script_reached_through_env_only_that_never_names_the_var_produces_no_chain_of_its_own(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "quiet.sh").write_text("echo quiet\n")
    chains = analyse_text(
        workflow_with(
            '      - run: |\n          bash quiet.sh\n          echo "$BODY"',
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["DIES"]


def test_a_node_script_reached_from_a_shell_script_is_analysed_by_the_js_heuristic(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "run.sh").write_text('node "$GITHUB_WORKSPACE/tool.js"\n')
    (tmp_path / "tool.js").write_text(
        'const { execSync } = require("node:child_process");\nexecSync(`x ${process.env.BODY}`);\n'
    )
    chains = analyse_text(
        workflow_with("      - run: bash run.sh", env="  BODY: ${{ github.event.comment.body }}")
    )
    assert kinds(chains) == ["SUSPECT"]


# --- reusable workflows ----------------------------------------------------------------


def test_a_reusable_workflow_receives_with_taint_as_inputs_one_level_deep() -> None:
    chains = analyse(REPO / ".github" / "workflows" / "caller.yml")
    assert kinds(chains) == ["SHELL"]
    assert carriers(chains[0]) == ["with title", "inputs.title", "run"]
    assert chains[0].hops[1].file.endswith("called.yml")


def test_a_reusable_workflow_scanned_on_its_own_labels_inputs_semi_trusted() -> None:
    chains = analyse(REPO / ".github" / "workflows" / "called.yml")
    assert kinds(chains) == ["SHELL"]
    assert not chains[0].counts


def test_a_reusable_workflow_missing_locally_is_unknown(analyse_text: AnalyseText) -> None:
    text = (
        "name: t\non:\n  issues:\njobs:\n  call:\n"
        "    uses: someone/else/.github/workflows/x.yml@v1\n"
        "    with:\n      t: ${{ github.event.issue.title }}\n"
    )
    chains = analyse_text(text)
    assert kinds(chains) == ["UNKNOWN"]
    assert "reusable workflow" in chains[0].verdict.reason


def test_a_reusable_workflow_nested_beyond_one_level_is_unknown(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "top.yml").write_text(
        "name: top\non:\n  issues:\njobs:\n  a:\n    uses: ./.github/workflows/mid.yml\n"
        "    with:\n      t: ${{ github.event.issue.title }}\n"
    )
    (workflows / "mid.yml").write_text(
        "name: mid\non:\n  workflow_call:\n    inputs:\n      t:\n        type: string\n"
        "jobs:\n  b:\n    uses: ./.github/workflows/leaf.yml\n    with:\n      t: ${{ inputs.t }}\n"
    )
    (workflows / "leaf.yml").write_text(
        "name: leaf\non:\n  workflow_call:\n    inputs:\n      t:\n        type: string\n"
        'jobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ inputs.t }}"\n'
    )
    analyzer = Analyzer(LocalDirResolver(None), cwd=ROOT)
    chains = analyzer.analyse_file(workflows / "top.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "beyond one level" in chains[0].verdict.reason


def test_a_reusable_workflow_exports_tainted_outputs_to_the_caller(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "top.yml").write_text(
        "name: top\non:\n  issues:\njobs:\n  a:\n    uses: ./.github/workflows/inner.yml\n"
        "    with:\n      t: ${{ github.event.issue.title }}\n"
        "  b:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "${{ needs.a.outputs.echoed }}"\n'
    )
    (workflows / "inner.yml").write_text(
        "name: inner\non:\n  workflow_call:\n    inputs:\n      t:\n        type: string\n"
        "    outputs:\n      echoed:\n        value: ${{ jobs.j.outputs.e }}\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    outputs:\n      e: ${{ inputs.t }}\n"
        "    steps:\n      - run: echo hi\n"
    )
    analyzer = Analyzer(LocalDirResolver(None), cwd=ROOT)
    chains = analyzer.analyse_file(workflows / "top.yml")
    assert kinds(chains) == ["SHELL"]
    assert "outputs.echoed" in carriers(chains[0])


def test_parse_workflow_reads_reusable_job_fields() -> None:
    text = (REPO / ".github" / "workflows" / "caller.yml").read_text()
    workflow = parse_workflow(text, REPO / ".github" / "workflows" / "caller.yml")
    assert workflow.jobs[0].uses is not None
    assert workflow.repo_root == REPO.resolve()


# --- references that must never leave the actions directory -------------------


@pytest.mark.parametrize(
    "uses",
    [
        "example/direct@../../../outside",
        "a/b/../../../outside@v1",
        "../evil/repo@v1",
        "evil/../repo@v1",
        "evil/repo@-oops",
        "evil/repo@/etc/passwd",
        "evil/repo@refs/../../x",
        "evil/repo@v1 v2",
        "evil/repo@",
        "evil/repo@v1\\x",
        "evil/repo/../x@v1",
        "./../../outside",
        "./a/../../outside",
    ],
)
def test_references_that_could_escape_the_actions_directory_are_invalid(uses: str) -> None:
    assert parse_uses(uses).kind == "invalid"


def test_a_ref_with_a_slash_is_still_a_valid_pinned_reference() -> None:
    ref = parse_uses("owner/repo@releases/v1")
    assert ref.kind == "repo"
    assert ref.ref == "releases/v1"


def test_the_resolver_never_leaves_the_actions_directory_even_through_a_symlink(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside" / "repo" / "v1"
    outside.mkdir(parents=True)
    (outside / "action.yml").write_text("runs:\n  using: composite\n")
    actions = tmp_path / "actions"
    actions.mkdir()
    (actions / "evil").symlink_to(tmp_path / "outside")
    assert LocalDirResolver(actions).action(parse_uses("evil/repo@v1"), None) is None


def test_a_local_reference_never_leaves_the_repository_even_through_a_symlink(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "action.yml").write_text("runs:\n  using: composite\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "link").symlink_to(outside)
    assert LocalDirResolver(None).action(parse_uses("./link"), repo) is None


def test_a_ref_that_climbs_out_is_unknown_and_the_outside_action_is_never_read() -> None:
    chains = analyse(TRAVERSAL / "workflows" / "traversal_ref.yml", actions=TRAVERSAL / "actions")
    assert kinds(chains) == ["UNKNOWN"]
    assert "could not be parsed" in chains[0].verdict.reason
    assert not any("outside" in hop.file for hop in chains[0].hops)


def test_a_path_that_climbs_out_is_unknown() -> None:
    chains = analyse(TRAVERSAL / "workflows" / "traversal_path.yml", actions=TRAVERSAL / "actions")
    assert kinds(chains) == ["UNKNOWN"]
    assert "could not be parsed" in chains[0].verdict.reason


def test_a_non_utf8_action_manifest_is_an_action_error_not_a_traceback(tmp_path: Path) -> None:
    (tmp_path / "action.yml").write_bytes(b"\xff\xfename: x\n")
    with pytest.raises(ActionError):
        load_action(tmp_path)


# --- JavaScript and github-script outputs are over-approximated --------------------


def test_a_js_action_that_received_a_tainted_input_taints_its_declared_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: example/js-output-action@v1\n        with:\n"
            "          prompt: ${{ github.event.comment.body }}\n"
            "      - run: echo ${{ steps.x.outputs.result }}"
        )
    )
    assert kinds(chains) == ["DIES", "SHELL"]
    assert "outputs.result" in carriers(chains[1])
    assert any("over-approximation" in hop.detail for hop in chains[1].hops)


def test_a_js_action_without_declared_outputs_taints_the_wildcard(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    action = tmp_path / "x" / "undeclared" / "v1"
    (action / "dist").mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: u\ndescription: u\ninputs:\n  a:\n    description: a\nruns:\n"
        "  using: node20\n  main: dist/index.js\n"
    )
    (action / "dist" / "index.js").write_text(
        'const core = require("@actions/core");\ncore.setOutput("anything", core.getInput("a"));\n'
    )
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: x/undeclared@v1\n        with:\n"
            "          a: ${{ github.event.issue.title }}\n"
            '      - run: eval "${{ steps.x.outputs.anything }}"'
        ),
        actions=tmp_path,
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]


def test_a_js_action_reading_a_tainted_env_var_by_name_taints_its_outputs(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    action = tmp_path / "x" / "envout" / "v1"
    (action / "dist").mkdir(parents=True)
    (action / "action.yml").write_text(
        "name: e\ndescription: e\noutputs:\n  out:\n    description: o\nruns:\n"
        "  using: node20\n  main: dist/index.js\n"
    )
    (action / "dist" / "index.js").write_text(
        'const core = require("@actions/core");\ncore.setOutput("out", process.env.BODY);\n'
    )
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: x/envout@v1\n"
            "      - run: echo ${{ steps.x.outputs.out }}",
            env="  BODY: ${{ github.event.comment.body }}",
        ),
        actions=tmp_path,
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]


def test_a_js_action_with_a_clean_input_does_not_taint_its_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: example/js-output-action@v1\n        with:\n"
            "          prompt: plain\n"
            "      - run: echo ${{ steps.x.outputs.result }}"
        )
    )
    assert chains == []


def test_github_script_that_sets_an_output_from_a_tainted_env_var_taints_the_step_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: g\n        uses: actions/github-script@v7\n        env:\n"
            "          BODY: ${{ github.event.comment.body }}\n        with:\n"
            "          script: core.setOutput('x', process.env.BODY)\n"
            '      - run: eval "${{ steps.g.outputs.x }}"'
        )
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]
    assert "steps.g.outputs.*" in carriers(chains[1])


def test_github_script_with_an_interpolated_expression_taints_its_result(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: g\n        uses: actions/github-script@v7\n        with:\n"
            '          script: return "${{ github.event.comment.body }}"\n'
            "      - run: echo ${{ steps.g.outputs.result }}"
        )
    )
    assert kinds(chains) == ["SHELL", "SHELL"]


def test_a_followed_js_script_that_writes_the_output_file_triggers_the_over_approximation(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: example/composite-js-output@v1\n        with:\n"
            "          prompt: ${{ github.event.comment.body }}\n"
            '      - run: eval "${{ steps.x.outputs.result }}"'
        )
    )
    assert kinds(chains) == ["DIES", "SHELL"]
    assert "outputs.result" in carriers(chains[1])


def test_a_followed_js_script_that_calls_set_output_triggers_the_over_approximation(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    (tmp_path / "tool.js").write_text(
        'const core = require("@actions/core");\ncore.setOutput("v", process.env.BODY);\n'
    )
    chains = analyse_text(
        workflow_with(
            "      - id: s\n        run: node tool.js\n"
            '      - run: eval "${{ steps.s.outputs.v }}"',
            env="  BODY: ${{ github.event.comment.body }}",
        )
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]


def test_a_reusable_workflow_with_broken_yaml_is_unknown_not_a_traceback(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "top.yml").write_text(
        "name: top\non:\n  issues:\njobs:\n  a:\n    uses: ./.github/workflows/broken.yml\n"
        "    with:\n      t: ${{ github.event.issue.title }}\n"
    )
    (workflows / "broken.yml").write_text("on: [unclosed\n")
    analyzer = Analyzer(LocalDirResolver(None), cwd=ROOT)
    chains = analyzer.analyse_file(workflows / "top.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "broken.yml" in chains[0].verdict.reason


# --- owner and repo may not start with a dash --------------------------------------------


@pytest.mark.parametrize("uses", ["-owner/repo@v1", "owner/-repo@v1", "-/x@v1", "x/-@v1"])
def test_an_owner_or_repo_starting_with_a_dash_is_invalid(uses: str) -> None:
    assert parse_uses(uses).kind == "invalid"


def test_a_dash_inside_an_owner_or_repo_is_still_valid() -> None:
    assert parse_uses("my-org/my-repo@v1").kind == "repo"


# --- process.env through an alias or destructuring ---------------------------------------


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("const env = process.env;\ncore.setOutput('r', env.HELPER_PROMPT);", 2),
        ("let env = process.env;\nrun(env['HELPER_PROMPT']);", 2),
        ('var e = process.env\nconsole.log(e["HELPER_PROMPT"])', 2),
        ("const env = process.env\n\n\nconsole.log(env.HELPER_PROMPT)", 4),
        ("const { HELPER_PROMPT } = process.env;\nrun(HELPER_PROMPT);", 1),
        ("const { HELPER_PROMPT: p } = process.env;\nrun(p);", 1),
    ],
)
def test_js_references_env_sees_an_alias_of_process_env_and_destructuring(
    text: str, line: int
) -> None:
    assert js_references_env(text, "HELPER_PROMPT") == line


def test_an_alias_of_process_env_used_for_another_name_is_not_a_reference() -> None:
    assert js_references_env("const env = process.env;\nconsole.log(env.OTHER);", "BODY") is None


def test_a_variable_called_env_that_is_not_process_env_is_not_an_alias() -> None:
    assert js_references_env("const env = {};\nconsole.log(env.BODY);", "BODY") is None


def test_the_heuristic_ties_an_exec_template_to_a_value_read_through_an_alias() -> None:
    text = (
        'const { exec } = require("child_process");\nconst env = process.env;\n'
        "const p = env.BODY;\nexec(`echo ${p}`);\n"
    )
    verdict = js_heuristic(text, env_names=["BODY"])
    assert verdict.kind == "SUSPECT"
    assert "template literal" in verdict.reason
    assert verdict.reference_line == 3


def test_a_js_action_reading_env_through_an_alias_taints_its_outputs(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: example/js-env-alias@v1\n        env:\n"
            "          HELPER_PROMPT: ${{ github.event.comment.body }}\n"
            "      - run: echo ${{ steps.x.outputs.r }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]


# --- outputs a JavaScript action sets without declaring them ---------------------------------


def test_a_js_action_output_the_manifest_does_not_declare_is_tainted_too(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: example/js-undeclared-output@v1\n        env:\n"
            "          HELPER_PROMPT: ${{ github.event.comment.body }}\n"
            "      - run: echo ${{ steps.x.outputs.secret }}"
        )
    )
    assert kinds(chains) == ["UNKNOWN", "SHELL"]
    assert "outputs.*" in carriers(chains[1])


def test_a_declared_output_is_carried_by_its_own_hop_and_reported_once(
    analyse_text: AnalyseText,
) -> None:
    chains = analyse_text(
        workflow_with(
            "      - id: x\n        uses: example/js-output-action@v1\n        with:\n"
            "          prompt: ${{ github.event.comment.body }}\n"
            "      - run: echo ${{ steps.x.outputs.result }}"
        )
    )
    assert kinds(chains) == ["DIES", "SHELL"]
    assert "outputs.result" in carriers(chains[1])
    assert "outputs.*" not in carriers(chains[1])


# --- every file the tool opens is checked against a root, symlinks resolved -----------------

MARKER = "outside_marker_never_printed"
OUTSIDE_MANIFEST = (
    "name: o\ndescription: must never be read\ninputs:\n  x:\n    description: t\nruns:\n"
    "  using: composite\n  steps:\n    - shell: bash\n"
    f'      run: eval "${{{{ inputs.x }}}}" {MARKER}\n'
)


def leaked(chains: list[object]) -> bool:
    from taint_trail.model import Chain

    text = " ".join(
        f"{hop.file} {hop.carrier} {hop.detail} {chain.verdict.reason}"
        for chain in chains
        if isinstance(chain, Chain)
        for hop in chain.hops
    ) + " ".join(chain.verdict.reason for chain in chains if isinstance(chain, Chain))
    return MARKER in text


def test_the_outside_fixtures_carry_the_marker_that_must_never_be_printed() -> None:
    assert MARKER in (TRAVERSAL / "outside" / "leak" / "leak.sh").read_text()
    assert MARKER in (TRAVERSAL / "outside" / "leak" / "leak.js").read_text()


def test_a_manifest_that_is_a_symlink_outside_the_action_directory_is_never_read(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "action.yml").write_text(OUTSIDE_MANIFEST)
    actions = tmp_path / "actions"
    directory = actions / "example" / "linked-manifest" / "v1"
    directory.mkdir(parents=True)
    os.symlink(outside / "action.yml", directory / "action.yml")
    chains = analyse_text(
        workflow_with(
            "      - uses: example/linked-manifest@v1\n        with:\n"
            "          x: ${{ github.event.comment.body }}"
        ),
        actions=actions,
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "outside" in chains[0].verdict.reason
    assert not leaked(list(chains))


def test_a_runs_main_that_climbs_out_of_the_action_directory_is_never_read() -> None:
    chains = analyse(TRAVERSAL / "workflows" / "main_climbs.yml", actions=TRAVERSAL / "actions")
    assert kinds(chains) == ["UNKNOWN"]
    assert "outside" in chains[0].verdict.reason
    assert not leaked(list(chains))


def test_a_runs_main_that_is_a_symlink_outside_the_action_directory_is_never_read(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.js").write_text(
        f'require("child_process").execSync(`echo ${{process.env.BODY}} {MARKER}`);\n'
    )
    actions = tmp_path / "actions"
    directory = actions / "example" / "linked-main" / "v1"
    (directory / "dist").mkdir(parents=True)
    (directory / "action.yml").write_text(
        "name: m\ndescription: m\ninputs:\n  x:\n    description: t\nruns:\n"
        "  using: node20\n  main: dist/index.js\n"
    )
    os.symlink(outside / "leak.js", directory / "dist" / "index.js")
    chains = analyse_text(
        workflow_with(
            "      - uses: example/linked-main@v1\n        with:\n"
            "          x: ${{ github.event.comment.body }}",
            env="  BODY: ${{ github.event.comment.body }}",
        ),
        actions=actions,
    )
    assert kinds(chains) == ["UNKNOWN", "UNKNOWN"]
    assert "outside" in chains[0].verdict.reason
    assert "linked-main" in chains[1].verdict.reason
    assert not leaked(list(chains))


def test_a_followed_script_that_climbs_out_of_the_action_directory_is_never_read() -> None:
    chains = analyse(TRAVERSAL / "workflows" / "script_climbs.yml", actions=TRAVERSAL / "actions")
    assert kinds(chains) == ["UNKNOWN"]
    assert "outside the scanned roots" in chains[0].verdict.reason
    assert not leaked(list(chains))


def test_a_followed_script_that_is_a_symlink_outside_every_root_is_never_read(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.sh").write_text(f'eval "$BODY" {MARKER}\n')
    actions = tmp_path / "actions"
    directory = actions / "example" / "linked-script" / "v1"
    (directory / "scripts").mkdir(parents=True)
    (directory / "action.yml").write_text(
        "name: s\ndescription: s\nruns:\n  using: composite\n  steps:\n    - shell: bash\n"
        '      run: bash "$GITHUB_ACTION_PATH/scripts/run.sh"\n'
    )
    os.symlink(outside / "leak.sh", directory / "scripts" / "run.sh")
    (tmp_path / "repo" / ".github" / "workflows").mkdir(parents=True)
    chains = analyse_text(
        workflow_with(
            "      - uses: example/linked-script@v1", env="  BODY: ${{ github.event.comment.body }}"
        ),
        actions=actions,
        name="repo/.github/workflows/wf.yml",
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "outside the scanned roots" in chains[0].verdict.reason
    assert not leaked(list(chains))


def test_a_script_named_by_an_absolute_path_is_never_read(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.sh").write_text(f'eval "$BODY" {MARKER}\n')
    (tmp_path / "repo" / ".github" / "workflows").mkdir(parents=True)
    chains = analyse_text(
        workflow_with(
            f"      - run: bash {outside / 'leak.sh'}",
            env="  BODY: ${{ github.event.comment.body }}",
        ),
        name="repo/.github/workflows/wf.yml",
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "absolute" in chains[0].verdict.reason
    assert not leaked(list(chains))


def test_a_working_directory_that_climbs_out_of_the_repository_is_never_entered() -> None:
    chains = analyse(TRAVERSAL / "repo" / ".github" / "workflows" / "wd_climb.yml")
    assert kinds(chains) == ["UNKNOWN"]
    assert "working-directory" in chains[0].verdict.reason
    assert not leaked(list(chains))


def test_a_working_directory_that_is_a_symlink_outside_the_repository_is_never_entered(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.sh").write_text(f'eval "$BODY" {MARKER}\n')
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    os.symlink(outside, repo / "scripts")
    chains = analyse_text(
        workflow_with(
            "      - working-directory: scripts\n        run: bash leak.sh",
            env="  BODY: ${{ github.event.comment.body }}",
        ),
        name="repo/.github/workflows/wf.yml",
    )
    assert kinds(chains) == ["UNKNOWN"]
    assert "working-directory" in chains[0].verdict.reason
    assert not leaked(list(chains))


def test_a_working_directory_inside_the_repository_is_still_followed(
    analyse_text: AnalyseText, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "scripts" / "run.sh").write_text('eval "$BODY"\n')
    chains = analyse_text(
        workflow_with(
            "      - working-directory: scripts\n        run: bash run.sh",
            env="  BODY: ${{ github.event.comment.body }}",
        ),
        name="repo/.github/workflows/wf.yml",
    )
    assert kinds(chains) == ["SHELL"]
    assert chains[0].hops[-1].file.endswith("scripts/run.sh")
