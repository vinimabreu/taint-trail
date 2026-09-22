"""Shapes the third adversarial review re-broke, pinned one variant at a time.

Each block matches a numbered finding: a shell or interpreter named by its full
path, a group that closes with a continuation on the closing line, a ``case``
pattern inside a subshell, a heredoc piped to an interpreter with a script file,
a pipe into an interpreter with trailing redirects and flags, redirected loops
and conditionals, the sanitiser idiom, more command-position shapes, ``|&`` and
a process substitution.
"""

from __future__ import annotations

import pytest

from taint_trail.sinks import HitKind, ShellHit, scan_shell


def hits(script: str, *tainted: str) -> list[ShellHit]:
    return scan_shell(script, tainted).hits


def only(script: str, *tainted: str) -> ShellHit:
    found = [h for h in hits(script, *tainted) if h.kind is not HitKind.INVOKE]
    assert len(found) == 1, found
    return found[0]


# --- 1. shells and interpreters named by full path ------------------------------

FULL_PATH_SHELL = [
    '/bin/bash -c "$BODY"',
    '/bin/sh -c "echo $BODY"',
    '/usr/bin/env bash -c "$BODY"',
    'echo "$BODY" | /bin/sh',
    'echo "$BODY" | /bin/bash',
    'echo "$BODY" | /usr/bin/python3',
    '/usr/bin/python3 -c "import os; os.system(os.environ[\\"X\\"])" "$BODY"',
    'bash -o pipefail -c "$BODY"',
    'sudo /bin/bash -c "$BODY"',
]


@pytest.mark.parametrize("line", FULL_PATH_SHELL)
def test_a_shell_or_interpreter_by_full_path_is_a_shell_hit(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.SHELL, line


def test_a_full_path_tool_that_is_not_a_shell_stays_a_value() -> None:
    assert only('/usr/local/bin/mytool -c config "$BODY"', "BODY").kind is HitKind.VALUE


# --- 2. group close with a continuation on the closing line ---------------------

_BODY_BLOCK = '  echo "x<<EOF"\n  echo "$BODY"\n  echo "EOF"'
CONTINUATION_CLOSE_SPOOF = {
    "backslash then redirect": f'{{\n{_BODY_BLOCK}\n}} \\\n  >> "$GITHUB_OUTPUT"',
    "paren backslash then redirect": f'(\n{_BODY_BLOCK}\n) \\\n  >> "$GITHUB_OUTPUT"',
    "pipe then tee": f'{{\n{_BODY_BLOCK}\n}} |\n  tee -a "$GITHUB_OUTPUT"',
    "redirect op backslash then target": f'{{\n{_BODY_BLOCK}\n}} >> \\\n  "$GITHUB_OUTPUT"',
}


@pytest.mark.parametrize(
    "script", CONTINUATION_CLOSE_SPOOF.values(), ids=list(CONTINUATION_CLOSE_SPOOF)
)
def test_a_group_closing_with_a_continuation_still_reaches_the_runner_file(script: str) -> None:
    assert only(script, "BODY").kind is HitKind.SPOOF, script


def test_a_group_closing_then_piped_to_a_shell_over_a_newline_is_a_shell_hit() -> None:
    assert only('{\n  echo "$BODY"\n} |\n  bash', "BODY").kind is HitKind.SHELL


def test_a_group_closing_then_piped_to_a_stdin_interpreter_over_a_newline_is_a_shell_hit() -> None:
    assert only('{\n  echo "$BODY"\n} |\n  sh -s', "BODY").kind is HitKind.SHELL


# --- 3. case patterns inside a ( ) subshell -------------------------------------


def test_a_case_pattern_inside_a_subshell_does_not_close_it_early() -> None:
    script = (
        '(\n  echo "x<<EOF"\n  case "$k" in\n    a) echo "$BODY";;\n'
        '  esac\n  echo "EOF"\n) >> "$GITHUB_OUTPUT"'
    )
    hit = only(script, "BODY")
    assert hit.kind is HitKind.SPOOF, script


def test_a_one_line_case_pattern_inside_a_subshell_does_not_close_it_early() -> None:
    script = '( echo "x<<EOF"; case $k in a) echo "$BODY";; esac; echo "EOF"; ) >> "$GITHUB_OUTPUT"'
    assert only(script, "BODY").kind is HitKind.SPOOF, script


def test_a_case_pattern_inside_a_brace_group_stays_green() -> None:
    script = (
        '{\n  echo "x<<EOF"\n  case "$k" in\n    a) echo "$BODY";;\n'
        '  esac\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"'
    )
    assert only(script, "BODY").kind is HitKind.SPOOF


# --- 4. heredoc piped to an interpreter with a script file ----------------------

HEREDOC_TO_SCRIPT_VALUE = [
    "cat <<EOF | python3 parse.py\n$BODY\nEOF\n",
    "cat <<EOF | node app.js\n$BODY\nEOF\n",
    "cat <<EOF | python3 -m json.tool\n$BODY\nEOF\n",
    "cat <<EOF | perl -ne '...'\n$BODY\nEOF\n",
]


@pytest.mark.parametrize("script", HEREDOC_TO_SCRIPT_VALUE)
def test_a_heredoc_piped_to_an_interpreter_with_a_script_is_a_value(script: str) -> None:
    kinds = {h.kind for h in hits(script, "BODY") if h.kind is not HitKind.INVOKE}
    assert HitKind.SHELL not in kinds, (script, kinds)


def test_a_heredoc_piped_to_a_bare_interpreter_is_still_a_shell_hit() -> None:
    assert only("cat <<EOF | python3\n$BODY\nEOF\n", "BODY").kind is HitKind.SHELL


# --- 5. pipe into an interpreter with trailing redirects, args and prefixes -----

PIPE_INTERP_SHELL = [
    'echo "$BODY" | python3 2>/dev/null',
    'echo "$BODY" | python3 > out.txt',
    'echo "$BODY" | node 2>/dev/null',
    'echo "$BODY" | python3 - arg',
    'echo "$BODY" | python3 -u',
    'echo "$BODY" | python3 -I -',
    'echo "$BODY" | sudo -E python3',
    'echo "$BODY" | env python3',
]


@pytest.mark.parametrize("line", PIPE_INTERP_SHELL)
def test_a_pipe_into_an_interpreter_with_a_tail_is_a_shell_hit(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.SHELL, line


def test_a_pipe_into_an_interpreter_given_a_script_with_a_redirect_stays_a_value() -> None:
    assert only('echo "$BODY" | python3 script.py 2>/dev/null', "BODY").kind is HitKind.VALUE


# --- 6. redirected loops and conditionals ---------------------------------------

REDIRECTED_COMPOUND_SPOOF = {
    "for done redirect": 'for k in a b; do\n  echo "$k=$BODY"\ndone >> "$GITHUB_OUTPUT"',
    "for done tee": 'for k in a b; do\n  echo "$k=$BODY"\ndone | tee -a "$GITHUB_OUTPUT"',
    "while done redirect": 'while read -r l; do\n  echo "k=$BODY"\ndone >> "$GITHUB_OUTPUT"',
    "if fi redirect": 'if true; then\n  echo "k=$BODY"\nfi >> "$GITHUB_OUTPUT"',
}


@pytest.mark.parametrize(
    "script", REDIRECTED_COMPOUND_SPOOF.values(), ids=list(REDIRECTED_COMPOUND_SPOOF)
)
def test_a_redirected_loop_or_conditional_reaches_the_runner_file(script: str) -> None:
    assert only(script, "BODY").kind is HitKind.SPOOF, script


def test_an_unredirected_loop_body_stays_a_value() -> None:
    assert only('for k in a b; do\n  echo "$k=$BODY"\ndone', "BODY").kind is HitKind.VALUE


def test_a_loop_redirected_to_a_plain_file_stays_a_value() -> None:
    assert only('for k in a b; do\n  echo "$BODY"\ndone >> notes.txt', "BODY").kind is HitKind.VALUE


# --- 8. the sanitiser idiom: value only left of the pipe, static program --------

SANITISER_VALUE = [
    "echo \"$BODY\" | perl -pe 's/\\n//g'",
    "echo \"$BODY\" | perl -ne 'print if /x/'",
    "echo \"$BODY\" | python3 -c 'import sys; print(sys.stdin.read())'",
    "echo \"$BODY\" | node -e 'process.stdin.pipe(process.stdout)'",
    "echo \"$BODY\" | sed -e 's/x//'",
]


@pytest.mark.parametrize("line", SANITISER_VALUE)
def test_a_static_program_reading_stdin_treats_the_piped_value_as_data(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.VALUE, line


def test_a_double_quoted_program_that_names_the_value_is_still_a_shell_hit() -> None:
    assert only('perl -e "print $BODY"', "BODY").kind is HitKind.SHELL


# --- 9. more command positions --------------------------------------------------

COMMAND_POSITION_SHELL = [
    'env FOO=1 "$BODY"',
    'FOO=1 "$BODY"',
    'nohup "$BODY" &',
    'echo x | "$BODY"',
    'if "$BODY"; then echo hi; fi',
    'while "$BODY"; do echo hi; done',
    'time "$BODY"',
    '! "$BODY"',
]


@pytest.mark.parametrize("line", COMMAND_POSITION_SHELL)
def test_the_value_in_command_position_runs_as_the_command(line: str) -> None:
    found = [h for h in hits(line, "BODY") if h.var == "BODY" and h.kind is not HitKind.INVOKE]
    assert found and found[0].kind is HitKind.SHELL, (line, found)


# --- 10. |& is a pipe -----------------------------------------------------------


def test_pipe_ampersand_into_a_shell_is_a_shell_hit() -> None:
    assert only('echo "$BODY" |& bash', "BODY").kind is HitKind.SHELL


# --- 16. process substitution in a script-argument position ---------------------


def test_a_process_substitution_fed_to_bash_is_a_shell_hit() -> None:
    hit = only('bash <(echo "$BODY")', "BODY")
    assert hit.kind is HitKind.SHELL
    assert "process substitution" in hit.reason
