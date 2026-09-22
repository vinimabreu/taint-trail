"""Shapes the fourth adversarial review re-broke, pinned one variant at a time.

Each block matches a numbered finding: an interpreter reading standard input
followed by another pipe stage, an arithmetic ``((`` in a redirected compound,
a program string that names the variable after the value was piped in, long
flags and ``-r module`` before standard input, and a here-string that is not a
script to follow.
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


# --- 1. a pipe into an interpreter followed by another pipe stage ---------------

PIPE_INTERP_THEN_STAGE_SHELL = [
    'echo "$BODY" | python3 | tee out.log',
    'echo "$BODY" | python3 2>&1 | tee log',
    'echo "$BODY" | node - | tee log',
    'echo "$BODY" | node | grep ok',
    'echo "$BODY" | php | cat',
    'echo "$BODY" | deno run - | tee log',
]


@pytest.mark.parametrize("line", PIPE_INTERP_THEN_STAGE_SHELL)
def test_a_pipe_stage_after_the_interpreter_does_not_hide_the_stdin_execution(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.SHELL, line


def test_a_heredoc_piped_to_an_interpreter_then_another_stage_is_a_shell_hit() -> None:
    assert only("cat <<EOF | python3 | tee log\n$BODY\nEOF\n", "BODY").kind is HitKind.SHELL


def test_a_pipe_into_an_interpreter_given_a_script_then_a_stage_stays_a_value() -> None:
    assert only('echo "$BODY" | python3 script.py | tee log', "BODY").kind is HitKind.VALUE


# --- 2. an arithmetic (( in a redirected compound ------------------------------

ARITH_COMPOUND_SPOOF = {
    "for arithmetic": 'for ((i=0;i<3;i++)); do\n  echo "k=$BODY"\ndone >> "$GITHUB_OUTPUT"',
    "while arithmetic": 'while (( i < 3 )); do\n  echo "k=$BODY"\ndone >> "$GITHUB_OUTPUT"',
    "if arithmetic": 'if (( n > 1 )); then\n  echo "k=$BODY"\nfi >> "$GITHUB_OUTPUT"',
    "if arithmetic on the value length": (
        'if (( ${#BODY} > 0 )); then\n  echo "body=$BODY"\nfi >> "$GITHUB_OUTPUT"'
    ),
    "arithmetic inside a redirected brace group": (
        '{\n  for ((i=0;i<3;i++)); do\n    echo "k=$BODY"\n  done\n} >> "$GITHUB_OUTPUT"'
    ),
}


@pytest.mark.parametrize("script", ARITH_COMPOUND_SPOOF.values(), ids=list(ARITH_COMPOUND_SPOOF))
def test_an_arithmetic_compound_whose_terminator_redirects_to_output_is_spoof(script: str) -> None:
    assert only(script, "BODY").kind is HitKind.SPOOF, script


def test_an_arithmetic_if_piped_to_a_shell_is_a_shell_hit() -> None:
    assert only('if (( n > 1 )); then\n  echo "$BODY"\nfi | bash', "BODY").kind is HitKind.SHELL


def test_an_arithmetic_expansion_before_a_write_does_not_open_a_group() -> None:
    script = 'n=$((1+2))\necho "k=$BODY" >> "$GITHUB_OUTPUT"'
    assert only(script, "BODY").kind is HitKind.SPOOF


# --- 4. the program string names the variable after the value was piped in ------

PIPED_THEN_NAMED_UNKNOWN = [
    'echo "$BODY" | python3 -c \'import os; os.system(os.environ["BODY"])\'',
    "echo \"$BODY\" | perl -e 'system($ENV{BODY})'",
    'echo "$BODY" | node -e \'require("child_process").execSync(process.env.BODY)\'',
]


@pytest.mark.parametrize("line", PIPED_THEN_NAMED_UNKNOWN)
def test_a_program_string_naming_the_piped_variable_is_unknown_not_a_value(line: str) -> None:
    found = [h for h in hits(line, "BODY") if h.kind is HitKind.UNKNOWN]
    assert found, line
    assert "by name" in found[0].reason


SANITISER_STILL_VALUE = [
    "echo \"$BODY\" | perl -pe 's/\\n//g'",
    "echo \"$BODY\" | python3 -c 'import sys; print(sys.stdin.read())'",
]


@pytest.mark.parametrize("line", SANITISER_STILL_VALUE)
def test_the_sanitiser_idiom_is_still_a_value_when_the_program_does_not_name_it(
    line: str,
) -> None:
    assert only(line, "BODY").kind is HitKind.VALUE, line


def test_envsubst_reading_a_single_quoted_reference_from_its_input_is_still_unknown() -> None:
    hit = only("echo 'echo $BODY' | envsubst | bash", "BODY")
    assert hit.kind is HitKind.UNKNOWN
    assert "by name" in hit.reason


# --- 6. long flags and -r module before standard input --------------------------

PIPE_INTERP_LONG_FLAG_SHELL = [
    'echo "$BODY" | node --input-type=module',
    'echo "$BODY" | node --no-warnings',
    'echo "$BODY" | node --no-warnings -',
    'echo "$BODY" | ruby --disable-gems',
    'echo "$BODY" | node -r esm -',
    'echo "$BODY" | node -r ts-node/register',
]


@pytest.mark.parametrize("line", PIPE_INTERP_LONG_FLAG_SHELL)
def test_a_long_flag_or_a_required_module_before_stdin_is_a_shell_hit(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.SHELL, line


PIPE_INTERP_LONG_FLAG_VALUE = [
    'echo "$BODY" | node --input-type=module app.js',
    'echo "$BODY" | node -r ts-node/register app.ts',
]


@pytest.mark.parametrize("line", PIPE_INTERP_LONG_FLAG_VALUE)
def test_a_long_flag_followed_by_a_script_file_stays_a_value(line: str) -> None:
    assert only(line, "BODY").kind is HitKind.VALUE, line


# --- 10. a here-string is not a script to follow --------------------------------


def test_a_here_string_after_a_shell_is_not_reported_as_an_unlocatable_script() -> None:
    found = hits('bash <<< "$BODY"', "BODY")
    assert all(h.kind is not HitKind.INVOKE for h in found), found
