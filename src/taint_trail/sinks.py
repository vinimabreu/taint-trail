"""Pattern scanner for shell scripts (``run:`` blocks and followed ``.sh`` files).

This is not a bash parser. It works pipeline by pipeline on a comment-stripped,
single-quote-masked view of each logical line, which is enough to tell three
situations apart with a name on each: a tainted variable that is re-parsed as
code (``eval``, ``-c`` strings, ``source``, ``xargs``, a pipe into a shell), a
tainted variable written to ``$GITHUB_OUTPUT`` or ``$GITHUB_ENV`` where a
newline or a static heredoc delimiter lets the value add keys, and a tainted
variable used only as a value. What the patterns do not understand is reported
as such by the analyser, never silently dropped.

Groups (``{ ...; }`` and ``( ...; )``) are tracked as real constructs: a brace
in command position opens one, the matching brace closes it wherever it sits,
and a redirect or pipe on the closing line applies to every command inside.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum


class HitKind(StrEnum):
    SHELL = "shell"
    SPOOF = "spoof"
    VALUE = "value"
    UNKNOWN = "unknown"
    INVOKE = "invoke"


@dataclass(frozen=True)
class Invocation:
    """A command that runs another file: ``bash x.sh``, ``./x.sh``, ``node x.js``."""

    interpreter: str | None
    target: str
    tainted_args: tuple[tuple[str, frozenset[str]], ...]
    """Positional name (``"1"``, ``"@"``, ``"*"``) to the tainted variables inside it."""


@dataclass(frozen=True)
class ShellHit:
    kind: HitKind
    line: int
    text: str
    var: str | None
    reason: str
    invocation: Invocation | None = None


@dataclass
class ShellScan:
    hits: list[ShellHit] = field(default_factory=list)
    writes_output: bool = False
    assignments: dict[str, str] = field(default_factory=dict)
    self_dir_vars: set[str] = field(default_factory=set)
    tainted: set[str] = field(default_factory=set)
    derived: dict[str, set[str]] = field(default_factory=dict)

    def origins(self, var: str) -> set[str]:
        """The originally tainted names behind ``var`` (itself if not derived)."""
        seen: set[str] = set()
        stack = [var]
        roots: set[str] = set()
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            parents = self.derived.get(name)
            if parents:
                stack.extend(parents)
            else:
                roots.add(name)
        return roots


Segment = tuple[int, str]
"""One piece of script text and the line it came from."""

_SHELLS = r"(?:bash|sh|zsh|dash|ksh)"
# Interpreters that take a program string on the command line.
_INTERPRETERS = r"(?:python[23]?|node|ruby|perl|bun)"
# Interpreters that run their standard input when given no file (or ``-``).
_STDIN_INTERPRETERS = r"(?:python[23]?|node|ruby|perl|php)"
_DENO_STDIN = r"deno\s+run(?:\s+-{1,2}[\w=,.-]+)*\s+-"
# A program can be named by its basename behind a path (``/bin/bash``), an
# ``env`` wrapper (``/usr/bin/env bash``) or ``sudo`` with its own options.
_PROG_PREFIX = r"(?:(?:sudo(?:\s+-\S+)*|env)\s+|[^\s|]*/)*"
# Options before ``-c``, allowing one that takes an argument (``bash -o pipefail -c``).
_PRE_C_OPTS = r"(?:\s+-\S+(?:\s+[^\s\-<>|]\S*)?)*"

_SHELL_C_RE = re.compile(rf"(?<![\w/-]){_PROG_PREFIX}{_SHELLS}\b{_PRE_C_OPTS}\s+-[A-Za-z]*c\b")
_INTERPRETER_PROGRAM_RE = re.compile(
    rf"(?<![\w/-]){_PROG_PREFIX}(?:{_INTERPRETERS}\b{_PRE_C_OPTS}\s+-[A-Za-z]*[ce]\b"
    rf"|php\b{_PRE_C_OPTS}\s+-r\b|deno\s+eval\b)"
)
_ENVSUBST_RE = re.compile(r"(?<![\w/-])envsubst\b")
# A shell in a script-argument position given a process substitution runs the
# substituted output (``bash <(echo "$V")``): the value is executed.
_PROC_SUB_EXEC_RE = re.compile(
    rf"(?<![\w/-]){_PROG_PREFIX}(?:{_SHELLS}|{_INTERPRETERS})\b(?:\s+-\S+)*\s+<\("
)
_PIPED_INTO_SHELL_RE = re.compile(rf"\|&?\s*{_PROG_PREFIX}{_SHELLS}\b")
# The tail after a piped-into interpreter: redirects, plain options (``-W``/``-X``
# and ``-r`` take an argument), long options (``--input-type=module``,
# ``--no-warnings``), and an optional ``-`` stdin marker with its own arguments.
# A bare token that is not one of these (a script file, ``-m module``) breaks
# it. The tail ends at the end of the pipeline or at the next ``|`` stage, so
# ``| python3 | tee log`` is still standard input run as code.
_INTERP_END = r"\s*(?:$|(?=\|))"
_INTERP_TAIL = (
    r"(?:\s+[0-9]?[<>]{1,2}\s*(?:&\s*[0-9]+|\S+)"
    r"|\s+--[\w-]+(?:=\S+)?"
    r"|\s+-(?:[WXr]\s+[^\s-]\S*|(?!m\b|c\b|e\b)[A-Za-z]+))*"
    rf"(?:\s+-(?:\s+[^\s|]+)*)?{_INTERP_END}"
)
_PIPED_INTO_INTERPRETER_RE = re.compile(
    rf"\|&?\s*{_PROG_PREFIX}(?:{_STDIN_INTERPRETERS}{_INTERP_TAIL}|{_DENO_STDIN}{_INTERP_END})"
)

_PIPED_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_PIPED_INTO_SHELL_RE, "piped into a shell"),
    (_PIPED_INTO_INTERPRETER_RE, "piped into an interpreter that runs its standard input"),
)

_SHELL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w-])eval\b"), "eval re-parses the value as shell"),
    (_SHELL_C_RE, "the value is inside a shell -c command string"),
    (
        _INTERPRETER_PROGRAM_RE,
        "the value is inside an interpreter program string (-c, -e, php -r, deno eval)",
    ),
    (
        re.compile(r"(?:^|[;&|(]|\$\()\s*(?:source|\.)\s+"),
        "source re-parses the target as shell",
    ),
    (re.compile(r"(?<![\w-])xargs\b"), "xargs re-splits the value into a command line"),
    (
        _PROC_SUB_EXEC_RE,
        "the value is executed through a process substitution given to the interpreter",
    ),
    *_PIPED_PATTERNS,
)

_REDIRECT_OPS = r"(?:[0-9]?>>?|&>>?|>\||\btee\b(?:\s+-{1,2}[\w-]+)*)"
_OUTPUT_TARGET_RE = re.compile(rf"{_REDIRECT_OPS}\s*[\"']?\$\{{?GITHUB_(OUTPUT|ENV)\b\}}?")
_FD_REDIRECT_RE = re.compile(r"[0-9]?>&\s*([0-9]+)\b")
_EXEC_FD_RE = re.compile(r"^\s*exec\s+([0-9]+)>>?\s*(\S+)")
_FILE_VAR_RE = re.compile(r"^\$\{?([A-Za-z_]\w*)\}?$")
_HEREDOC_OP_RE = re.compile(r"(?<!<)<<(?!<)-?")
_HEREDOC_DELIM_RE = re.compile(r"<<-?\s*(?P<q>['\"\\]?)(?P<delim>[^\s'\"]+)")
_HEREDOC_INTERP_RE = re.compile(
    rf"(?:^|[;&|(]\s*)(?:sudo\s+)?(?:{_SHELLS}|{_STDIN_INTERPRETERS}|deno\s+run)\b"
    r"(?:\s+-\S+)*\s*(?:-\s*)?<<"
)
_FILEFORMAT_MARKER_RE = re.compile(r"(?<![\w$])([A-Za-z_][\w-]*)<<([^\s\"']+)")
_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\S+\s+)*)?([A-Za-z_]\w*)=(.*)$"
)
_SELF_DIR_RE = re.compile(r"dirname\s+\"?\$\{?(?:0\b|BASH_SOURCE)")
_RANDOM_RE = re.compile(
    r"\$\{?RANDOM\b|openssl\s+rand|uuidgen|/dev/urandom|\bmktemp\b|secrets\.token"
)
_VAR_IN_TOKEN_RE = re.compile(r"\$\{?([A-Za-z_]\w*)")
# ``;``, ``&&``, ``||`` and a background ``&``; not the ``&`` of ``2>&1``, ``&>``,
# ``<&`` or the ``&`` of a ``|&`` pipe (which stays with its pipeline).
_SEPARATOR_RE = re.compile(r";|&&|\|\||(?<![<>|])&(?![&>])")
# A single ``|`` pipe (not ``||`` and not ``|&``), splitting a pipeline into stages.
_PIPE_STAGE_RE = re.compile(r"(?<![|&])\|(?![|&])")
# Words and inline assignments that can precede a command without changing what
# runs as the command: ``env FOO=1 "$V"``, ``nohup "$V"``, ``if "$V"``, ``! "$V"``.
_CMD_POS_PREFIX_RE = re.compile(
    r"^\s*(?:"
    r"(?:if|elif|while|until|then|else|do|time|exec|nohup|command|builtin|sudo|env)\b\s+"
    r"|!\s+"
    r"|[A-Za-z_]\w*=(?:\"[^\"]*\"|'[^']*'|[^\s\"'()])*\s+"
    r")*"
)
_INVOKE_RE = re.compile(
    r"^(?:exec\s+)?(?:sudo\s+(?:-\S+\s+)*)?"
    r"(?:(?P<interp>bash|sh|zsh|dash|ksh|node|python3?|source|\.)\s+)?"
    r"(?P<target>\"[^\"]+\"|\S+)(?P<rest>.*)$"
)
_SCRIPT_EXT_RE = re.compile(r"\.(?:sh|bash|js|mjs|cjs|py)\"?$")
_ARG_TOKEN_RE = re.compile(r"\"[^\"]*\"|\S+")
_ECHO_RE = re.compile(r"^\s*(?:echo|printf)\s+(?:-\w+\s+)*")
_SET_OUTPUT_RE = re.compile(r"::set-output\s+name=")
# Words after which a ``{`` or ``(`` starts a group rather than an argument.
_COMMAND_POSITION_WORDS = frozenset(
    {"do", "then", "else", "if", "elif", "while", "until", "!", "time"}
)
_COMMAND_BOUNDARY_RE = re.compile(r";|&&|\|\||\||&|\(|\{")
# Compound-statement keywords: a ``for``/``while``/``until``/``if`` block whose
# ``done``/``fi`` line carries a redirect applies it to the whole body.
_COMPOUND_OPEN_WORDS = frozenset({"for", "while", "until", "if", "select", "case"})
_COMPOUND_CLOSE_WORDS = frozenset({"done", "fi", "esac"})
_COMPOUND_START_RE = re.compile(r"^\s*(?:for|while|until|if)\b")
_COMPOUND_CLOSER_RE = re.compile(r"\b(?:done|fi)\b")
_COMPOUND_DO_THEN_RE = re.compile(r"\b(?:do|then)\b")


def ref_pattern(var: str) -> re.Pattern[str]:
    """``$VAR``, ``${VAR}``, ``${VAR:-x}``, ``"$VAR"``; not ``$VARX`` and not ``${#VAR}``."""
    return re.compile(r"\$(?:\{\s*)?" + re.escape(var) + r"(?![A-Za-z0-9_])")


def refs_var(text: str, var: str) -> bool:
    return ref_pattern(var).search(text) is not None


def mask(line: str, double_quotes: bool = False) -> str:
    """Blank out single-quoted content (and double-quoted if asked), drop comments.

    Columns are preserved up to the comment, so a position found in the masked
    view indexes the same character in the original line."""
    out: list[str] = []
    in_single = in_double = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_single:
            if c == "'":
                in_single = False
                out.append(c)
            else:
                out.append(" ")
        elif in_double:
            if c == "\\" and i + 1 < len(line):
                out.append(" " if double_quotes else c)
                out.append(" " if double_quotes else line[i + 1])
                i += 2
                continue
            if c == '"':
                in_double = False
                out.append(c)
            else:
                out.append(" " if double_quotes else c)
        elif c == "\\" and i + 1 < len(line):
            out.append(c)
            out.append(line[i + 1])
            i += 2
            continue
        elif c == "'":
            in_single = True
            out.append(c)
        elif c == '"':
            in_double = True
            out.append(c)
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def strip_comment(line: str) -> str:
    return line[: len(mask(line, double_quotes=True))]


def delimiter_kind(token: str, assignments: dict[str, str]) -> str:
    """``static`` (no expansion), ``random`` (proven), or ``unknown``."""
    if "$" not in token and "`" not in token:
        return "static"
    if _RANDOM_RE.search(token):
        return "random"
    names = _VAR_IN_TOKEN_RE.findall(token)
    if not names:
        return "unknown"
    for name in names:
        rhs = assignments.get(name)
        if rhs is None or not _RANDOM_RE.search(rhs):
            return "unknown"
    return "random"


def _logical(segments: list[Segment], start: int) -> tuple[str, int, int]:
    """Join continuation lines (trailing ``\\``, ``|``, ``&&``, ``||``).

    Returns the joined text, the line of its first piece, and the next position."""
    parts: list[str] = []
    first = segments[start][0]
    i = start
    while i < len(segments):
        raw = segments[i][1]
        stripped = strip_comment(raw).rstrip()
        i += 1
        if stripped.endswith("\\"):
            parts.append(stripped[:-1])
            continue
        parts.append(raw)
        if stripped.endswith(("|", "&&", "||")) and i < len(segments):
            continue
        break
    if len(parts) == 1:
        return parts[0], first, i
    return " ".join(p.strip() for p in parts), first, i


def _pipelines(logical: str) -> list[str]:
    """Split a logical line on ``;``, ``&&``, ``||`` and ``&`` outside quotes."""
    masked = mask(logical, double_quotes=True)
    pieces: list[str] = []
    last = 0
    for m in _SEPARATOR_RE.finditer(masked):
        pieces.append(logical[last : m.start()])
        last = m.end()
    pieces.append(logical[last:])
    return [p for p in (piece.strip() for piece in pieces) if p]


def _split_trailer(text: str) -> tuple[str, str]:
    """What follows a closing brace up to the next separator, and the rest."""
    masked = mask(text, double_quotes=True)
    m = _SEPARATOR_RE.search(masked)
    if m is None:
        return text, ""
    return text[: m.start()], text[m.end() :]


def _first_words(text: str) -> list[str]:
    """The first bare word of each ``;``/``&&``/``||``/``&`` piece of ``text``."""
    words: list[str] = []
    for piece in _pipelines(text):
        tokens = piece.split()
        if tokens:
            words.append(tokens[0])
    return words


def _compound_depth(line: str) -> int:
    """How much the keyword nesting of one line opens (+) or closes (-)."""
    depth = 0
    for word in _first_words(line):
        if word in _COMPOUND_OPEN_WORDS:
            depth += 1
        elif word in _COMPOUND_CLOSE_WORDS:
            depth -= 1
    return depth


def _group_opener(masked: str) -> int | None:
    """Column of the first ``{`` or ``(`` that starts a group, in the masked view.

    ``{`` must be a word of its own (followed by whitespace or the end);
    ``$(``, ``${``, ``<(``, ``>(``, an arithmetic ``((`` and a brace expansion
    are not groups. The text before it, back to the last separator, must be
    empty or made only of the words that precede a command (``do``, ``then``,
    ``else``, ...)."""
    for i, c in enumerate(masked):
        if c not in "{(":
            continue
        prev = masked[i - 1] if i > 0 else " "
        if prev in "$<>\\":
            continue
        if c == "(" and (prev == "(" or (i + 1 < len(masked) and masked[i + 1] == "(")):
            continue  # ``for ((i=0; ...))``, ``while (( n ))``: arithmetic, not a subshell
        if c == "{" and i + 1 < len(masked) and not masked[i + 1].isspace():
            continue
        before = _COMMAND_BOUNDARY_RE.split(masked[:i])[-1]
        if all(word in _COMMAND_POSITION_WORDS for word in before.split()):
            return i
    return None


def _word_boundary(masked: str, i: int) -> bool:
    prev = masked[i - 1] if i > 0 else " "
    return not (prev.isalnum() or prev == "_")


def _scan_for_close(
    masked: str, start: int, stack: list[str], case_depth: list[int] | None = None
) -> tuple[int | None, list[int]]:
    """Advance through ``masked`` from ``start`` keeping ``stack`` balanced.

    Returns the column of the brace that empties the stack (or None) and the
    updated ``case_depth``. ``${``, ``$(``, ``<(``, ``>(`` and an arithmetic
    ``((`` are pushed as non-group openers so their closers pop them without
    closing the group; a ``}`` only closes when it is a word of its own; a
    ``)`` that terminates a
    ``case`` pattern (inside ``case``..``esac`` with no ``(`` open past the
    depth the case began at) does not pop the enclosing subshell. ``case_depth``
    carries the case nesting across segments; each entry is the stack length
    when that ``case`` opened."""
    if case_depth is None:
        case_depth = []
    i = start
    n = len(masked)
    while i < n:
        c = masked[i]
        prev = masked[i - 1] if i > 0 else " "
        if c == "c" and masked.startswith("case", i) and _word_boundary(masked, i):
            end = i + 4
            if end >= n or not (masked[end].isalnum() or masked[end] == "_"):
                case_depth.append(len(stack))
                i = end
                continue
        elif c == "e" and masked.startswith("esac", i) and _word_boundary(masked, i):
            end = i + 4
            if end >= n or not (masked[end].isalnum() or masked[end] == "_"):
                if case_depth:
                    case_depth.pop()
                i = end
                continue
        if c in "{(":
            if prev == "\\":
                pass
            elif prev in "$<>":
                stack.append("x" + c)
            elif c == "(" and (prev == "(" or (i + 1 < n and masked[i + 1] == "(")):
                stack.append("x(")  # arithmetic ``((``: never a subshell
            elif c == "(" or i + 1 >= n or masked[i + 1].isspace():
                stack.append(c)
        elif c == "}" and stack:
            if stack[-1] == "x{":
                stack.pop()
            elif stack[-1] == "{" and (prev.isspace() or prev in ";&|({"):
                stack.pop()
                if not stack:
                    return i, case_depth
        elif c == ")" and stack and stack[-1] in ("(", "x("):
            if case_depth and len(stack) == case_depth[-1]:
                pass  # a case pattern terminator, not the subshell close
            else:
                stack.pop()
                if not stack:
                    return i, case_depth
        i += 1
    return None, case_depth


@dataclass(frozen=True)
class _Found:
    interpreter: str | None
    target: str
    rest: str
    tainted_args: tuple[tuple[str, frozenset[str]], ...]


@dataclass(frozen=True)
class _Group:
    body: list[Segment]
    close_index: int
    after: str
    """Text after the closing brace on its line."""
    next_pos: int


def _invocation(masked: str, tainted: set[str]) -> _Found | None:
    m = _INVOKE_RE.match(masked.strip())
    if m is None:
        return None
    interp = m.group("interp")
    target = m.group("target")
    rest = m.group("rest") or ""
    if target.startswith("-"):
        return None
    if target.startswith(("<(", ">(", "<<<")):
        # a process substitution is handled as a sink and a here-string is not
        # matched at all; neither is a file to follow
        return None
    if interp is None and not _SCRIPT_EXT_RE.search(target):
        return None
    if any(refs_var(target, var) for var in tainted):
        return None
    tainted_args: list[tuple[str, frozenset[str]]] = []
    everything: set[str] = set()
    for position, token in enumerate(_ARG_TOKEN_RE.findall(rest), start=1):
        found = frozenset(var for var in tainted if refs_var(token, var))
        if found:
            tainted_args.append((str(position), found))
            everything.update(found)
    if everything:
        tainted_args.append(("@", frozenset(everything)))
        tainted_args.append(("*", frozenset(everything)))
    return _Found(interp, target.strip('"'), rest, tuple(tainted_args))


def _in_command_position(masked: str, var: str) -> bool:
    """The first word of the pipeline, or of any of its ``|`` stages, is ``$var``."""
    head = re.compile(r'^\s*"?\$\{?' + re.escape(var) + r"\b")
    for stage in _PIPE_STAGE_RE.split(masked):
        rest = stage[_CMD_POS_PREFIX_RE.match(stage).end() :]  # type: ignore[union-attr]
        if head.match(rest):
            return True
    return False


def _program_string_start(masked: str) -> int | None:
    """Where the program string begins on this pipeline, or None when there is
    none. The earliest of ``python -c``-style and ``bash -c`` matches; 0 when
    ``envsubst`` is present, because its program text comes from its input."""
    if _ENVSUBST_RE.search(masked) is not None:
        return 0
    starts = [
        m.start()
        for m in (_INTERPRETER_PROGRAM_RE.search(masked), _SHELL_C_RE.search(masked))
        if m is not None
    ]
    return min(starts) if starts else None


def _shell_reason(masked: str, var: str) -> str | None:
    """The first shell pattern that fires for ``var``. The interpreter
    program-string pattern only counts ``var`` when it appears inside that
    string; a value merely piped in from the left (``echo "$V" | perl -pe '...'``)
    is data the fixed program reads, not code."""
    for pat, reason in _SHELL_PATTERNS:
        m = pat.search(masked)
        if m is None:
            continue
        if pat is _INTERPRETER_PROGRAM_RE and not ref_pattern(var).search(masked[m.start() :]):
            continue
        return reason
    return None


class _Scanner:
    def __init__(self, script: str, tainted: Iterable[str]) -> None:
        self.lines = script.split("\n")
        self.scan = ShellScan(tainted=set(tainted))
        self.scan.writes_output = (
            "GITHUB_OUTPUT" in script or "GITHUB_ENV" in script or "::set-output" in script
        )
        self.block_delim: str | None = None
        self.block_kind = ""
        self.file_aliases: dict[str, str] = {}
        """Variables assigned the output or env file path (``OUT="$GITHUB_OUTPUT"``)."""
        self.fd_targets: dict[str, str] = {}
        """Descriptors opened on the output or env file (``exec 3>>"$GITHUB_OUTPUT"``)."""

    # -- helpers -----------------------------------------------------------

    def hit(self, kind: HitKind, index: int, text: str, var: str | None, reason: str) -> None:
        self.scan.hits.append(ShellHit(kind, index, text.strip(), var, reason))

    def tainted_refs(self, text: str, raw: bool = False) -> list[str]:
        """Tainted names referenced by ``text``. Heredoc bodies are ``raw``: single
        quotes do not stop expansion there, so nothing is masked."""
        view = strip_comment(text) if raw else mask(text)
        return [var for var in sorted(self.scan.tainted) if refs_var(view, var)]

    def _closes_block(self, content: str) -> bool:
        assert self.block_delim is not None
        payload = _ECHO_RE.sub("", strip_comment(content)).strip()
        return payload.strip("\"'") == self.block_delim.strip("\"'")

    def _file_kind(self, token: str) -> str | None:
        """``OUTPUT`` or ``ENV`` when ``token`` names the runner file, directly or by alias."""
        m = _FILE_VAR_RE.match(token.strip().strip("\"'"))
        if m is None:
            return None
        name = m.group(1)
        if name == "GITHUB_OUTPUT":
            return "OUTPUT"
        if name == "GITHUB_ENV":
            return "ENV"
        return self.file_aliases.get(name)

    def _target(self, masked: str) -> str | None:
        """The runner file a pipeline writes to: by name, through a variable that
        holds its path, or through a descriptor opened on it with ``exec``."""
        m = _OUTPUT_TARGET_RE.search(masked)
        if m is not None:
            return m.group(1)
        if self.file_aliases:
            names = "|".join(re.escape(n) for n in sorted(self.file_aliases))
            alias = re.search(rf"{_REDIRECT_OPS}\s*[\"']?\$\{{?({names})\b\}}?", masked)
            if alias is not None:
                return self.file_aliases[alias.group(1)]
        if self.fd_targets:
            fd = _FD_REDIRECT_RE.search(masked)
            if fd is not None and fd.group(1) in self.fd_targets:
                return self.fd_targets[fd.group(1)]
        return None

    def _track(self, text: str) -> None:
        """Assignments (for delimiter randomness and derived taint), file aliases
        and descriptors opened with ``exec``."""
        masked = mask(text)
        candidates = [masked] if _ASSIGN_RE.match(masked) else _pipelines(masked)
        for piece in candidates:
            assign = _ASSIGN_RE.match(piece)
            if assign is not None:
                name, rhs = assign.group(1), assign.group(2)
                self.scan.assignments[name] = rhs
                if _SELF_DIR_RE.search(rhs):
                    self.scan.self_dir_vars.add(name)
                kind = self._file_kind(rhs)
                if kind is not None:
                    self.file_aliases[name] = kind
                parents = {var for var in self.scan.tainted if refs_var(rhs, var)}
                if parents and name not in parents:
                    self.scan.tainted.add(name)
                    self.scan.derived.setdefault(name, set()).update(parents)
                continue
            opened = _EXEC_FD_RE.match(piece)
            if opened is not None:
                kind = self._file_kind(opened.group(2))
                if kind is not None:
                    self.fd_targets[opened.group(1)] = kind

    # -- writes to $GITHUB_OUTPUT / $GITHUB_ENV ----------------------------

    def write(
        self, index: int, content: str, target: str, skip: Iterable[str] = (), raw: bool = False
    ) -> None:
        """One line of content that lands in the runner's key=value file."""
        skipped = set(skip)
        if self.block_delim is not None:
            if self._closes_block(content):
                self.block_delim = None
                return
            for var in self.tainted_refs(content, raw):
                if var in skipped:
                    continue
                if self.block_kind == "static":
                    self.hit(
                        HitKind.SPOOF,
                        index,
                        content,
                        var,
                        f"written to $GITHUB_{target} inside a heredoc block whose delimiter "
                        f"'{self.block_delim}' is static; a value containing that line closes "
                        "the block early and the rest is parsed as new keys",
                    )
                elif self.block_kind == "random" and target == "ENV":
                    self.hit(
                        HitKind.UNKNOWN,
                        index,
                        content,
                        var,
                        f"written to $GITHUB_ENV under a random heredoc delimiter "
                        f"({self.block_delim}); the variable it defines is visible to later "
                        "steps, which are not tracked",
                    )
                elif self.block_kind == "random":
                    self.hit(
                        HitKind.VALUE,
                        index,
                        content,
                        var,
                        f"written to $GITHUB_{target} under a random heredoc delimiter "
                        f"({self.block_delim})",
                    )
                else:
                    self.hit(
                        HitKind.UNKNOWN,
                        index,
                        content,
                        var,
                        f"written to $GITHUB_{target} inside a heredoc block whose delimiter "
                        f"{self.block_delim} is not static but could not be proven random",
                    )
            return
        marker = _FILEFORMAT_MARKER_RE.search(strip_comment(content))
        if marker is not None:
            self.block_delim = marker.group(2)
            self.block_kind = delimiter_kind(marker.group(2), self.scan.assignments)
        for var in self.tainted_refs(content, raw):
            if var in skipped:
                continue
            self.hit(
                HitKind.SPOOF,
                index,
                content,
                var,
                f"single-line write of the value to $GITHUB_{target}; a value containing a "
                "newline adds keys of the attacker's choosing",
            )

    # -- constructs --------------------------------------------------------

    def _compound_redirect(
        self,
        segments: list[Segment],
        pos: int,
        index: int,
        text: str,
        masked: str,
        target: str | None,
        shell_reason: str | None,
    ) -> int | None:
        """A ``for``/``while``/``until``/``if`` block whose ``done``/``fi`` line
        carries a redirect to the runner file or a pipe into a shell: the body
        inherits it, exactly like a brace group. Returns the next position when
        it engages, None when the line is not such a block (leaving the caller to
        scan it as ordinary pipelines with no state touched)."""
        if _COMPOUND_START_RE.match(masked) is None:
            return None
        depth = _compound_depth(text)
        if depth <= 0:  # a one-line compound: rare, left to the ordinary path
            return None
        body: list[Segment] = []
        p = pos
        term: Segment | None = None
        while p < len(segments):
            line_index, raw = segments[p]
            seg_masked = mask(raw, double_quotes=True)
            op = _HEREDOC_OP_RE.search(seg_masked)
            limit = op.start() if op is not None else len(seg_masked)
            depth += _compound_depth(raw[:limit])
            if depth <= 0:
                term = (line_index, raw)
                break
            body.append((line_index, raw))
            p += 1
            if op is None:
                continue
            delim = _HEREDOC_DELIM_RE.search(raw[op.start() :])
            if delim is None:
                continue
            strip_tabs = raw[op.start() :].startswith("<<-")
            while p < len(segments):
                candidate = segments[p][1].lstrip("\t") if strip_tabs else segments[p][1]
                body.append(segments[p])
                p += 1
                if candidate.strip() == delim.group("delim"):
                    break
        if term is None:
            return None
        term_line, term_raw = term
        closer = _COMPOUND_CLOSER_RE.search(mask(term_raw, double_quotes=True))
        if closer is None:
            return None
        trailer = term_raw[closer.end() :]
        before = term_raw[: closer.start()]
        trailer_masked = mask(trailer)
        inner_target = self._target(trailer_masked)
        piped = next((r for pat, r in _PIPED_PATTERNS if pat.search(trailer_masked)), None)
        if inner_target is None and piped is None:
            return None  # `done < list.txt`, `done > /dev/null`: not a runner target
        do_then = list(_COMPOUND_DO_THEN_RE.finditer(masked))
        if do_then:
            condition, opener_body = text[: do_then[-1].end()], text[do_then[-1].end() :]
        else:
            condition, opener_body = text, ""
        for piece in _pipelines(condition):
            self.pipeline(index, piece, target, shell_reason)
        inner = [(index, opener_body), *body, (term_line, before)]
        self._drive(inner, inner_target or target, piped or shell_reason)
        if trailer.strip():
            self.pipeline(term_line, trailer, target, shell_reason)
        return p + 1

    def _find_close(
        self, text: str, opener: int, index: int, segments: list[Segment], pos: int
    ) -> _Group | None:
        """The matching close for the group opened at ``opener`` in ``text``.

        Looks first in the rest of the same logical line, then in the following
        segments (skipping heredoc bodies). None when the group never closes."""
        stack = [text[opener]]
        masked = mask(text, double_quotes=True)
        col, case_depth = _scan_for_close(masked, opener + 1, stack, [])
        if col is not None:
            return _Group([(index, text[opener + 1 : col])], index, text[col + 1 :], pos)
        body: list[Segment] = [(index, text[opener + 1 :])]
        p = pos
        while p < len(segments):
            line_index, raw = segments[p]
            seg_masked = mask(raw, double_quotes=True)
            op = _HEREDOC_OP_RE.search(seg_masked)
            limit = op.start() if op is not None else len(seg_masked)
            col, case_depth = _scan_for_close(seg_masked[:limit], 0, stack, case_depth)
            if col is not None:
                body.append((line_index, raw[:col]))
                # A ``\``, ``|`` or ``&&`` on the closing line joins the trailer
                # with the lines below, so the redirect or pipe still applies.
                tail = [(line_index, raw[col + 1 :]), *segments[p + 1 :]]
                after, _first, consumed = _logical(tail, 0)
                return _Group(body, line_index, after, p + consumed)
            body.append((line_index, raw))
            p += 1
            if op is None:
                continue
            delim = _HEREDOC_DELIM_RE.search(raw[op.start() :])
            if delim is None:
                continue
            strip_tabs = raw[op.start() :].startswith("<<-")
            while p < len(segments):
                candidate = segments[p][1].lstrip("\t") if strip_tabs else segments[p][1]
                body.append(segments[p])
                p += 1
                if candidate.strip() == delim.group("delim"):
                    break
        return None

    def heredoc(
        self,
        segments: list[Segment],
        pos: int,
        logical: str,
        op_at: int,
        target: str | None,
        shell_reason: str | None,
    ) -> int | None:
        delim_match = _HEREDOC_DELIM_RE.search(logical[op_at:])
        if delim_match is None:
            return None
        quoted = bool(delim_match.group("q"))
        delim = delim_match.group("delim")
        strip_tabs = logical[op_at:].startswith("<<-")
        j = pos
        while j < len(segments):
            candidate = segments[j][1].lstrip("\t") if strip_tabs else segments[j][1]
            if candidate.strip() == delim:
                break
            j += 1
        if quoted:
            return j + 1
        masked = mask(logical)
        effective = self._target(masked) or target
        fed = (
            _HEREDOC_INTERP_RE.search(masked)
            or _PIPED_INTO_SHELL_RE.search(masked)
            or _PIPED_INTO_INTERPRETER_RE.search(masked)
        )
        for line_index, body_line in segments[pos:j]:
            if fed is not None or shell_reason is not None:
                for var in self.tainted_refs(body_line, raw=True):
                    self.hit(
                        HitKind.SHELL,
                        line_index,
                        body_line,
                        var,
                        "heredoc body containing the value is fed to an interpreter",
                    )
            elif effective is not None:
                self.write(line_index, body_line, effective, raw=True)
            else:
                for var in self.tainted_refs(body_line, raw=True):
                    self.hit(
                        HitKind.VALUE,
                        line_index,
                        body_line,
                        var,
                        "used as a value inside a heredoc",
                    )
        return j + 1

    def pipeline(
        self,
        index: int,
        pipeline: str,
        forced_target: str | None = None,
        shell_reason: str | None = None,
    ) -> None:
        """One command between separators. ``forced_target`` is the redirect of an
        enclosing group, which every fragment inside inherits; ``shell_reason`` is
        set when an enclosing group is piped into a shell."""
        masked = mask(pipeline)
        invocation = _invocation(masked, self.scan.tainted)
        target = self._target(masked) or forced_target
        set_output = _SET_OUTPUT_RE.search(masked) is not None
        handled_by_shell: set[str] = set()
        refs = self.tainted_refs(pipeline)
        for var in refs:
            if _in_command_position(masked, var):
                self.hit(
                    HitKind.SHELL,
                    index,
                    pipeline,
                    var,
                    "the value is in command position; its first word runs as the command",
                )
                handled_by_shell.add(var)
                continue
            found_reason = _shell_reason(masked, var)
            if found_reason is None:
                found_reason = shell_reason
            if found_reason is not None:
                self.hit(HitKind.SHELL, index, pipeline, var, found_reason)
                handled_by_shell.add(var)
                continue
            if set_output:
                self.hit(
                    HitKind.SPOOF,
                    index,
                    pipeline,
                    var,
                    "the deprecated ::set-output workflow command carries the value as a step "
                    "output; the runner still honours it with a warning, and a newline in the "
                    "value starts a new workflow command",
                )
                handled_by_shell.add(var)
                continue
            if target is not None:
                continue
            if invocation is not None and any(
                refs_var(token, var) for token in _ARG_TOKEN_RE.findall(invocation.rest)
            ):
                continue
            self.hit(
                HitKind.VALUE,
                index,
                pipeline,
                var,
                "used as a value (quoted or unquoted expansion, no re-evaluation)",
            )
        if target is not None:
            self.write(index, pipeline, target, skip=handled_by_shell)
        start = _program_string_start(masked)
        if start is not None:
            self.mentioned_by_name(index, pipeline, start)
        if invocation is not None:
            self.scan.hits.append(
                ShellHit(
                    HitKind.INVOKE,
                    index,
                    pipeline.strip(),
                    None,
                    f"invokes {invocation.target}",
                    Invocation(invocation.interpreter, invocation.target, invocation.tainted_args),
                )
            )

    def mentioned_by_name(self, index: int, pipeline: str, start: int) -> None:
        """A program string (``python -c``, ``bash -c``, ``envsubst`` input) that names a
        tainted variable the outer shell did not expand: the program may read it
        itself, so the line is UNKNOWN rather than a silent "never read".

        Only the text from ``start`` (the program-string match) on is read, both
        for the name and for what the shell expanded there: a value piped in from
        the left (``echo "$V" | python3 -c '...'``) is data the program receives,
        and neither hides nor counts as a mention. ``start`` is 0 for ``envsubst``,
        whose program text is its standard input."""
        raw = strip_comment(pipeline)[start:]
        expanded = self.tainted_refs(raw)
        for var in sorted(self.scan.tainted):
            if var in expanded or not var.isidentifier():
                continue
            bare = re.compile(r"(?<![\w$])" + re.escape(var) + r"(?!\w)")
            if refs_var(raw, var) or bare.search(raw) is not None:
                self.hit(
                    HitKind.UNKNOWN,
                    index,
                    pipeline,
                    var,
                    "interpreter string mentions the variable by name; what the program does "
                    "with the value is not analysed",
                )

    # -- driver ------------------------------------------------------------

    def _drive(self, segments: list[Segment], target: str | None, shell_reason: str | None) -> None:
        """Scan ``segments`` in order. ``target`` and ``shell_reason`` are what an
        enclosing group imposes on every command inside (None at top level)."""
        pos = 0
        while pos < len(segments):
            logical, index, pos = _logical(segments, pos)
            self._track(logical)
            pos = self._statement(segments, pos, index, logical, target, shell_reason)

    def _statement(
        self,
        segments: list[Segment],
        pos: int,
        index: int,
        text: str,
        target: str | None,
        shell_reason: str | None,
    ) -> int:
        """One logical line starting at ``index``; may consume more segments (a
        group or heredoc that continues below). Returns the next position."""
        masked = mask(text, double_quotes=True)
        opener = _group_opener(masked)
        op = _HEREDOC_OP_RE.search(masked)
        if op is not None and (opener is None or op.start() < opener):
            after = self.heredoc(segments, pos, text, op.start(), target, shell_reason)
            if after is not None:
                return after
        if opener is None:
            compound = self._compound_redirect(
                segments, pos, index, text, masked, target, shell_reason
            )
            if compound is not None:
                return compound
            for piece in _pipelines(text):
                self.pipeline(index, piece, target, shell_reason)
            return pos
        for piece in _pipelines(text[:opener]):
            self.pipeline(index, piece, target, shell_reason)
        group = self._find_close(text, opener, index, segments, pos)
        if group is None:
            for piece in _pipelines(text[opener + 1 :]):
                self.pipeline(index, piece, target, shell_reason)
            return pos
        trailer, rest = _split_trailer(group.after)
        trailer_masked = mask(trailer)
        inner_target = self._target(trailer_masked) or target
        piped = next((r for p, r in _PIPED_PATTERNS if p.search(trailer_masked)), None)
        inner_shell = piped or shell_reason
        self._drive(group.body, inner_target, inner_shell)
        if trailer.strip():
            self.pipeline(group.close_index, trailer, target, shell_reason)
        if rest.strip():
            return self._statement(
                segments, group.next_pos, group.close_index, rest, target, shell_reason
            )
        return group.next_pos

    def run(self) -> ShellScan:
        self._drive(list(enumerate(self.lines)), None, None)
        return self.scan


def scan_shell(script: str, tainted: Iterable[str]) -> ShellScan:
    """Scan one shell script for uses of the tainted variables.

    ``tainted`` holds environment variable names and, for a script invoked with
    tainted arguments, positional names (``"1"``, ``"@"``, ``"*"``).
    """
    return _Scanner(script, tainted).run()
