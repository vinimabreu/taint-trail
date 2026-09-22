"""The fixed list of untrusted expression contexts, and how to find them.

The list follows the GitHub documentation on script injection ("Understanding
the risk of script injections") plus the event fields an outside contributor
controls through a discussion, a workflow_run chain or a repository_dispatch
payload. ``github.event.inputs.*`` and a top-level ``inputs.*`` are labelled
semi-trusted: only someone who can already dispatch the workflow sets them.

Matching is on the normalised path: lower-cased, ``['x']`` folded to ``.x`` and
any other index folded to ``.*``. A reference that is a strict prefix of a
source (``github.event.issue``, or ``github.event`` inside ``toJSON``) is
tainted too, because it carries the untrusted fields inside it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from .model import Source, Trust

UNTRUSTED_SOURCES: tuple[str, ...] = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.name",
    "github.event.commits.*.author.email",
    "github.event.head_commit.message",
    "github.event.head_commit.author.*",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.*",
    "github.event.workflow_run.display_title",
    "github.event.client_payload.*",
)

SEMI_TRUSTED_SOURCES: tuple[str, ...] = (
    "github.event.inputs.*",
    "inputs.*",
)

_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_SQ_INDEX_RE = re.compile(r"\[\s*'([^']*)'\s*\]")
_DQ_INDEX_RE = re.compile(r'\[\s*"([^"]*)"\s*\]')
_ANY_INDEX_RE = re.compile(r"\[[^\]]*\]")
_STRING_RE = re.compile(r"'(?:[^']|'')*'")
_REF_RE = re.compile(r"(?<![\w.$-])([A-Za-z_][\w-]*(?:\.(?:[\w-]+|\*))*)(?![\w-]|\s*\()")
_KEYWORDS = frozenset({"true", "false", "null"})


@dataclass(frozen=True)
class Expression:
    body: str
    start: int
    end: int
    text: str

    @property
    def lines(self) -> int:
        return self.text.count("\n")


def find_expressions(text: str) -> list[Expression]:
    """Every ``${{ ... }}`` in ``text`` with its character span and original text."""
    return [
        Expression(m.group(1).strip(), m.start(), m.end(), m.group(0))
        for m in _EXPR_RE.finditer(text)
    ]


def normalise(path: str) -> str:
    """Fold ``['x']`` and ``["x"]`` into ``.x`` and any other index into ``.*``."""
    text = _SQ_INDEX_RE.sub(r".\1", path)
    text = _DQ_INDEX_RE.sub(r".\1", text)
    return _ANY_INDEX_RE.sub(".*", text)


def references(expression: str) -> list[str]:
    """Context references inside one expression body, normalised.

    ``contains(github.event['comment'].body, '/run')`` yields
    ``["github.event.comment.body"]``. Function names and string literals are
    dropped.
    """
    text = _STRING_RE.sub(" ", normalise(expression))
    found: list[str] = []
    for match in _REF_RE.finditer(text):
        ref = match.group(1)
        if ref.lower() in _KEYWORDS:
            continue
        found.append(ref)
    return found


Match = Literal["full", "prefix"] | None


def _match(pattern: str, ref: str) -> Match:
    p_parts = pattern.split(".")
    r_parts = ref.lower().split(".")
    for index, p_seg in enumerate(p_parts):
        if index >= len(r_parts):
            return "prefix"
        r_seg = r_parts[index]
        if p_seg == "*" or r_seg == "*" or p_seg == r_seg:
            continue
        return None
    return "full"


def classify(ref: str) -> Source | None:
    """Return the Source for a context reference, or None when it is trusted.

    Only ``github.*`` and ``inputs.*`` are decided here. ``env.*``,
    ``steps.*``, ``needs.*`` and ``matrix.*`` depend on what the workflow put in
    them and are resolved by the analyser.
    """
    ref = normalise(ref)
    lowered = ref.lower()
    for pattern in SEMI_TRUSTED_SOURCES:
        if _match(pattern, lowered) == "full":
            note = (
                "workflow_dispatch input"
                if pattern.startswith("github.")
                else "workflow_dispatch or workflow_call input"
            )
            return Source(ref, Trust.SEMI_TRUSTED, pattern, note)
    if not lowered.startswith("github"):
        return None
    best: Source | None = None
    for pattern in UNTRUSTED_SOURCES:
        outcome = _match(pattern, lowered)
        if outcome == "full":
            return Source(ref, Trust.UNTRUSTED, pattern)
        if outcome == "prefix" and best is None:
            best = Source(ref, Trust.UNTRUSTED, pattern, "contains untrusted fields")
    return best


def direct_sources(expression: str) -> list[Source]:
    """Sources referenced directly by one expression body (no context lookup)."""
    out: list[Source] = []
    seen: set[str] = set()
    for ref in references(expression):
        source = classify(ref)
        if source is not None and source.path not in seen:
            seen.add(source.path)
            out.append(source)
    return out
