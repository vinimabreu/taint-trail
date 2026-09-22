"""taint-trail: follow an untrusted value through a GitHub Actions workflow.

The interesting question is not whether ``${{ github.event.comment.body }}``
appears inside a ``run:`` block. It is what happens to that value after a
maintainer moves it into ``env:``, passes it through ``with:`` into an action,
or writes it to ``$GITHUB_OUTPUT``. This package follows it until it dies in
an argv array, reaches a shell, spoofs the runner's key=value file, or becomes
opaque, and says which.
"""

from __future__ import annotations

from .actions import LocalDirResolver, NoResolver, Resolver
from .model import Chain, Hop, Source, Summary, Trust, Verdict, VerdictKind
from .propagate import Analyzer
from .report import render_json, render_text, summarise

__version__ = "0.1.0"

__all__ = [
    "Analyzer",
    "Chain",
    "Hop",
    "LocalDirResolver",
    "NoResolver",
    "Resolver",
    "Source",
    "Summary",
    "Trust",
    "Verdict",
    "VerdictKind",
    "__version__",
    "render_json",
    "render_text",
    "summarise",
]
