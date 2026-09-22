"""YAML loading that keeps line numbers and survives the YAML 1.1 boolean trap.

PyYAML implements YAML 1.1, where the plain scalars ``on``, ``off``, ``yes`` and
``no`` are booleans. A workflow's top-level ``on:`` key therefore comes back as
the Python value ``True``. GitHub reads workflows with YAML 1.2 semantics, where
``on`` is a string. The loader below keeps the literal text of any key that
PyYAML would turn into a boolean, so ``on`` stays ``"on"``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class LineStr(str):
    """A string that remembers where it came from.

    ``line`` is the 1-based line of the scalar itself (for an inline value this
    is the line of its key). ``body_line`` is the 1-based line where the first
    line of the content lives: for block scalars (``|`` and ``>``) that is the
    line after the indicator, for everything else it equals ``line``.
    """

    line: int
    body_line: int

    def __new__(cls, value: str, line: int = 0, body_line: int | None = None) -> LineStr:
        obj = super().__new__(cls, value)
        obj.line = line
        obj.body_line = line if body_line is None else body_line
        return obj


class LineDict(dict[Any, Any]):
    line: int
    key_lines: dict[Any, int]

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line
        self.key_lines = {}

    def key_line(self, key: Any, default: int | None = None) -> int:
        return self.key_lines.get(key, self.line if default is None else default)


class LineList(list[Any]):
    line: int

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line


class _Loader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _Loader, node: yaml.Node) -> LineDict:
    assert isinstance(node, yaml.MappingNode)
    loader.flatten_mapping(node)
    result = LineDict(node.start_mark.line + 1)
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if isinstance(key, bool | type(None)) and isinstance(key_node, yaml.ScalarNode):
            # YAML 1.1: `on`, `off`, `yes`, `no`, `null` as keys. Keep the text.
            key = key_node.value
        if isinstance(key, LineStr):
            key = str(key)
        value = loader.construct_object(value_node, deep=True)
        result[key] = value
        result.key_lines[key] = key_node.start_mark.line + 1
    return result


def _construct_sequence(loader: _Loader, node: yaml.Node) -> LineList:
    assert isinstance(node, yaml.SequenceNode)
    result = LineList(node.start_mark.line + 1)
    result.extend(loader.construct_object(child, deep=True) for child in node.value)
    return result


def _construct_str(loader: _Loader, node: yaml.Node) -> LineStr:
    assert isinstance(node, yaml.ScalarNode)
    value = loader.construct_scalar(node)
    line = node.start_mark.line + 1
    body_line = line + 1 if node.style in ("|", ">") else line
    return LineStr(str(value), line, body_line)


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)
_Loader.add_constructor("tag:yaml.org,2002:str", _construct_str)


class YamlError(ValueError):
    pass


def load_yaml(text: str, name: str = "<string>") -> Any:
    """Parse YAML into LineDict / LineList / LineStr values."""
    try:
        return yaml.load(text, Loader=_Loader)  # noqa: S506 (SafeLoader subclass)
    except yaml.YAMLError as exc:
        raise YamlError(f"{name}: {exc}") from exc
    except RecursionError as exc:
        raise YamlError(f"{name}: document is nested too deeply to parse") from exc


def load_yaml_file(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise YamlError(f"{path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise YamlError(f"{path}: not valid UTF-8 ({exc.reason} at byte {exc.start})") from exc
    return load_yaml(text, str(path))


def as_dict(value: Any) -> LineDict:
    """Return ``value`` if it is a mapping, else an empty LineDict."""
    return value if isinstance(value, LineDict) else LineDict()


def as_list(value: Any) -> LineList:
    return value if isinstance(value, LineList) else LineList()


def as_text(value: Any) -> LineStr | None:
    """Scalars that are not strings (numbers, booleans) carry no expression."""
    if isinstance(value, LineStr):
        return value
    if isinstance(value, str):
        return LineStr(value)
    return None
