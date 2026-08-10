"""Search query language: tokenizer, parser and safe SQL compiler.

Grammar
-------
::

    expression := term (("AND" | "OR" | ",")? term)*
    term       := "NOT"? (group | comparison | free_text)
    group      := "(" expression ")"
    comparison := field op value
    op         := "=" | "!=" | ":" | ">" | ">=" | "<" | "<=" | "~"
    value      := bare | "quoted string" | value ("," value)*

Examples
--------
``service=payment AND level=ERROR``
``status_code>=500 AND NOT endpoint~/health``
``level=ERROR,CRITICAL``          (implicit IN)
``ip=192.0.2.5 "connection refused"``
``endpoint~/api/v1/*``            (``~`` is a wildcard/contains match)

Why a custom parser instead of "just build the SQL string"
----------------------------------------------------------
This is the platform's largest injection surface: the search box is
user-controlled text that must become a SQL predicate.  The design makes
injection *structurally impossible* rather than filtered:

1. The tokenizer only recognises a fixed vocabulary; anything else is a syntax
   error the user sees.
2. Field names are checked against an allow-list
   (:data:`app.models.log_event.QUERYABLE_COLUMNS`) at parse time.
3. The compiler emits **only** operators from a fixed map and ``?``
   placeholders — every value leaves as a bound parameter.  No user byte ever
   reaches the SQL text.
4. Complexity is bounded (node count, nesting depth, value length) so a
   pathological query cannot become a denial of service.

Wildcards are translated to ``LIKE`` with ``\\``-escaping of ``%`` and ``_``,
so a literal ``%`` in a search term cannot silently become "match anything".
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from app.core.exceptions import SearchSyntaxError
from app.core.timeutil import parse_timestamp
from app.models.log_event import QUERYABLE_COLUMNS

MAX_QUERY_LENGTH: Final[int] = 4_096
MAX_NODES: Final[int] = 64
MAX_DEPTH: Final[int] = 8
MAX_VALUE_LENGTH: Final[int] = 512
MAX_IN_VALUES: Final[int] = 50

#: Operators the user may write → SQL operator.  A closed map: the compiler
#: cannot emit anything outside it.
_SQL_OPERATORS: Final[dict[str, str]] = {
    "=": "=",
    "==": "=",
    ":": "=",
    "!=": "<>",
    "<>": "<>",
    ">": ">",
    ">=": ">=",
    "<": "<",
    "<=": "<=",
}

#: Columns stored as numbers — comparisons bind numeric parameters.
_NUMERIC_COLUMNS: Final[frozenset[str]] = frozenset(
    {"status_code", "response_time_ms", "bytes_sent"}
)
_TIMESTAMP_COLUMNS: Final[frozenset[str]] = frozenset({"timestamp", "ingested_at"})

#: Convenience aliases so users can type what they say.
FIELD_ALIASES: Final[dict[str, str]] = {
    "ip": "ip_address",
    "client_ip": "ip_address",
    "status": "status_code",
    "path": "endpoint",
    "url": "endpoint",
    "method": "http_method",
    "host": "hostname",
    "duration": "response_time_ms",
    "latency": "response_time_ms",
    "response_time": "response_time_ms",
    "time": "timestamp",
    "msg": "message",
    "app": "service",
    "user": "user_id",
    "trace_id": "request_id",
    "bytes": "bytes_sent",
    "ua": "user_agent",
    "severity": "level",
}

_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<op>>=|<=|!=|<>|==|=|:|>|<|~)
  | (?P<comma>,)
  | (?P<quoted>"[^"]{0,512}"|'[^']{0,512}')
  | (?P<word>[^\s()=:<>!~,"']{1,512})
    """,
    re.VERBOSE,
)


# --------------------------------------------------------------------------- #
# Tokens
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: str
    position: int


def tokenize(text: str) -> list[Token]:
    """Split a query into tokens, rejecting anything unrecognised."""
    if len(text) > MAX_QUERY_LENGTH:
        raise SearchSyntaxError(f"query exceeds {MAX_QUERY_LENGTH} characters")
    tokens: list[Token] = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if match is None:
            raise SearchSyntaxError(
                f"unexpected character {text[position]!r} at position {position}"
            )
        kind = match.lastgroup or "word"
        value = match.group()
        position = match.end()
        if kind == "ws":
            continue
        if kind == "quoted":
            value = value[1:-1]
        tokens.append(Token(kind, value, match.start()))
    return _merge_value_colons(tokens)


def _is_field_name(word: str) -> bool:
    key = word.strip().lower()
    return key in QUERYABLE_COLUMNS or key in FIELD_ALIASES


def _merge_value_colons(tokens: list[Token]) -> list[Token]:
    """Re-attach colons that belong to a *value*, not to ``field:value``.

    ``:`` is both a comparison operator and a character inside timestamps
    (``2026-08-07T14:32:10Z``), URLs and IPv6 addresses.  It is treated as an
    operator only when the word before it is an allow-listed field name;
    otherwise it is glued back into the surrounding word.  Requiring the parts
    to be physically adjacent keeps ``level : ERROR`` working as a comparison.
    """
    merged: list[Token] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        previous = merged[-1] if merged else None
        is_value_colon = (
            token.kind == "op"
            and token.value == ":"
            and previous is not None
            and previous.kind == "word"
            and not _is_field_name(previous.value)
            and token.position == previous.position + len(previous.value)
        )
        if not is_value_colon or previous is None:
            merged.append(token)
            index += 1
            continue

        merged.pop()
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if (
            following is not None
            and following.kind == "word"
            and following.position == token.position + 1
        ):
            merged.append(Token("word", f"{previous.value}:{following.value}", previous.position))
            index += 2
        else:
            merged.append(Token("word", f"{previous.value}:", previous.position))
            index += 1
    return merged


# --------------------------------------------------------------------------- #
# AST
# --------------------------------------------------------------------------- #
class Node:
    """Base AST node."""

    def compile(self) -> tuple[str, list[Any]]:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(slots=True)
class Comparison(Node):
    """``field op value`` — the only node that binds a user value."""

    column: str
    operator: str
    value: Any
    values: list[Any] = field(default_factory=list)

    def compile(self) -> tuple[str, list[Any]]:
        if self.values:
            placeholders = ", ".join("?" for _ in self.values)
            return f"{self.column} IN ({placeholders})", list(self.values)
        if self.operator == "~":
            # Wildcard/contains.  ESCAPE makes a literal % or _ in the user's
            # term stay literal instead of becoming a wildcard.
            return f"{self.column}::VARCHAR ILIKE ? ESCAPE '\\'", [self.value]
        sql_operator = _SQL_OPERATORS[self.operator]
        return f"{self.column} {sql_operator} ?", [self.value]


@dataclass(slots=True)
class FreeText(Node):
    """Bare text — searched across the message and the raw line."""

    value: str

    def compile(self) -> tuple[str, list[Any]]:
        pattern = f"%{_escape_like(self.value)}%"
        return (
            "(message ILIKE ? ESCAPE '\\' OR raw_message ILIKE ? ESCAPE '\\')",
            [pattern, pattern],
        )


@dataclass(slots=True)
class Not(Node):
    child: Node

    def compile(self) -> tuple[str, list[Any]]:
        sql, params = self.child.compile()
        return f"NOT ({sql})", params


@dataclass(slots=True)
class BoolOp(Node):
    operator: str  # "AND" | "OR"
    children: list[Node]

    def compile(self) -> tuple[str, list[Any]]:
        parts: list[str] = []
        params: list[Any] = []
        for child in self.children:
            sql, child_params = child.compile()
            parts.append(f"({sql})")
            params.extend(child_params)
        return f" {self.operator} ".join(parts), params


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class QueryParser:
    """Recursive-descent parser with hard complexity limits."""

    def __init__(self, tokens: Sequence[Token]) -> None:
        self._tokens = list(tokens)
        self._index = 0
        self._nodes = 0

    # -- token helpers ------------------------------------------------------ #
    def _peek(self) -> Token | None:
        return self._tokens[self._index] if self._index < len(self._tokens) else None

    def _next(self) -> Token | None:
        token = self._peek()
        if token is not None:
            self._index += 1
        return token

    def _count_node(self) -> None:
        self._nodes += 1
        if self._nodes > MAX_NODES:
            raise SearchSyntaxError(f"query is too complex (over {MAX_NODES} terms)")

    # -- grammar ------------------------------------------------------------ #
    def parse(self) -> Node | None:
        if not self._tokens:
            return None
        node = self._parse_or(depth=0)
        remaining = self._peek()
        if remaining is not None:
            raise SearchSyntaxError(
                f"unexpected {remaining.value!r} at position {remaining.position}"
            )
        return node

    def _parse_or(self, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise SearchSyntaxError(f"query nesting exceeds {MAX_DEPTH} levels")
        nodes = [self._parse_and(depth)]
        while self._is_keyword("OR"):
            self._next()
            nodes.append(self._parse_and(depth))
        return nodes[0] if len(nodes) == 1 else BoolOp("OR", nodes)

    def _parse_and(self, depth: int) -> Node:
        nodes = [self._parse_term(depth)]
        while True:
            token = self._peek()
            if token is None or token.kind == "rparen":
                break
            if self._is_keyword("OR"):
                break
            if self._is_keyword("AND"):
                self._next()
            # Adjacent terms without a keyword are implicitly ANDed, which is
            # what every search box in the world does.
            nodes.append(self._parse_term(depth))
        return nodes[0] if len(nodes) == 1 else BoolOp("AND", nodes)

    def _parse_term(self, depth: int) -> Node:
        if self._is_keyword("NOT") or self._is_keyword("-"):
            self._next()
            self._count_node()
            return Not(self._parse_term(depth))

        token = self._peek()
        if token is None:
            raise SearchSyntaxError("query ended unexpectedly")
        if token.kind == "lparen":
            self._next()
            node = self._parse_or(depth + 1)
            closing = self._next()
            if closing is None or closing.kind != "rparen":
                raise SearchSyntaxError("unbalanced parenthesis")
            return node
        return self._parse_comparison()

    def _parse_comparison(self) -> Node:
        token = self._next()
        if token is None:  # pragma: no cover - guarded by callers
            raise SearchSyntaxError("query ended unexpectedly")
        self._count_node()

        operator_token = self._peek()
        if operator_token is None or operator_token.kind != "op":
            if token.kind not in {"word", "quoted"}:
                raise SearchSyntaxError(f"unexpected {token.value!r}")
            return FreeText(_bounded(token.value))

        self._next()
        column = resolve_column(token.value)
        values = self._parse_values()
        return build_comparison(column, operator_token.value, values)

    def _parse_values(self) -> list[str]:
        values: list[str] = []
        while True:
            token = self._next()
            if token is None or token.kind not in {"word", "quoted"}:
                raise SearchSyntaxError("a comparison must be followed by a value")
            values.append(_bounded(token.value))
            if len(values) > MAX_IN_VALUES:
                raise SearchSyntaxError(f"at most {MAX_IN_VALUES} values may be listed")
            following = self._peek()
            if following is not None and following.kind == "comma":
                self._next()
                continue
            return values

    def _is_keyword(self, keyword: str) -> bool:
        token = self._peek()
        return token is not None and token.kind == "word" and token.value.upper() == keyword.upper()


# --------------------------------------------------------------------------- #
# Building blocks
# --------------------------------------------------------------------------- #
def resolve_column(name: str) -> str:
    """Map a user-facing field name onto an allow-listed column."""
    key = name.strip().lower()
    key = FIELD_ALIASES.get(key, key)
    if key not in QUERYABLE_COLUMNS:
        raise SearchSyntaxError(
            f"unknown field {name!r}; searchable fields: {', '.join(sorted(QUERYABLE_COLUMNS))}"
        )
    return key


def build_comparison(column: str, operator: str, values: Sequence[str]) -> Comparison:
    """Type-coerce values and choose between ``=``, ``IN`` and ``ILIKE``."""
    if operator not in _SQL_OPERATORS and operator != "~":
        raise SearchSyntaxError(f"unsupported operator {operator!r}")

    if len(values) > 1:
        if operator not in {"=", "==", ":"}:
            raise SearchSyntaxError("value lists are only supported with '=' or ':'")
        return Comparison(column, "=", None, [_coerce(column, v) for v in values])

    raw = values[0]
    if operator == "~" or ("*" in raw and column not in _NUMERIC_COLUMNS):
        return Comparison(column, "~", _to_like_pattern(raw))
    return Comparison(column, operator, _coerce(column, raw))


def _coerce(column: str, value: str) -> Any:
    """Convert a value to the column's type, with a clear error if it cannot."""
    if column in _NUMERIC_COLUMNS:
        try:
            return float(value) if column == "response_time_ms" else int(value)
        except ValueError as exc:
            raise SearchSyntaxError(f"{column} expects a number, got {value!r}") from exc
    if column in _TIMESTAMP_COLUMNS:
        parsed = parse_timestamp(value)
        if parsed is None:
            raise SearchSyntaxError(f"{column} expects a timestamp, got {value!r}")
        return parsed
    return value


def _escape_like(value: str) -> str:
    """Escape LIKE metacharacters so they match literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _to_like_pattern(value: str) -> str:
    """User ``*`` wildcards → SQL ``%``; everything else stays literal."""
    escaped = _escape_like(value)
    if "*" in value:
        return escaped.replace("*", "%")
    return f"%{escaped}%"


def _bounded(value: str) -> str:
    if len(value) > MAX_VALUE_LENGTH:
        raise SearchSyntaxError(f"a search value exceeds {MAX_VALUE_LENGTH} characters")
    return value


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class CompiledQuery:
    """A parsed query, ready to hand to the storage engine."""

    sql: str
    params: tuple[Any, ...]
    text: str

    @property
    def is_empty(self) -> bool:
        return not self.sql

    def describe(self) -> dict[str, Any]:
        """Explain the compiled form — used by ``/logs/search?explain=true``."""
        return {"query": self.text, "predicate": self.sql, "parameters": len(self.params)}


def compile_query(text: str) -> CompiledQuery:
    """Parse and compile a search expression into a safe SQL predicate.

    Raises :class:`~app.core.exceptions.SearchSyntaxError` — whose message *is*
    safe to return to the client, because it only ever describes the client's
    own input.
    """
    stripped = (text or "").strip()
    if not stripped:
        return CompiledQuery("", (), "")
    node = QueryParser(tokenize(stripped)).parse()
    if node is None:
        return CompiledQuery("", (), stripped)
    sql, params = node.compile()
    return CompiledQuery(sql, tuple(params), stripped)


def compile_filters(filters: dict[str, Any]) -> CompiledQuery:
    """Compile a structured ``{field: value}`` filter map (API query params)."""
    nodes: list[Node] = []
    for name, value in filters.items():
        if value is None or value == "":
            continue
        column = resolve_column(name)
        if isinstance(value, (list, tuple, set)):
            items = [str(v) for v in value][:MAX_IN_VALUES]
            if not items:
                continue
            nodes.append(build_comparison(column, "=", items))
        else:
            nodes.append(build_comparison(column, "=", [str(value)]))
    if not nodes:
        return CompiledQuery("", (), "")
    node = nodes[0] if len(nodes) == 1 else BoolOp("AND", nodes)
    sql, params = node.compile()
    return CompiledQuery(sql, tuple(params), "")


def combine(*queries: CompiledQuery, operator: str = "AND") -> CompiledQuery:
    """AND/OR several compiled queries together."""
    if operator not in {"AND", "OR"}:
        raise ValueError("operator must be AND or OR")
    active = [q for q in queries if not q.is_empty]
    if not active:
        return CompiledQuery("", (), "")
    if len(active) == 1:
        return active[0]
    sql = f" {operator} ".join(f"({q.sql})" for q in active)
    params = tuple(param for q in active for param in q.params)
    text = f" {operator} ".join(q.text for q in active if q.text)
    return CompiledQuery(sql, params, text)


def iter_nodes(node: Node) -> Iterator[Node]:
    """Walk an AST — used by tests and by the query explainer."""
    yield node
    if isinstance(node, Not):
        yield from iter_nodes(node.child)
    elif isinstance(node, BoolOp):
        for child in node.children:
            yield from iter_nodes(child)


__all__ = [
    "MAX_NODES",
    "MAX_QUERY_LENGTH",
    "BoolOp",
    "Comparison",
    "CompiledQuery",
    "FreeText",
    "Node",
    "Not",
    "QueryParser",
    "combine",
    "compile_filters",
    "compile_query",
    "iter_nodes",
    "resolve_column",
    "tokenize",
]
