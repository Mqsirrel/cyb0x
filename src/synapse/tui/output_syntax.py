"""Syntax coloring for command output rendered inside the RunnerModal.

Subprocess pipes normally strip ANSI escapes, leaving tool output monochrome.
This module restores color fidelity two ways:

1. ANSI passthrough: when captured output DOES contain SGR escape sequences
   (e.g. ``script``/``unbuffer`` wrappers or pasted terminal logs), the codes
   are decoded with Rich's ``AnsiDecoder`` into exact per-span styles, so
   native Nmap/ffuf/rustscan palettes display accurately.
2. Grammar fallback: for plain piped text, a lightweight tokenizer paints
   known line shapes -- nmap port-table states, rustscan ``Open host:port``
   hits, ffuf/gobuster status codes, URLs, summary lines, STDERR blocks, and
   proof-flag tokens -- with the synapse palette.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from rich.ansi import AnsiDecoder
from rich.style import Style

from synapse.tui.theme import (
    BACKGROUND,
    CREAM,
    ERROR_RED,
    KRAFT,
    MUTED,
    SAGE,
    TERRACOTTA,
)

ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-9;?]*[A-Za-z]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b[P^_].*?\x1b\\"
    r"|\x1b[@-_]"
)

FLAG_TOKEN_RE = re.compile(
    r"(?:flag|CTF|HTB|THM|EJPT|OffSec)\{[^{}\s]+\}"
    r"|\b[0-9a-fA-F]{32}\b"
)

NMAP_PORT_ROW_RE = re.compile(
    r"^(\s*)(\d+)/(tcp|udp)\s+(\S+)(.*)$",
    re.IGNORECASE,
)
NMAP_STATES = {
    "open": ("syn.state-open", True),
    "closed": ("syn.state-closed", False),
    "filtered": ("syn.state-filtered", False),
    "unfiltered": ("syn.state-filtered", False),
}
NMAP_SUMMARY_RES = [
    re.compile(r"^Starting Nmap"),
    re.compile(r"^Nmap done:"),
    re.compile(r"^Service detection performed"),
    re.compile(r"^Read data files"),
    re.compile(r"^Initiating|^Completed|^Scanned at|^Pre-scan"),
]
HOST_UP_RE = re.compile(r"^Host is up")
HOST_DOWN_RE = re.compile(r"^Host (?:is down|seems down)|^Failed to resolve")
PORT_HEADER_RE = re.compile(r"^\s*PORT\s+STATE\s+SERVICE", re.IGNORECASE)

RUSTSCAN_OPEN_RE = re.compile(r"^(Open|OPEN)\s+(\S+)\s*$")
BRACKET_PREFIX_RE = re.compile(r"^(\[[+\-!~x]\])")

STATUS_CODE_RE = re.compile(r"(Status:\s*(\d{3}))")
URL_RE = re.compile(r"https?://[^\s\"']+")

STDERR_MARKER = "[STDERR]"


def contains_ansi(text: str) -> bool:
    return bool(ANSI_ESCAPE_RE.search(text))


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


Span = Tuple[int, int, str]
LineSpans = List[Span]


@dataclass
class HighlightResult:
    text: str
    style_map: Dict[str, Style] = field(default_factory=dict)
    line_spans: List[LineSpans] = field(default_factory=list)


def _compress(painted: List[object]) -> LineSpans:
    spans: LineSpans = []
    run_key: object = None
    run_start = 0
    for i, key in enumerate(painted):
        if key != run_key:
            if run_key is not None:
                spans.append((run_start, i, str(run_key)))
            run_key = key
            run_start = i
    if run_key is not None:
        spans.append((run_start, len(painted), str(run_key)))
    return spans


def _spans_from_rich_line(line_text, registry: Dict[str, str], styles: Dict[str, Style]) -> LineSpans:
    base_key: object = None
    if line_text.style:
        base_style = line_text.style
        base_style = Style.parse(base_style) if isinstance(base_style, str) else base_style
        base_key = _register_style(base_style, registry, styles)
    painted: List[object] = [base_key] * line_text.cell_len
    for span in line_text.spans:
        style = span.style
        if not style:
            continue
        if isinstance(style, str):
            style = Style.parse(style)
        key = _register_style(style, registry, styles)
        for i in range(span.start, min(span.end, len(painted))):
            painted[i] = key
    return _compress(painted)


def _register_style(style: Style, registry: Dict[str, str], styles: Dict[str, Style]) -> str:
    sig = repr(
        (
            style.color.get_truecolor() if style.color else None,
            style.bgcolor.get_truecolor() if style.bgcolor else None,
            style.bold,
            style.dim,
            style.italic,
            style.underline,
            style.strike,
            style.reverse,
        )
    )
    key = registry.get(sig)
    if key is None:
        key = f"dyn-{len(registry)}"
        registry[sig] = key
        styles[key] = style
    return key


SYNTAX_STYLES: Dict[str, Style] = {
    "syn.state-open": Style(color=SAGE, bold=True),
    "syn.state-closed": Style(color=MUTED, dim=True),
    "syn.state-filtered": Style(color=KRAFT),
    "syn.port": Style(color=TERRACOTTA, bold=True),
    "syn.proto": Style(color=MUTED),
    "syn.header": Style(color=MUTED, bold=True),
    "syn.summary": Style(color=MUTED, dim=True),
    "syn.stderr": Style(color=ERROR_RED),
    "syn.stderr-label": Style(color=CREAM, bgcolor=ERROR_RED, bold=True),
    "syn.host-up": Style(color=SAGE),
    "syn.host-down": Style(color=MUTED, dim=True),
    "syn.url": Style(color=TERRACOTTA),
    "syn.status-ok": Style(color=SAGE, bold=True),
    "syn.status-redir": Style(color=KRAFT, bold=True),
    "syn.status-err": Style(color=ERROR_RED, bold=True),
    "syn.flag": Style(color=BACKGROUND, bgcolor=TERRACOTTA, bold=True),
    "syn.prefix-ok": Style(color=SAGE, bold=True),
    "syn.prefix-warn": Style(color=KRAFT, bold=True),
    "syn.prefix-fail": Style(color=ERROR_RED, bold=True),
}


def _grammar_line_spans(line: str, in_stderr: bool) -> Tuple[LineSpans, bool]:
    """Returns (spans, stderr_still_active) for a single plain-text line."""
    if in_stderr:
        return [(0, len(line), "syn.stderr")] if line else [], True

    if line.strip() == STDERR_MARKER:
        return [(0, len(line), "syn.stderr-label")], True

    painted: List[object] = [None] * max(len(line), 1)

    def paint(start: int, end: int, key: str) -> None:
        end = end if end > start else start + 1
        for i in range(max(0, start), min(end, len(painted))):
            painted[i] = key

    def paint_token(match: re.Match, group: int, key: str) -> None:
        paint(match.start(group), match.end(group), key)

    m = RUSTSCAN_OPEN_RE.match(line)
    if m:
        paint(m.start(1), m.end(1), "syn.state-open")
        paint(m.start(2), m.end(2), "syn.port")
        return _compress(painted), False

    m = NMAP_PORT_ROW_RE.match(line)
    if m:
        paint_token(m, 2, "syn.port")
        paint_token(m, 3, "syn.proto")
        state_raw = m.group(4).lower()
        base_state = state_raw.split("|")[0]
        key, _ = NMAP_STATES.get(state_raw, NMAP_STATES.get(base_state, ("syn.state-closed", False)))
        paint_token(m, 4, key)
        return _compress(painted), False

    if PORT_HEADER_RE.match(line):
        return [(0, len(line.rstrip()), "syn.header")], False

    if HOST_UP_RE.match(line):
        return [(0, len("Host is up"), "syn.host-up")] + (
            [(len("Host is up"), len(line), "syn.summary")]
            if len(line) > len("Host is up")
            else []
        ), False

    if HOST_DOWN_RE.match(line):
        return [(0, len(line), "syn.host-down")], False

    if any(rx.match(line) for rx in NMAP_SUMMARY_RES):
        return [(0, len(line), "syn.summary")], False

    m = BRACKET_PREFIX_RE.match(line)
    if m:
        token = m.group(1)
        key = {"[+]": "syn.prefix-ok", "[!]": "syn.prefix-warn", "[~]": "syn.prefix-warn"}.get(
            token, "syn.prefix-fail"
        )
        paint(m.start(1), m.end(1), key)

    m = STATUS_CODE_RE.search(line)
    if m:
        code = int(m.group(2))
        if 200 <= code < 300:
            key = "syn.status-ok"
        elif 300 <= code < 400:
            key = "syn.status-redir"
        else:
            key = "syn.status-err"
        paint(m.start(1), m.end(1), key)

    for um in URL_RE.finditer(line):
        paint(um.start(), um.end(), "syn.url")

    for fm in FLAG_TOKEN_RE.finditer(line):
        paint(fm.start(), fm.end(), "syn.flag")

    return _compress(painted), False


def compute_output_highlight(raw: str) -> HighlightResult:
    """Computes clean text plus per-line highlight spans for RunnerModal output."""
    if not raw:
        return HighlightResult(text="")

    styles: Dict[str, Style] = {}

    if contains_ansi(raw):
        registry: Dict[str, str] = {}
        decoded = AnsiDecoder().decode(raw)
        line_spans: List[LineSpans] = []
        lines: List[str] = []
        for rich_line in decoded:
            lines.append(rich_line.plain)
            line_spans.append(_spans_from_rich_line(rich_line, registry, styles))
        clean = "\n".join(lines)
        for fm_line_idx, line in enumerate(lines):
            extra: LineSpans = [
                (fm.start(), fm.end(), "syn.flag") for fm in FLAG_TOKEN_RE.finditer(line)
            ]
            if extra:
                line_spans[fm_line_idx] = sorted(line_spans[fm_line_idx] + extra)
        return HighlightResult(text=clean, style_map=styles, line_spans=line_spans)

    clean_lines = raw.splitlines()
    line_spans = []
    in_stderr = False
    for line in clean_lines:
        spans, in_stderr = _grammar_line_spans(line, in_stderr)
        line_spans.append(spans)
    return HighlightResult(text="\n".join(clean_lines), style_map=styles, line_spans=line_spans)
