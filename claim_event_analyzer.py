#!/usr/bin/env python3
"""
claim_event_analyzer.py

Version: 1.1.1

What this app does
------------------
Reads row-based “claim event” data (CSV/TSV/pipe/etc), groups events by a configurable
“base” portion of a claim identifier (business-wise: derived from EDI 837 CLM01),
and produces a report that includes:

1) A top-level SUMMARY:
   - totals across all base_ids
   - a per-base rollup row (base_id, first/last timestamps, latest status/state, headline issue, etc.)

2) Per-base DETAILS:
   - ordered events
   - prev_pk thread chains
   - rule-based findings (warnings/errors/infos)

EDI context used
----------------
- CLM05-3 (Claim Frequency Type Code): 1=Original, 7=Replacement/Correction, 8=Void/Delete
- REF*F8: Original Reference Number (often used to reference the prior/original claim for 7/8)

Install
-------
Python 3.10+ recommended (3.12 OK). Standard library only.

Typical usage
-------------
python claim_event_analyzer.py --config config.claims.json --input events.csv --out report.json
python claim_event_analyzer.py --config config.claims.json --input events.csv --out report.json --out-csv findings.csv

Debug input/header parsing (use this when you see header mismatch)
------------------------------------------------------------------
python claim_event_analyzer.py --config config.claims.json --input events.csv --out report.json --debug-read --log-level DEBUG

Why you’re seeing “missing fields” even though you “see them in the header”
---------------------------------------------------------------------------
The most common real cause is delimiter mismatch.

Example symptom:
  Parsed header columns (1): ['EVENT_ID|PREV_EVENT_ID|CLM01|CREATE_DT|...']

To a human, those column names are “right there” in that string.
To the CSV parser, that is ONE column name because it never split the header line.

Fix:
  Set io.delimiter to the actual delimiter in the file (e.g. "|" or "," or "\\t").
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


APP_NAME = "claim_event_analyzer"
APP_VERSION = "1.1.1"

LOG = logging.getLogger(APP_NAME)

COMMON_DELIMS: Sequence[str] = [",", "|", "\t", ";"]


# -----------------------------
# Models
# -----------------------------
@dataclass(frozen=True)
class Event:
    """A single inbound row normalized into typed fields used for diagnostics."""
    base_id: str
    clm01_full: str
    clm_suffix: str

    pk: str
    prev_pk: str

    ref_f8: str

    system_state: str
    system_status: str

    clm0503: str
    system_clm0503: str

    cms_icn: str
    cms_out_icn: str

    created_at: datetime

    raw: Dict[str, str]


@dataclass(frozen=True)
class Finding:
    """A diagnostic produced by a rule."""
    code: str
    severity: str  # INFO/WARN/ERROR
    message: str
    related_pks: Tuple[str, ...] = ()
    related_rows: Tuple[int, ...] = ()


@dataclass
class BaseGroupReport:
    """Report for one base_id."""
    base_id: str
    created_min: datetime
    created_max: datetime
    events_sorted: List[Event]
    threads: List[List[str]]
    findings: List[Finding]


# -----------------------------
# Config helpers
# -----------------------------
def _must(d: Dict[str, Any], key: str) -> Any:
    """Fetch a required config key or raise a clear error."""
    if key not in d or d[key] in (None, ""):
        raise ValueError(f"Config missing required key: {key}")
    return d[key]


def _get(d: Dict[str, Any], key: str, default: Any) -> Any:
    """Fetch an optional config key."""
    return d.get(key, default)


def _required_internal_fields() -> Set[str]:
    """Internal logical fields required for the app to function."""
    return {"pk", "clm01_full", "created_at"}


def _field_display(cfg_fields: Dict[str, str]) -> str:
    """Pretty display of internal->input header mapping for logs/errors."""
    lines = ["Field mapping (internal -> input header):"]
    longest = max((len(k) for k in cfg_fields.keys()), default=0)
    for k in sorted(cfg_fields.keys()):
        lines.append(f"  {k:<{longest}} -> {cfg_fields[k]}")
    return "\n".join(lines)


def _delimiter_diagnostics(header_line: str, configured: str) -> str:
    """Heuristic: counts of common delimiters in the header line to detect mismatch."""
    counts = {d: header_line.count(d) for d in COMMON_DELIMS}
    parts = ["Header delimiter counts: " + ", ".join([f"{repr(k)}={v}" for k, v in counts.items()])]
    if counts.get(configured, 0) == 0:
        best = max(counts.items(), key=lambda kv: kv[1])
        if best[1] > 0:
            parts.append(
                f"Configured delimiter {repr(configured)} does not appear in the header line, "
                f"but {repr(best[0])} appears {best[1]} times. Check your io.delimiter."
            )
    return "\n".join(parts)


def _debug_header_chars(label: str, s: str) -> str:
    """
    Make invisible header issues obvious:
      - shows repr
      - shows code points for the first few chars
    """
    s = s or ""
    cps = " ".join([f"U+{ord(ch):04X}" for ch in s[:40]])
    return f"{label}: repr={s!r} | first_chars_codepoints={cps}"


def parse_datetime(value: str, fmt: str) -> datetime:
    """
    Parse a datetime string using either:
      - explicit strptime format, or
      - if fmt == "ISO", use datetime.fromisoformat
    Returns an aware datetime in UTC.

    Note: If an input datetime is naive (no tzinfo), we assume UTC in v1.x.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("created_at is blank")

    if fmt.upper() == "ISO":
        dt = datetime.fromisoformat(value)
    else:
        dt = datetime.strptime(value, fmt)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _strip_surrounding_quotes(s: str) -> str:
    """Remove one layer of surrounding single/double quotes if present."""
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    return s


def _normalize_header(name: str, match_mode: str) -> str:
    """
    Normalize a header name for matching.

    match_mode:
      - "exact": strip whitespace only
      - "case_insensitive": strip + lowercase
      - "normalized": strip + remove surrounding quotes + collapse whitespace + lowercase +
                      remove a few common invisible chars (BOM, NBSP, ZWSP)
    """
    if name is None:
        return ""

    s = name.strip()

    if match_mode.lower() in ("normalized", "case_insensitive"):
        # Sometimes headers come in as '"CLM01"' or with odd spacing.
        s = _strip_surrounding_quotes(s)
        # remove common invisible/control characters that sneak in
        s = s.replace("\ufeff", "").replace("\u200b", "").replace("\xa0", " ")
        # collapse whitespace
        s = re.sub(r"\s+", " ", s).strip()

    if match_mode.lower() in ("case_insensitive", "normalized"):
        s = s.lower()

    return s


def _resolve_header(
    parsed_headers: List[str],
    desired_header: str,
    match_mode: str,
) -> Optional[str]:
    """
    Given parsed headers from the file and a desired header from config,
    find the actual header key used in DictReader row dicts.

    Returns the matched actual header, or None if not found.
    """
    desired_norm = _normalize_header(desired_header, match_mode)
    if not desired_norm:
        return None

    mapping: Dict[str, str] = {}
    for h in parsed_headers:
        mapping[_normalize_header(h, match_mode)] = h  # last wins (headers should be unique)

    return mapping.get(desired_norm)


def _maybe_sniff_delimiter(header_line: str, configured: str, enabled: bool) -> str:
    """
    Optional safety net: attempt to sniff delimiter from header line.
    Uses csv.Sniffer with a restricted delimiter set.
    """
    if not enabled:
        return configured

    try:
        dialect = csv.Sniffer().sniff(header_line, delimiters="".join(COMMON_DELIMS))
        sniffed = getattr(dialect, "delimiter", configured)
        return sniffed or configured
    except Exception:
        return configured


# -----------------------------
# Input reading
# -----------------------------
def read_events(
    input_path: Path,
    cfg: Dict[str, Any],
    debug_read: bool = False,
) -> List[Event]:
    """
    Read input rows and normalize into Event objects.
    Produces rich debug output (header + mapping resolution + sample rows) when debug_read=True.
    """
    io_cfg = _must(cfg, "io")
    fields = _must(cfg, "fields")
    grouping = _must(cfg, "grouping")

    configured_delimiter = _get(io_cfg, "delimiter", ",")
    encoding = _get(io_cfg, "encoding", "utf-8-sig")
    dt_fmt = _get(io_cfg, "datetime_format", "ISO")
    header_match_mode = _get(io_cfg, "header_match", "exact")  # exact|case_insensitive|normalized
    sniff_delimiter = bool(_get(io_cfg, "sniff_delimiter", False))

    base_len = int(_get(grouping, "base_len", 10))
    suffix_len = int(_get(grouping, "suffix_len", 2))

    # internal -> configured input header names
    pk_header_cfg = _must(fields, "pk")
    clm01_header_cfg = _must(fields, "clm01_full")
    created_at_header_cfg = _must(fields, "created_at")

    prev_pk_header_cfg = _get(fields, "prev_pk", "")
    ref_f8_header_cfg = _get(fields, "ref_f8", "")
    system_state_header_cfg = _get(fields, "system_state", "")
    system_status_header_cfg = _get(fields, "system_status", "")
    clm0503_header_cfg = _get(fields, "clm0503", "")
    system_clm0503_header_cfg = _get(fields, "system_clm0503", "")
    cms_icn_header_cfg = _get(fields, "cms_icn", "")
    cms_out_icn_header_cfg = _get(fields, "cms_out_icn", "")

    # validate internal keys exist
    missing_internal = [k for k in _required_internal_fields() if k not in fields]
    if missing_internal:
        raise ValueError(f"Config missing required internal mapping(s): {missing_internal}")

    if debug_read:
        LOG.info("Reading input: %s", str(input_path))
        LOG.info("Configured delimiter: %r | encoding: %s | datetime_format: %s", configured_delimiter, encoding, dt_fmt)
        LOG.info("Header match mode: %s | sniff_delimiter: %s", header_match_mode, sniff_delimiter)
        LOG.info("Configured base_len=%s suffix_len=%s", base_len, suffix_len)
        LOG.info("\n%s", _field_display(fields))
        LOG.info(_debug_header_chars("cfg.pk", pk_header_cfg))
        LOG.info(_debug_header_chars("cfg.clm01_full", clm01_header_cfg))
        LOG.info(_debug_header_chars("cfg.created_at", created_at_header_cfg))

    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    with input_path.open("r", encoding=encoding, newline="") as f:
        header_line = f.readline()
        if not header_line:
            raise ValueError("Input file is empty.")

        if debug_read:
            LOG.info("Raw header line (first 300 chars): %r", header_line[:300])
            LOG.info("%s", _delimiter_diagnostics(header_line, configured_delimiter))

        delimiter = _maybe_sniff_delimiter(header_line, configured_delimiter, sniff_delimiter)
        if debug_read and delimiter != configured_delimiter:
            LOG.warning("Delimiter sniffed %r (overriding configured %r) based on header line.", delimiter, configured_delimiter)

        f.seek(0)
        reader = csv.DictReader(f, delimiter=delimiter)
        if not reader.fieldnames:
            raise ValueError("Input appears to have no header row (DictReader.fieldnames is empty).")

        # strip whitespace from headers
        parsed_headers = [(h.strip() if h is not None else "") for h in reader.fieldnames]
        reader.fieldnames = parsed_headers

        if debug_read:
            LOG.info("Parsed header columns (%d): %s", len(parsed_headers), parsed_headers)
            # If it parsed only 1 header, call it out loudly (this is almost always delimiter mismatch)
            if len(parsed_headers) == 1 and any(d in parsed_headers[0] for d in COMMON_DELIMS):
                LOG.warning(
                    "Parsed exactly 1 header column that still contains delimiter characters. "
                    "This strongly suggests delimiter mismatch. Parsed header[0]=%r",
                    parsed_headers[0],
                )
            for i, h in enumerate(parsed_headers[:25]):
                LOG.info(_debug_header_chars(f"header[{i}]", h))

        # resolve configured headers to actual parsed headers
        pk_h = _resolve_header(parsed_headers, pk_header_cfg, header_match_mode)
        clm01_h = _resolve_header(parsed_headers, clm01_header_cfg, header_match_mode)
        created_h = _resolve_header(parsed_headers, created_at_header_cfg, header_match_mode)

        if debug_read:
            LOG.info(
                "Resolved required headers:\n"
                "  pk         cfg=%r norm=%r -> actual=%r\n"
                "  clm01_full  cfg=%r norm=%r -> actual=%r\n"
                "  created_at  cfg=%r norm=%r -> actual=%r",
                pk_header_cfg, _normalize_header(pk_header_cfg, header_match_mode), pk_h,
                clm01_header_cfg, _normalize_header(clm01_header_cfg, header_match_mode), clm01_h,
                created_at_header_cfg, _normalize_header(created_at_header_cfg, header_match_mode), created_h,
            )

        missing_required_actual: List[str] = []
        if not pk_h:
            missing_required_actual.append(pk_header_cfg)
        if not clm01_h:
            missing_required_actual.append(clm01_header_cfg)
        if not created_h:
            missing_required_actual.append(created_at_header_cfg)

        if missing_required_actual:
            # Help the “but I see them right there!” scenario: show normalized header map keys
            norm_map_keys = sorted({_normalize_header(h, header_match_mode) for h in parsed_headers if h})
            raise ValueError(
                "Header validation failed.\n"
                f"Missing required input column(s): {missing_required_actual}\n"
                f"Delimiter used: {delimiter!r} (configured: {configured_delimiter!r})\n"
                f"Header columns seen ({len(parsed_headers)}): {parsed_headers}\n\n"
                f"{_field_display(fields)}\n\n"
                f"Normalized header keys seen (mode={header_match_mode}): {norm_map_keys}\n\n"
                "Most common cause: delimiter mismatch. If header columns show as ONE big string, fix io.delimiter.\n"
                "If it’s a case/quotes/whitespace issue, set io.header_match to \"case_insensitive\" or \"normalized\"."
            )

        # resolve optional headers
        prev_h = _resolve_header(parsed_headers, prev_pk_header_cfg, header_match_mode) if prev_pk_header_cfg else None
        ref_f8_h = _resolve_header(parsed_headers, ref_f8_header_cfg, header_match_mode) if ref_f8_header_cfg else None
        sys_state_h = _resolve_header(parsed_headers, system_state_header_cfg, header_match_mode) if system_state_header_cfg else None
        sys_status_h = _resolve_header(parsed_headers, system_status_header_cfg, header_match_mode) if system_status_header_cfg else None
        clm0503_h = _resolve_header(parsed_headers, clm0503_header_cfg, header_match_mode) if clm0503_header_cfg else None
        sys_clm0503_h = _resolve_header(parsed_headers, system_clm0503_header_cfg, header_match_mode) if system_clm0503_header_cfg else None
        cms_icn_h = _resolve_header(parsed_headers, cms_icn_header_cfg, header_match_mode) if cms_icn_header_cfg else None
        cms_out_icn_h = _resolve_header(parsed_headers, cms_out_icn_header_cfg, header_match_mode) if cms_out_icn_header_cfg else None

        if debug_read:
            LOG.info(
                "Resolved optional headers:\n"
                "  prev_pk        cfg=%r -> actual=%r\n"
                "  ref_f8         cfg=%r -> actual=%r\n"
                "  system_state   cfg=%r -> actual=%r\n"
                "  system_status  cfg=%r -> actual=%r\n"
                "  clm0503        cfg=%r -> actual=%r\n"
                "  system_clm0503 cfg=%r -> actual=%r\n"
                "  cms_icn        cfg=%r -> actual=%r\n"
                "  cms_out_icn    cfg=%r -> actual=%r",
                prev_pk_header_cfg, prev_h,
                ref_f8_header_cfg, ref_f8_h,
                system_state_header_cfg, sys_state_h,
                system_status_header_cfg, sys_status_h,
                clm0503_header_cfg, clm0503_h,
                system_clm0503_header_cfg, sys_clm0503_h,
                cms_icn_header_cfg, cms_icn_h,
                cms_out_icn_header_cfg, cms_out_icn_h,
            )

        events: List[Event] = []
        total_rows = 0
        emitted = 0
        skipped_blank_clm01 = 0
        sample_shown = 0

        for row in reader:
            total_rows += 1

            # normalize keys: strip (extra safety)
            row = {(k.strip() if k else k): v for k, v in row.items()}

            pk = (row.get(pk_h, "") or "").strip()
            clm01_full = (row.get(clm01_h, "") or "").strip()
            created_at_raw = (row.get(created_h, "") or "").strip()

            if debug_read and sample_shown < 3:
                LOG.info("Sample row %d mapped values: pk=%r clm01=%r created_at=%r", sample_shown + 1, pk, clm01_full, created_at_raw)
                sample_shown += 1

            if not clm01_full:
                skipped_blank_clm01 += 1
                continue

            if not pk:
                raise ValueError(
                    f"Row missing PK value under column {pk_h!r}. "
                    f"Check your mapping: pk -> {pk_header_cfg!r}."
                )

            created_at = parse_datetime(created_at_raw, dt_fmt)

            base_id = clm01_full[:base_len]
            clm_suffix = clm01_full[base_len:base_len + suffix_len] if len(clm01_full) >= base_len else ""

            prev_pk = (row.get(prev_h, "") or "").strip() if prev_h else ""
            ref_f8 = (row.get(ref_f8_h, "") or "").strip() if ref_f8_h else ""
            system_state = (row.get(sys_state_h, "") or "").strip() if sys_state_h else ""
            system_status = (row.get(sys_status_h, "") or "").strip() if sys_status_h else ""
            clm0503 = (row.get(clm0503_h, "") or "").strip() if clm0503_h else ""
            system_clm0503 = (row.get(sys_clm0503_h, "") or "").strip() if sys_clm0503_h else ""
            cms_icn = (row.get(cms_icn_h, "") or "").strip() if cms_icn_h else ""
            cms_out_icn = (row.get(cms_out_icn_h, "") or "").strip() if cms_out_icn_h else ""

            events.append(
                Event(
                    base_id=base_id,
                    clm01_full=clm01_full,
                    clm_suffix=clm_suffix,
                    pk=pk,
                    prev_pk=prev_pk,
                    ref_f8=ref_f8,
                    system_state=system_state,
                    system_status=system_status,
                    clm0503=clm0503,
                    system_clm0503=system_clm0503,
                    cms_icn=cms_icn,
                    cms_out_icn=cms_out_icn,
                    created_at=created_at,
                    raw=row,
                )
            )
            emitted += 1

        if debug_read:
            LOG.info(
                "Read summary: total_rows=%d emitted_events=%d skipped_blank_clm01=%d",
                total_rows, emitted, skipped_blank_clm01
            )

        return events


# -----------------------------
# Thread building (PK chains)
# -----------------------------
def build_threads(events_sorted: List[Event]) -> Tuple[List[List[str]], List[Finding]]:
    """
    Build threads using prev_pk links.
    Returns:
      - list of threads (each is ordered PK list)
      - findings about missing references / cycles / splits
    """
    findings: List[Finding] = []

    by_pk: Dict[str, Event] = {e.pk: e for e in events_sorted}
    children: Dict[str, List[str]] = defaultdict(list)
    roots: List[str] = []

    for e in events_sorted:
        if e.prev_pk and e.prev_pk in by_pk:
            children[e.prev_pk].append(e.pk)
        elif e.prev_pk and e.prev_pk not in by_pk:
            findings.append(
                Finding(
                    code="CHAIN_MISSING_PREV_PK",
                    severity="WARN",
                    message=f"Event references prev_pk '{e.prev_pk}' that is not present in this base group.",
                    related_pks=(e.pk,),
                )
            )
            roots.append(e.pk)
        else:
            roots.append(e.pk)

    # Deduplicate roots while preserving event order
    seen: Set[str] = set()
    roots_ordered: List[str] = []
    for e in events_sorted:
        if e.pk in roots and e.pk not in seen:
            roots_ordered.append(e.pk)
            seen.add(e.pk)

    threads: List[List[str]] = []

    def dfs(path: List[str], current_pk: str) -> None:
        """Depth-first expansion to enumerate thread paths, splitting when multiple children exist."""
        kids = children.get(current_pk, [])
        if not kids:
            threads.append(path[:])
            return

        if len(kids) > 1:
            findings.append(
                Finding(
                    code="CHAIN_SPLIT",
                    severity="INFO",
                    message=f"Thread splits from pk '{current_pk}' into {len(kids)} child events.",
                    related_pks=(current_pk, *tuple(kids)),
                )
            )

        for k in sorted(kids, key=lambda pk_: by_pk[pk_].created_at):
            if k in path:
                findings.append(
                    Finding(
                        code="CHAIN_CYCLE",
                        severity="ERROR",
                        message="Cycle detected in prev_pk chain.",
                        related_pks=tuple(path + [k]),
                    )
                )
                continue
            dfs(path + [k], k)

    for r in roots_ordered:
        dfs([r], r)

    return threads, findings


# -----------------------------
# Rules
# -----------------------------
def rule_expected_acceptance(events_sorted: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    """
    Typical expectation:
      - suffix '00' should eventually reach an “ACCEPTED”-like status.
    If not seen, warn.
    """
    rules_cfg = _must(cfg, "rules")
    accepted_status_values = set(_get(rules_cfg, "accepted_status_values", ["CMS ACCEPTED", "ACCEPTED"]))
    expected_suffix = str(_get(rules_cfg, "expected_suffix", "00")).strip()

    accepted = [e for e in events_sorted if e.system_status in accepted_status_values]
    accepted_suffix = [e for e in accepted if e.clm_suffix == expected_suffix]

    findings: List[Finding] = []
    if not accepted_suffix:
        if accepted:
            findings.append(
                Finding(
                    code="ACCEPTED_BUT_NOT_EXPECTED_SUFFIX",
                    severity="WARN",
                    message=f"Acceptance exists, but not for expected suffix '{expected_suffix}'.",
                    related_pks=tuple(e.pk for e in accepted),
                )
            )
        else:
            findings.append(
                Finding(
                    code="MISSING_ACCEPTANCE",
                    severity="WARN",
                    message=f"No event found with an accepted status for suffix '{expected_suffix}'.",
                    related_pks=tuple(e.pk for e in events_sorted[:3]),
                )
            )
    return findings


def rule_locked_before_acceptance(events_sorted: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    """
    Detect LOCKED events that occurred before the first accepted event timestamp.
    Often indicates a later action arrived while earlier processing hadn't completed.
    """
    rules_cfg = _must(cfg, "rules")
    accepted_status_values = set(_get(rules_cfg, "accepted_status_values", ["CMS ACCEPTED", "ACCEPTED"]))
    locked_status_values = set(_get(rules_cfg, "locked_status_values", ["LOCKED"]))

    accepted_events = [e for e in events_sorted if e.system_status in accepted_status_values]
    if not accepted_events:
        return []

    first_accept_time = min(e.created_at for e in accepted_events)
    locked_early = [e for e in events_sorted if e.system_status in locked_status_values and e.created_at < first_accept_time]

    if not locked_early:
        return []

    return [
        Finding(
            code="LOCKED_BEFORE_ACCEPTANCE",
            severity="WARN",
            message="Found LOCKED event(s) that occurred before the first accepted event; likely queued behind earlier processing.",
            related_pks=tuple(e.pk for e in locked_early),
        )
    ]


def rule_correction_void_requires_f8(events_sorted: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    """
    For CLM05-3 = 7 or 8, expect REF*F8 to be populated.
    Checks both inbound clm0503 and system_clm0503 (if present).
    """
    _ = cfg
    findings: List[Finding] = []
    for e in events_sorted:
        freq_candidates = {e.clm0503.strip(), e.system_clm0503.strip()}
        freq_candidates.discard("")
        if freq_candidates.intersection({"7", "8"}) and not e.ref_f8:
            findings.append(
                Finding(
                    code="MISSING_REF_F8_FOR_7_8",
                    severity="WARN",
                    message="Correction/Void indicated (CLM05-3 7/8) but REF*F8 is blank.",
                    related_pks=(e.pk,),
                )
            )
    return findings


def rule_system_freq_differs(events_sorted: List[Event], cfg: Dict[str, Any]) -> List[Finding]:
    """Informational: system-altered frequency code differs from inbound frequency code."""
    _ = cfg
    findings: List[Finding] = []
    for e in events_sorted:
        if e.clm0503 and e.system_clm0503 and e.clm0503 != e.system_clm0503:
            findings.append(
                Finding(
                    code="SYSTEM_FREQ_OVERRIDE",
                    severity="INFO",
                    message=f"System frequency differs from inbound frequency (inbound={e.clm0503}, system={e.system_clm0503}).",
                    related_pks=(e.pk,),
                )
            )
    return findings


RULES = [
    rule_expected_acceptance,
    rule_locked_before_acceptance,
    rule_correction_void_requires_f8,
    rule_system_freq_differs,
]


# -----------------------------
# Digest + summary
# -----------------------------
def digest(events: List[Event], cfg: Dict[str, Any]) -> List[BaseGroupReport]:
    """Group events by base_id, order by created_at, build threads, run rules, and return reports."""
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        grouped[e.base_id].append(e)

    reports: List[BaseGroupReport] = []

    for base_id, group_events in grouped.items():
        group_sorted = sorted(group_events, key=lambda e: (e.created_at, e.pk))

        threads, thread_findings = build_threads(group_sorted)

        findings: List[Finding] = []
        findings.extend(thread_findings)
        for rule in RULES:
            findings.extend(rule(group_sorted, cfg))

        created_min = min(e.created_at for e in group_sorted)
        created_max = max(e.created_at for e in group_sorted)

        severity_rank = {"ERROR": 0, "WARN": 1, "INFO": 2}
        findings_sorted = sorted(findings, key=lambda f: (severity_rank.get(f.severity, 9), f.code, f.message))

        reports.append(
            BaseGroupReport(
                base_id=base_id,
                created_min=created_min,
                created_max=created_max,
                events_sorted=group_sorted,
                threads=threads,
                findings=findings_sorted,
            )
        )

    reports.sort(key=lambda r: (r.created_min, r.base_id))
    return reports


def _count_findings(findings: Iterable[Finding]) -> Dict[str, int]:
    """Count findings by severity."""
    out = {"ERROR": 0, "WARN": 0, "INFO": 0}
    for f in findings:
        if f.severity in out:
            out[f.severity] += 1
        else:
            out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _headline_for_base(findings: List[Finding]) -> str:
    """Pick a single headline issue for a base_id."""
    if not findings:
        return "OK"
    for sev in ("ERROR", "WARN", "INFO"):
        for f in findings:
            if f.severity == sev:
                return f.code
    return findings[0].code


def _has_status(events: List[Event], values: Set[str]) -> bool:
    """True if any event has a system_status in the provided set."""
    return any(e.system_status in values for e in events)


def _latest_nonblank(values: List[str]) -> str:
    """Return latest nonblank string from a list (or blank)."""
    for v in reversed(values):
        if v:
            return v
    return ""


def to_jsonable(reports: List[BaseGroupReport], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Convert reports to JSON-serializable structure with top-level summary + per-base details."""
    rules_cfg = _must(cfg, "rules")
    accepted_status_values = set(_get(rules_cfg, "accepted_status_values", ["CMS ACCEPTED", "ACCEPTED"]))
    locked_status_values = set(_get(rules_cfg, "locked_status_values", ["LOCKED"]))

    base_rollup: List[Dict[str, Any]] = []
    all_findings: List[Finding] = []
    all_events_count = 0

    for r in reports:
        all_events_count += len(r.events_sorted)
        all_findings.extend(r.findings)

        latest_status = _latest_nonblank([e.system_status for e in r.events_sorted])
        latest_state = _latest_nonblank([e.system_state for e in r.events_sorted])

        counts = _count_findings(r.findings)
        base_rollup.append(
            {
                "base_id": r.base_id,
                "created_min_utc": r.created_min.isoformat(),
                "created_max_utc": r.created_max.isoformat(),
                "event_count": len(r.events_sorted),
                "latest_system_status": latest_status,
                "latest_system_state": latest_state,
                "has_acceptance": _has_status(r.events_sorted, accepted_status_values),
                "has_locked": _has_status(r.events_sorted, locked_status_values),
                "headline": _headline_for_base(r.findings),
                "finding_counts": counts,
            }
        )

    totals_by_sev = _count_findings(all_findings)
    bases_with_warn_or_error = sum(
        1 for r in reports if any(f.severity in ("WARN", "ERROR") for f in r.findings)
    )

    out: Dict[str, Any] = {
        "app": {"name": APP_NAME, "version": APP_VERSION},
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "base_count": len(reports),
            "event_count": all_events_count,
            "findings_total": len(all_findings),
            "findings_by_severity": totals_by_sev,
            "bases_with_warn_or_error": bases_with_warn_or_error,
            "base_rollup": base_rollup,
        },
        "bases": [],
    }

    for r in reports:
        out["bases"].append(
            {
                "base_id": r.base_id,
                "created_min_utc": r.created_min.isoformat(),
                "created_max_utc": r.created_max.isoformat(),
                "event_count": len(r.events_sorted),
                "threads": r.threads,
                "findings": [dataclasses.asdict(f) for f in r.findings],
                "events": [
                    {
                        "pk": e.pk,
                        "prev_pk": e.prev_pk,
                        "created_at_utc": e.created_at.isoformat(),
                        "clm01_full": e.clm01_full,
                        "clm_suffix": e.clm_suffix,
                        "ref_f8": e.ref_f8,
                        "system_status": e.system_status,
                        "system_state": e.system_state,
                        "clm0503": e.clm0503,
                        "system_clm0503": e.system_clm0503,
                        "cms_icn": e.cms_icn,
                        "cms_out_icn": e.cms_out_icn,
                    }
                    for e in r.events_sorted
                ],
            }
        )

    return out


def write_findings_csv(reports: List[BaseGroupReport], out_path: Path) -> None:
    """Write a flat findings CSV for easy filtering/sorting."""
    rows: List[Dict[str, str]] = []
    for r in reports:
        for f in r.findings:
            rows.append(
                {
                    "base_id": r.base_id,
                    "severity": f.severity,
                    "code": f.code,
                    "message": f.message,
                    "related_pks": ",".join(f.related_pks),
                }
            )

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["base_id", "severity", "code", "message", "related_pks"])
        w.writeheader()
        w.writerows(rows)


# -----------------------------
# CLI
# -----------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """CLI argument parsing."""
    p = argparse.ArgumentParser(prog=APP_NAME)
    p.add_argument("--config", required=True, help="Path to config JSON.")
    p.add_argument("--input", required=True, help="Path to input delimited file.")
    p.add_argument("--out", required=True, help="Path to output JSON report.")
    p.add_argument("--out-csv", default="", help="Optional: path to findings CSV.")
    p.add_argument("--debug-read", action="store_true", help="Print detailed input/header/mapping diagnostics.")
    p.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARN, ERROR")
    return p.parse_args(argv)


def configure_logging(level: str) -> None:
    """Configure console logging."""
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(level=lvl, format="%(levelname)s %(message)s")


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    args = parse_args(argv)
    configure_logging(args.log_level)

    print(f"{APP_NAME} v{APP_VERSION}")
    LOG.info("Using config: %s", str(Path(args.config).resolve()))
    LOG.info("Using input:  %s", str(Path(args.input).resolve()))

    cfg_path = Path(args.config)
    in_path = Path(args.input)
    out_path = Path(args.out)

    if not cfg_path.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    events = read_events(in_path, cfg, debug_read=args.debug_read)

    if not events:
        LOG.warning(
            "No events were emitted after parsing. This usually means CLM01 is blank for all rows, "
            "or your delimiter/header mapping does not match the file."
        )

    reports = digest(events, cfg)
    out_json = to_jsonable(reports, cfg)

    out_path.write_text(json.dumps(out_json, indent=2), encoding="utf-8")

    if args.out_csv:
        write_findings_csv(reports, Path(args.out_csv))

    print(f"Wrote report: {out_path}")
    if args.out_csv:
        print(f"Wrote findings CSV: {args.out_csv}")

    summ = out_json.get("summary", {})
    print(
        f"Bases: {summ.get('base_count', 0)} | "
        f"Events: {summ.get('event_count', 0)} | "
        f"Findings: {summ.get('findings_total', 0)} | "
        f"WARN/ERROR bases: {summ.get('bases_with_warn_or_error', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
