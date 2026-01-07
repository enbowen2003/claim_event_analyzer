#!/usr/bin/env python3
"""
claim_event_analyzer.py

Version: 1.3.0

Goals for v1.3.0
----------------
- CSV is the primary (default) output. JSON is removed to avoid confusion.
- Output is consistent: the same "pertinent field data" is what you get in CSV.
- Add rule logic that understands events in relation to other PKs in the same base_id "family".
- Keep it less wordy: findings are compact (codes + short note).

Core idea
---------
We group events by a configurable base_id derived from CLM01 (first N chars),
then order events by created_at and build a family context timeline so per-event
classification can reference prior events.

Outputs
-------
1) Events CSV (required): one row per event, includes:
   - core tracked fields (CLM01, timestamp, state, status, etc.)
   - assessment_severity (OK/WARN/ERROR)
   - understanding_confidence (HIGH/MED/LOW)
   - assessment_codes (semicolon-delimited)
   - assessment_note (short)
   - related_pk (e.g., inflight pk that the LOCKED event is waiting on)

2) Base summary CSV (default alongside events CSV): one row per base_id family

Install
-------
Python 3.10+ recommended (3.12 OK). Standard library only.

Usage
-----
python claim_event_analyzer.py --version

python claim_event_analyzer.py \
  --config config.claims.json \
  --input events.txt \
  --out events_report.csv

Optional:
  --out-bases base_summary.csv
  --debug-read --log-level DEBUG
  --print-base 1234567890   (prints a short console timeline for one base_id)

Config mapping reminder
-----------------------
"fields" maps INTERNAL FIELD NAME (left) -> INPUT FILE HEADER (right).

Example:
  "fields": {
    "pk": "EVENT_ID",
    "clm01_full": "CLM01",
    "created_at": "CREATE_DT"
  }
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union


APP_NAME = "claim_event_analyzer"
APP_VERSION = "1.3.0"

LOG = logging.getLogger(APP_NAME)

COMMON_DELIMS: Sequence[str] = [",", "|", "\\t", ";"]


# -----------------------------
# Models
# -----------------------------
@dataclass(frozen=True)
class Event:
    """One inbound row normalized into typed fields used for diagnostics."""
    rownum: int

    base_id: str
    clm01_full: str

    pk: str
    prev_pk: str

    ref_f8: str

    system_state: str
    system_status: str

    clm0503: str
    system_clm0503: str

    cms_icn: str
    cms_out_icn: str

    create_by: str
    update_by: str

    created_at: datetime

    raw: Dict[str, str]


@dataclass(frozen=True)
class AssessedEvent:
    """An Event plus compact assessment results."""
    event: Event
    assessment_severity: str         # OK/WARN/ERROR
    understanding_confidence: str    # HIGH/MED/LOW
    assessment_codes: str            # ';' delimited codes
    assessment_note: str             # short note
    related_pk: str                  # e.g., inflight pk


@dataclass(frozen=True)
class BaseSummary:
    base_id: str
    event_count: int
    created_min_utc: str
    created_max_utc: str
    manual_flag: str

    first_terminal_utc: str
    terminal_statuses_seen: str

    has_locked: str

    headline_severity: str
    headline_code: str


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


def _field_display(cfg_fields: Dict[str, str]) -> str:
    """Pretty display of internal->input header mapping for logs/errors."""
    lines = ["Field mapping (internal -> input header):"]
    longest = max((len(k) for k in cfg_fields.keys()), default=0)
    for k in sorted(cfg_fields.keys()):
        lines.append(f"  {k:<{longest}} -> {cfg_fields[k]}")
    return "\\n".join(lines)


def _delimiter_diagnostics(header_line: str, configured: str) -> str:
    """Heuristic: counts of common delimiters in the header line to detect mismatch."""
    counts = {d: header_line.count(d) for d in [",", "|", "\\t", ";"]}
    parts = ["Header delimiter counts: " + ", ".join([f"{repr(k)}={v}" for k, v in counts.items()])]
    if counts.get(configured, 0) == 0:
        best = max(counts.items(), key=lambda kv: kv[1])
        if best[1] > 0:
            parts.append(
                f"Configured delimiter {repr(configured)} does not appear in the header line, "
                f"but {repr(best[0])} appears {best[1]} times. Check your io.delimiter."
            )
    return "\\n".join(parts)


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
        s = _strip_surrounding_quotes(s)
        s = s.replace("\\ufeff", "").replace("\\u200b", "").replace("\\xa0", " ")
        s = re.sub(r"\\s+", " ", s).strip()

    if match_mode.lower() in ("case_insensitive", "normalized"):
        s = s.lower()

    return s


def _resolve_header(parsed_headers: List[str], desired_header: str, match_mode: str) -> Optional[str]:
    """Resolve config header name to actual header key in the parsed file."""
    desired_norm = _normalize_header(desired_header, match_mode)
    if not desired_norm:
        return None

    mapping: Dict[str, str] = {}
    for h in parsed_headers:
        mapping[_normalize_header(h, match_mode)] = h

    return mapping.get(desired_norm)


def _maybe_sniff_delimiter(header_line: str, configured: str, enabled: bool) -> str:
    """Optional safety net: attempt to sniff delimiter from header line."""
    if not enabled:
        return configured
    try:
        dialect = csv.Sniffer().sniff(header_line, delimiters=",|\\t;")
        sniffed = getattr(dialect, "delimiter", configured)
        return sniffed or configured
    except Exception:
        return configured


# -----------------------------
# Datetime parsing
# -----------------------------
DateFmt = Union[str, Sequence[str]]


def parse_datetime(value: str, fmts: DateFmt) -> datetime:
    """
    Parse a datetime string using:
      - a single format string, or
      - multiple formats (tries in order),
      - special token "ISO" meaning datetime.fromisoformat.

    Returns an aware datetime in UTC.
    If input is naive (no tzinfo), we assume UTC in v1.x.
    """
    raw = (value or "").strip()
    if not raw:
        raise ValueError("created_at is blank")

    formats: List[str]
    if isinstance(fmts, (list, tuple)):
        formats = [str(x) for x in fmts]
    else:
        formats = [str(fmts)]

    last_err: Optional[Exception] = None
    for fmt in formats:
        try:
            if fmt.upper() == "ISO":
                dt = datetime.fromisoformat(raw)
            else:
                dt = datetime.strptime(raw, fmt)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception as e:
            last_err = e
            continue

    raise ValueError(
        f"Could not parse created_at value {raw!r} using formats: {formats}. "
        f"Last error: {last_err}"
    )


# -----------------------------
# Input reading
# -----------------------------
def read_events(input_path: Path, cfg: Dict[str, Any], debug_read: bool = False) -> List[Event]:
    """
    Read input rows and normalize into Event objects.
    Includes strong header validation + delimiter diagnostics.
    """
    io_cfg = _must(cfg, "io")
    fields = _must(cfg, "fields")
    grouping = _must(cfg, "grouping")

    configured_delimiter = _get(io_cfg, "delimiter", ",")
    encoding = _get(io_cfg, "encoding", "utf-8-sig")

    dt_formats = _get(io_cfg, "datetime_formats", None)
    dt_format = _get(io_cfg, "datetime_format", "ISO")
    dt_fmts: DateFmt = dt_formats if dt_formats else dt_format

    header_match_mode = _get(io_cfg, "header_match", "exact")  # exact|case_insensitive|normalized
    sniff_delimiter = bool(_get(io_cfg, "sniff_delimiter", False))

    base_len = int(_get(grouping, "base_len", 10))

    # Required mappings
    pk_header_cfg = _must(fields, "pk")
    clm01_header_cfg = _must(fields, "clm01_full")
    created_at_header_cfg = _must(fields, "created_at")

    # Optional mappings
    prev_pk_header_cfg = _get(fields, "prev_pk", "")
    ref_f8_header_cfg = _get(fields, "ref_f8", "")
    system_state_header_cfg = _get(fields, "system_state", "")
    system_status_header_cfg = _get(fields, "system_status", "")
    clm0503_header_cfg = _get(fields, "clm0503", "")
    system_clm0503_header_cfg = _get(fields, "system_clm0503", "")
    cms_icn_header_cfg = _get(fields, "cms_icn", "")
    cms_out_icn_header_cfg = _get(fields, "cms_out_icn", "")
    create_by_header_cfg = _get(fields, "create_by", "")
    update_by_header_cfg = _get(fields, "update_by", "")

    if debug_read:
        LOG.info("Reading input: %s", str(input_path))
        LOG.info("Configured delimiter: %r | encoding: %s", configured_delimiter, encoding)
        LOG.info("Datetime formats: %r", dt_fmts)
        LOG.info("Header match mode: %s | sniff_delimiter: %s", header_match_mode, sniff_delimiter)
        LOG.info("Configured base_len=%s", base_len)
        LOG.info("\\n%s", _field_display(fields))

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

        parsed_headers = [(h.strip() if h is not None else "") for h in reader.fieldnames]
        reader.fieldnames = parsed_headers

        if debug_read:
            LOG.info("Parsed header columns (%d): %s", len(parsed_headers), parsed_headers)
            if len(parsed_headers) == 1 and any(d in parsed_headers[0] for d in [",", "|", "\\t", ";"]):
                LOG.warning(
                    "Parsed exactly 1 header column that still contains delimiter characters. "
                    "This strongly suggests delimiter mismatch. Parsed header[0]=%r",
                    parsed_headers[0],
                )

        # Resolve required headers
        pk_h = _resolve_header(parsed_headers, pk_header_cfg, header_match_mode)
        clm01_h = _resolve_header(parsed_headers, clm01_header_cfg, header_match_mode)
        created_h = _resolve_header(parsed_headers, created_at_header_cfg, header_match_mode)

        missing_required: List[str] = []
        if not pk_h:
            missing_required.append(pk_header_cfg)
        if not clm01_h:
            missing_required.append(clm01_header_cfg)
        if not created_h:
            missing_required.append(created_at_header_cfg)

        if missing_required:
            raise ValueError(
                "Header validation failed.\\n"
                f"Missing required input column(s): {missing_required}\\n"
                f"Delimiter used: {delimiter!r} (configured: {configured_delimiter!r})\\n"
                f"Header columns seen ({len(parsed_headers)}): {parsed_headers}\\n\\n"
                f"{_field_display(fields)}\\n\\n"
                "Most common cause: delimiter mismatch. If header columns show as ONE big string, fix io.delimiter.\\n"
                "If it’s a case/quotes/whitespace issue, set io.header_match to \\"case_insensitive\\" or \\"normalized\\"."
            )

        # Resolve optional headers
        prev_h = _resolve_header(parsed_headers, prev_pk_header_cfg, header_match_mode) if prev_pk_header_cfg else None
        ref_f8_h = _resolve_header(parsed_headers, ref_f8_header_cfg, header_match_mode) if ref_f8_header_cfg else None
        sys_state_h = _resolve_header(parsed_headers, system_state_header_cfg, header_match_mode) if system_state_header_cfg else None
        sys_status_h = _resolve_header(parsed_headers, system_status_header_cfg, header_match_mode) if system_status_header_cfg else None
        clm0503_h = _resolve_header(parsed_headers, clm0503_header_cfg, header_match_mode) if clm0503_header_cfg else None
        sys_clm0503_h = _resolve_header(parsed_headers, system_clm0503_header_cfg, header_match_mode) if system_clm0503_header_cfg else None
        cms_icn_h = _resolve_header(parsed_headers, cms_icn_header_cfg, header_match_mode) if cms_icn_header_cfg else None
        cms_out_icn_h = _resolve_header(parsed_headers, cms_out_icn_header_cfg, header_match_mode) if cms_out_icn_header_cfg else None
        create_by_h = _resolve_header(parsed_headers, create_by_header_cfg, header_match_mode) if create_by_header_cfg else None
        update_by_h = _resolve_header(parsed_headers, update_by_header_cfg, header_match_mode) if update_by_header_cfg else None

        events: List[Event] = []
        total_rows = 0
        emitted = 0
        skipped_blank_clm01 = 0

        for row in reader:
            total_rows += 1
            row = {(k.strip() if k else k): v for k, v in row.items()}

            pk = (row.get(pk_h, "") or "").strip()
            clm01_full = (row.get(clm01_h, "") or "").strip()
            created_at_raw = (row.get(created_h, "") or "").strip()

            if not clm01_full:
                skipped_blank_clm01 += 1
                continue

            if not pk:
                raise ValueError(
                    f"Row {total_rows}: missing PK value under column {pk_h!r}. "
                    f"Check your mapping: pk -> {pk_header_cfg!r}."
                )

            created_at = parse_datetime(created_at_raw, dt_fmts)

            base_id = clm01_full[:base_len]

            prev_pk = (row.get(prev_h, "") or "").strip() if prev_h else ""
            ref_f8 = (row.get(ref_f8_h, "") or "").strip() if ref_f8_h else ""
            system_state = (row.get(sys_state_h, "") or "").strip() if sys_state_h else ""
            system_status = (row.get(sys_status_h, "") or "").strip() if sys_status_h else ""
            clm0503 = (row.get(clm0503_h, "") or "").strip() if clm0503_h else ""
            system_clm0503 = (row.get(sys_clm0503_h, "") or "").strip() if sys_clm0503_h else ""
            cms_icn = (row.get(cms_icn_h, "") or "").strip() if cms_icn_h else ""
            cms_out_icn = (row.get(cms_out_icn_h, "") or "").strip() if cms_out_icn_h else ""
            create_by = (row.get(create_by_h, "") or "").strip() if create_by_h else ""
            update_by = (row.get(update_by_h, "") or "").strip() if update_by_h else ""

            events.append(
                Event(
                    rownum=total_rows,
                    base_id=base_id,
                    clm01_full=clm01_full,
                    pk=pk,
                    prev_pk=prev_pk,
                    ref_f8=ref_f8,
                    system_state=system_state,
                    system_status=system_status,
                    clm0503=clm0503,
                    system_clm0503=system_clm0503,
                    cms_icn=cms_icn,
                    cms_out_icn=cms_out_icn,
                    create_by=create_by,
                    update_by=update_by,
                    created_at=created_at,
                    raw=row,
                )
            )
            emitted += 1

        if debug_read:
            LOG.info("Read summary: total_rows=%d emitted_events=%d skipped_blank_clm01=%d", total_rows, emitted, skipped_blank_clm01)

        return events


# -----------------------------
# Family interpretation
# -----------------------------
def _upper(s: str) -> str:
    return (s or "").upper()


def effective_clm0503(e: Event) -> str:
    """Prefer system_clm0503 when present, else inbound clm0503."""
    return (e.system_clm0503 or e.clm0503 or "").strip()


def action_type_from_clm0503(code: str) -> str:
    """Map CLM05-3 to an action type label."""
    code = (code or "").strip()
    if code == "1":
        return "ORIGINAL"
    if code == "7":
        return "CORRECTION"
    if code == "8":
        return "DELETE"
    if code:
        return f"UNKNOWN({code})"
    return ""


def status_implies_action(system_status: str) -> str:
    """
    Some systems embed action hints in status text (e.g., "... CORRECTION ..." or "... DELETE ...").
    Returns 'CORRECTION' / 'DELETE' / ''.
    """
    su = _upper(system_status)
    if "CORRECTION" in su:
        return "CORRECTION"
    if "DELETE" in su or "VOID" in su:
        return "DELETE"
    return ""


def starts_with_any(s: str, prefixes: Sequence[str]) -> bool:
    su = _upper(s).strip()
    for p in prefixes:
        if su.startswith(_upper(p).strip()):
            return True
    return False


def assess_family(events_sorted: List[Event], cfg: Dict[str, Any]) -> Tuple[List[AssessedEvent], BaseSummary]:
    """
    Build base-level context and then assess each event using that context.
    """
    rules = _must(cfg, "rules")

    accepted_status_values = set(_upper(x) for x in _get(rules, "accepted_status_values", ["CMS ACCEPTED", "ACCEPTED"]))
    rejected_status_values = set(_upper(x) for x in _get(rules, "rejected_status_values", ["REJECTED"]))
    terminal_status_values = accepted_status_values.union(rejected_status_values)

    locked_status_values = set(_upper(x) for x in _get(rules, "locked_status_values", ["LOCKED"]))
    submitted_state_values = set(_upper(x) for x in _get(rules, "submitted_state_values", ["SUBMITTED"]))

    manual_prefixes = _get(rules, "manual_user_prefixes", ["INC"])

    by_pk: Dict[str, Event] = {e.pk: e for e in events_sorted}
    base_id = events_sorted[0].base_id

    # Terminal time: earliest ACCEPTED or REJECTED
    terminal_events = [e for e in events_sorted if _upper(e.system_status) in terminal_status_values]
    first_terminal_time: Optional[datetime] = min((e.created_at for e in terminal_events), default=None)
    terminal_statuses_seen = sorted({e.system_status for e in terminal_events if e.system_status})

    # Manual intervention flag for family
    family_manual = any(starts_with_any(e.create_by, manual_prefixes) or starts_with_any(e.update_by, manual_prefixes) for e in events_sorted)
    manual_flag = "Y" if family_manual else "N"

    # LOCKED presence
    has_locked = any(_upper(e.system_status) in locked_status_values for e in events_sorted)

    # Timeline scan for inflight logic
    inflight_pk: str = ""
    inflight_state: str = ""

    assessed: List[AssessedEvent] = []
    codes_for_headline: List[Tuple[str, str]] = []  # (severity, code)

    for e in events_sorted:
        codes: List[str] = []
        notes: List[str] = []
        related_pk = ""

        eff_freq = effective_clm0503(e)
        action = action_type_from_clm0503(eff_freq) or status_implies_action(e.system_status)
        implied_action = status_implies_action(e.system_status)
        action_for_rules = action if action else implied_action

        # Manual flag (per event)
        event_manual = starts_with_any(e.create_by, manual_prefixes) or starts_with_any(e.update_by, manual_prefixes)
        if event_manual:
            codes.append("MANUAL_TOUCH")
            notes.append("create_by/update_by indicates manual work")

        # Parent link checks for CORRECTION / DELETE
        action_requires_parent = action_for_rules in ("CORRECTION", "DELETE")
        if action_requires_parent and not e.prev_pk:
            codes.append("MISSING_PARENT_FOR_ACTION")
            notes.append(f"{action_for_rules} indicated but prev_pk blank")

        if e.prev_pk and e.prev_pk not in by_pk:
            codes.append("PARENT_PK_NOT_FOUND")
            notes.append("prev_pk not present in this base group")

        # REF*F8 expectations for 7/8
        if eff_freq in ("7", "8") and not e.ref_f8:
            codes.append("MISSING_REF_F8")
            notes.append("CLM05-3 7/8 but REF*F8 blank")

        # LOCKED understanding logic
        if _upper(e.system_status) in locked_status_values:
            prior_events = [p for p in events_sorted if p.created_at < e.created_at]
            if not prior_events:
                codes.append("LOCKED_WITH_NO_PRIOR")
                notes.append("LOCKED but no earlier event exists in family")

            if first_terminal_time is None or e.created_at < first_terminal_time:
                codes.append("LOCKED_BEFORE_TERMINAL")
                if inflight_pk:
                    codes.append("LOCKED_WAITING_ON_INFLIGHT")
                    related_pk = inflight_pk
                    notes.append(f"LOCKED while inflight exists (waiting on {inflight_pk})")
                else:
                    notes.append("LOCKED before any ACCEPTED/REJECTED observed")
            else:
                codes.append("LOCKED_AFTER_TERMINAL")
                notes.append("LOCKED occurred after terminal status (review)")

        # Inflight tracking update (after we assess current event)
        if _upper(e.system_state) in submitted_state_values and _upper(e.system_status) not in terminal_status_values:
            inflight_pk = e.pk
            inflight_state = e.system_state
        if _upper(e.system_status) in terminal_status_values:
            inflight_pk = ""
            inflight_state = ""

        # Determine severity / confidence
        severity = "OK"
        confidence = "MED"

        error_codes = {"MISSING_PARENT_FOR_ACTION", "PARENT_PK_NOT_FOUND"}
        warn_codes = {"MISSING_REF_F8", "LOCKED_WITH_NO_PRIOR", "LOCKED_BEFORE_TERMINAL", "LOCKED_AFTER_TERMINAL"}

        if any(c in error_codes for c in codes):
            severity = "ERROR"
        elif any(c in warn_codes for c in codes):
            severity = "WARN"

        if "LOCKED_WAITING_ON_INFLIGHT" in codes:
            confidence = "HIGH"
        if "PARENT_PK_NOT_FOUND" in codes or "MISSING_PARENT_FOR_ACTION" in codes:
            confidence = "LOW"
        if not codes:
            confidence = "HIGH"

        codes_str = ";".join(sorted(set(codes))) if codes else ""
        note_str = "; ".join(notes[:2]) if notes else ""

        assessed.append(
            AssessedEvent(
                event=e,
                assessment_severity=severity,
                understanding_confidence=confidence,
                assessment_codes=codes_str,
                assessment_note=note_str,
                related_pk=related_pk,
            )
        )

        if severity != "OK" and codes:
            codes_for_headline.append((severity, sorted(set(codes))[0]))

    headline_severity = "OK"
    headline_code = "OK"
    if codes_for_headline:
        if any(sev == "ERROR" for sev, _ in codes_for_headline):
            headline_severity = "ERROR"
            headline_code = next(code for sev, code in codes_for_headline if sev == "ERROR")
        else:
            headline_severity = "WARN"
            headline_code = next(code for sev, code in codes_for_headline if sev == "WARN")

    created_min = min(e.created_at for e in events_sorted)
    created_max = max(e.created_at for e in events_sorted)

    base_summary = BaseSummary(
        base_id=base_id,
        event_count=len(events_sorted),
        created_min_utc=created_min.isoformat(),
        created_max_utc=created_max.isoformat(),
        manual_flag=manual_flag,
        first_terminal_utc=first_terminal_time.isoformat() if first_terminal_time else "",
        terminal_statuses_seen=";".join(terminal_statuses_seen),
        has_locked="Y" if has_locked else "N",
        headline_severity=headline_severity,
        headline_code=headline_code,
    )

    return assessed, base_summary


def analyze(events: List[Event], cfg: Dict[str, Any]) -> Tuple[List[AssessedEvent], List[BaseSummary]]:
    """Group by base_id, assess each family, return flat assessed events and base summaries."""
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        grouped[e.base_id].append(e)

    all_assessed: List[AssessedEvent] = []
    all_bases: List[BaseSummary] = []

    for _, group_events in grouped.items():
        group_sorted = sorted(group_events, key=lambda e: (e.created_at, e.pk))
        assessed, base_summary = assess_family(group_sorted, cfg)
        all_assessed.extend(assessed)
        all_bases.append(base_summary)

    all_assessed.sort(key=lambda ae: (ae.event.created_at, ae.event.base_id, ae.event.pk))
    all_bases.sort(key=lambda b: (b.created_min_utc, b.base_id))
    return all_assessed, all_bases


# -----------------------------
# CSV outputs
# -----------------------------
def write_events_csv(assessed: List[AssessedEvent], out_path: Path) -> None:
    """Write per-event CSV."""
    fieldnames = [
        "base_id",
        "pk",
        "prev_pk",
        "created_at_utc",
        "clm01_full",
        "system_state",
        "system_status",
        "effective_clm0503",
        "action_type",
        "ref_f8",
        "cms_icn",
        "cms_out_icn",
        "create_by",
        "update_by",
        "assessment_severity",
        "understanding_confidence",
        "assessment_codes",
        "assessment_note",
        "related_pk",
        "rownum",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for ae in assessed:
            e = ae.event
            eff = effective_clm0503(e)
            act = action_type_from_clm0503(eff) or status_implies_action(e.system_status)
            w.writerow(
                {
                    "base_id": e.base_id,
                    "pk": e.pk,
                    "prev_pk": e.prev_pk,
                    "created_at_utc": e.created_at.isoformat(),
                    "clm01_full": e.clm01_full,
                    "system_state": e.system_state,
                    "system_status": e.system_status,
                    "effective_clm0503": eff,
                    "action_type": act,
                    "ref_f8": e.ref_f8,
                    "cms_icn": e.cms_icn,
                    "cms_out_icn": e.cms_out_icn,
                    "create_by": e.create_by,
                    "update_by": e.update_by,
                    "assessment_severity": ae.assessment_severity,
                    "understanding_confidence": ae.understanding_confidence,
                    "assessment_codes": ae.assessment_codes,
                    "assessment_note": ae.assessment_note,
                    "related_pk": ae.related_pk,
                    "rownum": e.rownum,
                }
            )


def write_bases_csv(bases: List[BaseSummary], out_path: Path) -> None:
    """Write per-base summary CSV."""
    fieldnames = [
        "base_id",
        "event_count",
        "created_min_utc",
        "created_max_utc",
        "manual_flag",
        "first_terminal_utc",
        "terminal_statuses_seen",
        "has_locked",
        "headline_severity",
        "headline_code",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for b in bases:
            w.writerow(
                {
                    "base_id": b.base_id,
                    "event_count": b.event_count,
                    "created_min_utc": b.created_min_utc,
                    "created_max_utc": b.created_max_utc,
                    "manual_flag": b.manual_flag,
                    "first_terminal_utc": b.first_terminal_utc,
                    "terminal_statuses_seen": b.terminal_statuses_seen,
                    "has_locked": b.has_locked,
                    "headline_severity": b.headline_severity,
                    "headline_code": b.headline_code,
                }
            )


# -----------------------------
# Console helper
# -----------------------------
def print_base_console(assessed: List[AssessedEvent], base_id: str) -> None:
    """Print a compact timeline for one base_id."""
    rows = [ae for ae in assessed if ae.event.base_id == base_id]
    if not rows:
        print(f"No base_id found: {base_id}")
        return

    rows.sort(key=lambda ae: (ae.event.created_at, ae.event.pk))
    print(f"\\nBASE {base_id} | events={len(rows)}")
    print("-" * 120)
    print("created_at_utc           | pk            | prev_pk       | clm01_full             | state        | status       | sev  | conf | codes")
    print("-" * 120)
    for ae in rows:
        e = ae.event
        created = e.created_at.isoformat()[:19]
        pk = (e.pk or "")[:12]
        prev = (e.prev_pk or "")[:12]
        clm01 = (e.clm01_full or "")[:20]
        state = (e.system_state or "")[:12]
        status = (e.system_status or "")[:12]
        codes = (ae.assessment_codes or "")[:40]
        print(f"{created:<21} | {pk:<12} | {prev:<12} | {clm01:<20} | {state:<12} | {status:<12} | {ae.assessment_severity:<4} | {ae.understanding_confidence:<4} | {codes}")


# -----------------------------
# CLI
# -----------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog=APP_NAME)
    p.add_argument("--version", action="store_true", help="Print app version and exit.")
    p.add_argument("--config", help="Path to config JSON.")
    p.add_argument("--input", help="Path to input delimited file.")
    p.add_argument("--out", help="Path to EVENTS output CSV.")
    p.add_argument("--out-bases", default="", help="Optional: path to BASES summary CSV. Default: <out>_bases.csv")
    p.add_argument("--debug-read", action="store_true", help="Print detailed input/header/mapping diagnostics.")
    p.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARN, ERROR")
    p.add_argument("--print-base", default="", help="Optional: print console timeline for this base_id.")
    return p.parse_args(argv)


def configure_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(level=lvl, format="%(levelname)s %(message)s")


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.version:
        print(f"{APP_NAME} v{APP_VERSION}")
        return 0

    configure_logging(args.log_level)

    if not args.config or not args.input or not args.out:
        raise ValueError("Missing required args. Use: --config <file> --input <file> --out <events.csv>")

    print(f"{APP_NAME} v{APP_VERSION}")

    cfg_path = Path(args.config)
    in_path = Path(args.input)
    out_events = Path(args.out)

    if not cfg_path.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    events = read_events(in_path, cfg, debug_read=args.debug_read)
    if not events:
        LOG.warning("No events read. This usually means CLM01 is blank for all rows, or delimiter/header mapping mismatch.")

    assessed, bases = analyze(events, cfg)

    write_events_csv(assessed, out_events)

    out_bases = Path(args.out_bases) if args.out_bases else out_events.with_name(out_events.stem + "_bases.csv")
    write_bases_csv(bases, out_bases)

    print(f"Wrote events CSV: {out_events}")
    print(f"Wrote bases  CSV: {out_bases}")
    print(f"Bases: {len(bases)} | Events: {len(assessed)}")

    if args.print_base:
        print_base_console(assessed, args.print_base)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
