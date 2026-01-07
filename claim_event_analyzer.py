#!/usr/bin/env python3
"""
claim_event_digester.py

Version: 1.0.0

Purpose
-------
Reads row-based “claim event” data (CSV/TSV/pipe/etc), groups events by a configurable
“base” portion of a claim identifier (business-wise: derived from EDI 837 CLM01),
and produces rule-based diagnostics explaining likely issues (missing acceptance,
locked sequencing, missing REF*F8 for corrections/voids, broken chains, etc.).

EDI context (used by this tool)
-------------------------------
- CLM05-3 (Claim Frequency Type Code): 1=Original, 7=Replacement/Correction, 8=Void/Delete
- REF*F8: “Original Reference Number” often used to reference the prior claim when doing 7/8.

Install
-------
- Python 3.10+ recommended (3.12 OK)
- No third-party deps required.

Usage
-----
python claim_event_digester.py --config config.claims.json --input events.csv --out report.json
python claim_event_digester.py --config config.claims.json --input events.csv --out report.json --out-csv report.csv
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


APP_NAME = "claim_event_digester"
APP_VERSION = "1.0.0"


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
    related_rows: Tuple[int, ...] = ()  # if you later want row numbers


@dataclass
class BaseGroupReport:
    """Report for one base_id."""
    base_id: str
    created_min: datetime
    created_max: datetime
    events_sorted: List[Event]
    threads: List[List[str]]  # each thread is a list of PKs in order
    findings: List[Finding]


# -----------------------------
# Config + parsing helpers
# -----------------------------
def _must(d: Dict[str, Any], key: str) -> Any:
    """Fetch a required config key."""
    if key not in d or d[key] in (None, ""):
        raise ValueError(f"Config missing required key: {key}")
    return d[key]


def _get(d: Dict[str, Any], key: str, default: Any) -> Any:
    """Fetch an optional config key."""
    return d.get(key, default)


def parse_datetime(value: str, fmt: str) -> datetime:
    """
    Parse a datetime string using either:
      - explicit strptime format (recommended), or
      - if fmt == "ISO", try datetime.fromisoformat
    Returns an aware datetime in UTC.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("created_at is blank")

    if fmt.upper() == "ISO":
        dt = datetime.fromisoformat(value)
    else:
        dt = datetime.strptime(value, fmt)

    # If naive, assume it's local time and convert to UTC by treating it as “local” without DST rules.
    # If you want real TZ rules later, we can add zoneinfo-based conversion.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def read_events(
    input_path: Path,
    cfg: Dict[str, Any],
) -> List[Event]:
    """Read input rows and normalize into Event objects."""
    io_cfg = _must(cfg, "io")
    fields = _must(cfg, "fields")
    grouping = _must(cfg, "grouping")

    delimiter = _get(io_cfg, "delimiter", ",")
    encoding = _get(io_cfg, "encoding", "utf-8-sig")

    dt_field = _must(fields, "created_at")
    dt_fmt = _get(io_cfg, "datetime_format", "ISO")

    clm01_field = _must(fields, "clm01_full")
    base_len = int(_get(grouping, "base_len", 10))
    suffix_len = int(_get(grouping, "suffix_len", 2))

    pk_field = _must(fields, "pk")
    prev_pk_field = _get(fields, "prev_pk", "")

    ref_f8_field = _get(fields, "ref_f8", "")

    system_state_field = _get(fields, "system_state", "")
    system_status_field = _get(fields, "system_status", "")

    clm0503_field = _get(fields, "clm0503", "")
    system_clm0503_field = _get(fields, "system_clm0503", "")

    cms_icn_field = _get(fields, "cms_icn", "")
    cms_out_icn_field = _get(fields, "cms_out_icn", "")

    events: List[Event] = []

    with input_path.open("r", encoding=encoding, newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for row in reader:
            clm01_full = (row.get(clm01_field, "") or "").strip()
            if not clm01_full:
                # skip empty rows or rows missing CLM01
                continue

            base_id = clm01_full[:base_len]
            clm_suffix = clm01_full[base_len:base_len + suffix_len] if len(clm01_full) >= base_len else ""

            pk = (row.get(pk_field, "") or "").strip()
            if not pk:
                raise ValueError(f"Row missing PK field '{pk_field}' for base_id={base_id}")

            prev_pk = (row.get(prev_pk_field, "") or "").strip() if prev_pk_field else ""

            ref_f8 = (row.get(ref_f8_field, "") or "").strip() if ref_f8_field else ""

            system_state = (row.get(system_state_field, "") or "").strip() if system_state_field else ""
            system_status = (row.get(system_status_field, "") or "").strip() if system_status_field else ""

            clm0503 = (row.get(clm0503_field, "") or "").strip() if clm0503_field else ""
            system_clm0503 = (row.get(system_clm0503_field, "") or "").strip() if system_clm0503_field else ""

            cms_icn = (row.get(cms_icn_field, "") or "").strip() if cms_icn_field else ""
            cms_out_icn = (row.get(cms_out_icn_field, "") or "").strip() if cms_out_icn_field else ""

            created_at_raw = (row.get(dt_field, "") or "").strip()
            created_at = parse_datetime(created_at_raw, dt_fmt)

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
    seen = set()
    roots_ordered: List[str] = []
    for e in events_sorted:
        if e.pk in roots and e.pk not in seen:
            roots_ordered.append(e.pk)
            seen.add(e.pk)

    # DFS to enumerate threads; split when a node has multiple children
    threads: List[List[str]] = []

    def dfs(path: List[str], current_pk: str) -> None:
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
        for k in sorted(kids, key=lambda pk: by_pk[pk].created_at):
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
# Rules (v1 set)
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
    Common pattern:
      - a later action arrives while prior work is not accepted yet -> LOCKED.
    Detect LOCKED events that occur before first accepted event timestamp.
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
    For CLM05-3 = 7 or 8, expect REF*F8 (original reference number) to be populated.
    We check both raw and “system” frequency code fields if present.
    """
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
# Reporting
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

        reports.append(
            BaseGroupReport(
                base_id=base_id,
                created_min=created_min,
                created_max=created_max,
                events_sorted=group_sorted,
                threads=threads,
                findings=sorted(findings, key=lambda f: (f.severity, f.code, f.message)),
            )
        )

    # stable ordering for output
    reports.sort(key=lambda r: (r.created_min, r.base_id))
    return reports


def to_jsonable(reports: List[BaseGroupReport]) -> Dict[str, Any]:
    """Convert reports to a JSON-serializable structure."""
    out: Dict[str, Any] = {
        "app": {"name": APP_NAME, "version": APP_VERSION},
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
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
                "findings": [
                    dataclasses.asdict(f) for f in r.findings
                ],
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
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    args = parse_args(argv)

    print(f"{APP_NAME} v{APP_VERSION}")

    cfg_path = Path(args.config)
    in_path = Path(args.input)
    out_path = Path(args.out)

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    events = read_events(in_path, cfg)
    reports = digest(events, cfg)

    out_json = to_jsonable(reports)
    out_path.write_text(json.dumps(out_json, indent=2), encoding="utf-8")

    if args.out_csv:
        write_findings_csv(reports, Path(args.out_csv))

    print(f"Wrote report: {out_path}")
    if args.out_csv:
        print(f"Wrote findings CSV: {args.out_csv}")

    # tiny console summary
    total_bases = len(reports)
    total_findings = sum(len(r.findings) for r in reports)
    warn_err = sum(1 for r in reports for f in r.findings if f.severity in ("WARN", "ERROR"))
    print(f"Bases: {total_bases} | Findings: {total_findings} | WARN/ERROR: {warn_err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
