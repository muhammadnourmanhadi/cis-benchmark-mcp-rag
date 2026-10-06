#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ingest_cis.py — Ground-Truth Driven CIS Benchmark PDF Parser + Embedder
=======================================================================
Production-ready parser that converts CIS Benchmark PDFs into structured
JSON documents using a line-by-line State Machine approach, validates the
result against the official list of recommendations found in the PDF itself
(bookmarks + Table of Contents), recovers any recommendation the state
machine missed, then generates dense vector embeddings for each rule using
sentence-transformers.

Architecture:
    PDF  →  pdfplumber (extract text per page, dedupe bold chars)
         →  Ground truth: PDF bookmarks (pypdf) + Table of Contents
         →  State Machine (detect rule headers, accumulate content)
         →  Best-candidate selection + false-positive filtering
         →  Recovery pass for recommendations still missing
         →  Coverage report (expected vs parsed, per benchmark)
         →  Post-Processing (regex extraction of sections & metadata)
         →  Passage Embedding (sentence-transformers/all-MiniLM-L6-v2): every rule
            is split into passages that fit the 256-token window, so the whole
            rule is embedded instead of only its first 256 tokens
         →  NDJSON output (one document per CIS rule + passages[] + text_embedding)

Key Architecture Benefit:
    Each parsed CIS rule corresponds directly to 1 complete JSON document. This preserves context integrity and prevents critical information from being split mid-sentence.
    Every recommendation listed in the PDF's bookmarks / Table of Contents is
    checked against the output, so no control is silently dropped.

Supported Header Formats:
    WINDOWS: "1.2.1 (L1) Ensure 'xyz' is set to 'abc' (Automated)"
             (also (L2), (NG) and (BL) profile tags)
    RHEL:    "1.1.1.7 Ensure udf kernel module is not available (Automated)"
             (any title wording — no action-verb whitelist)

Output:
    1_parser_and_ingest/output.ndjson         — One JSON document per line for Logstash
    1_parser_and_ingest/coverage_report.json  — Expected vs parsed rules per benchmark

Dependencies:
    pip install torch --index-url https://download.pytorch.org/whl/cpu   (CPU-only, smaller)
    pip install -r 1_parser_and_ingest/requirements_ingest.txt
    (--no-embed only needs: pip install pdfplumber pypdf)

Usage:
    python 1_parser_and_ingest/ingest_cis.py              # parse + embed all PDFs
    python 1_parser_and_ingest/ingest_cis.py --strict     # exit 1 if any rule is missing
    python 1_parser_and_ingest/ingest_cis.py --no-embed   # quick coverage check, no embeddings
    python 1_parser_and_ingest/ingest_cis.py --only rhel_9
    python 1_parser_and_ingest/ingest_cis.py --only windows_server_2025
        # -> output.windows_server_2025.ndjson + coverage_report.windows_server_2025.json
"""

import re
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from collections import Counter, OrderedDict

try:
    import pdfplumber
except ImportError:
    print("=" * 60)
    print("  ERROR: pdfplumber is not installed.")
    print("  Run: pip install pdfplumber")
    print("=" * 60)
    sys.exit(1)

try:
    from pypdf import PdfReader
except ImportError:
    # Optional: bookmarks are an extra ground-truth source. The Table of
    # Contents is still used when pypdf is not available.
    PdfReader = None


# ======================================================================
# CONFIGURATION
# ======================================================================

SCRIPT_DIR  = Path(__file__).resolve().parent
PDF_DIR     = SCRIPT_DIR / "cis_benchmarks"

# A default run processes every entry whose PDF exists and writes them all to
# one output.ndjson. --only <source> (e.g. --only windows_server_2025)
# processes just those entries and writes output.<source>.ndjson and
# coverage_report.<source>.json instead.
PDF_FILES = [
    # ── Windows Server ──────────────────────────────────────────────────
    {
        "filename":  "CIS_Microsoft_Windows_Server_2025_Benchmark_v2.0.0.pdf",
        "source":    "windows_server_2025",
        "os_family": "windows",
        "os_name":   "Windows Server 2025",
        "benchmark": "CIS Microsoft Windows Server 2025 Benchmark",
        "version":   "v2.0.0",
    },
    {
        "filename":  "CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.pdf",
        "source":    "windows_server_2022",
        "os_family": "windows",
        "os_name":   "Windows Server 2022",
        "benchmark": "CIS Microsoft Windows Server 2022 Benchmark",
        "version":   "v4.0.0",
    },
    {
        "filename":  "CIS_Microsoft_Windows_Server_2019_Benchmark_v4.0.0.pdf",
        "source":    "windows_server_2019",
        "os_family": "windows",
        "os_name":   "Windows Server 2019",
        "benchmark": "CIS Microsoft Windows Server 2019 Benchmark",
        "version":   "v4.0.0",
    },
    {
        "filename":  "CIS_Microsoft_Windows_Server_2016_Benchmark_v3.0.0.pdf",
        "source":    "windows_server_2016",
        "os_family": "windows",
        "os_name":   "Windows Server 2016",
        "benchmark": "CIS Microsoft Windows Server 2016 Benchmark",
        "version":   "v3.0.0",
    },

    # ── Red Hat Enterprise Linux ─────────────────────────────────────────
    {
        "filename":  "CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0.pdf",
        "source":    "rhel_9",
        "os_family": "linux",
        "os_name":   "Red Hat Enterprise Linux 9",
        "benchmark": "CIS Red Hat Enterprise Linux 9 Benchmark",
        "version":   "v2.0.0",
    },
    {
        "filename":  "CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0.pdf",
        "source":    "rhel_8",
        "os_family": "linux",
        "os_name":   "Red Hat Enterprise Linux 8",
        "benchmark": "CIS Red Hat Enterprise Linux 8 Benchmark",
        "version":   "v4.0.0",
    },
    {
        "filename":  "CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v4.0.0.pdf",
        "source":    "rhel_7",
        "os_family": "linux",
        "os_name":   "Red Hat Enterprise Linux 7",
        "benchmark": "CIS Red Hat Enterprise Linux 7 Benchmark",
        "version":   "v4.0.0",
    },
]

# --- Output ---
OUTPUT_NDJSON   = SCRIPT_DIR / "output.ndjson"
COVERAGE_REPORT = SCRIPT_DIR / "coverage_report.json"

# --- Embedding Model ---
EMBEDDING_MODEL  = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIMS   = 384
BATCH_SIZE_EMBED = 64     # Reduce if RAM runs out
PASSAGE_OVERLAP_TOKENS = 32   # Context repeated between consecutive passages


# ======================================================================
# REGEX PATTERNS
# ======================================================================

# Rule ID at the start of a line, e.g. "1.1.1.7 " — also accepts an ID glued
# to the title ("1.1.1.7Ensure"), which pdfplumber produces for some fonts.
RULE_ID_PREFIX_RE = re.compile(
    r"^(\d+(?:\.\d+)+)(?:\s+|(?=[A-Z(\"'‘“]))"
)

# ---------------------------------------------------------------------------
# Generic rule header (Windows and Linux):
#   "1.2.1 (L1) Ensure 'xyz' is set to 'abc' (Automated)"
#   "18.9.5.1 (NG) Ensure 'Turn On Virtualization Based Security' ... (Automated)"
#   "1.1.1.7 Ensure udf kernel module is not available (Automated)"
#   Groups: (1) rule_id, (2) cis_level (optional), (3) rule_title, (4) automation_status
# The title is NOT restricted to a list of action verbs, so any wording works.
# ---------------------------------------------------------------------------
RULE_HEADER_RE = re.compile(
    r"^(\d+(?:\.\d+)+)(?:\s+|(?=[A-Z(\"'‘“]))"   # Group 1: rule_id
    r"(?:\(((?i:L1|L2|NG|BL))\)\s*)?"                      # Group 2: profile tag
    r"(.+?)"                                               # Group 3: rule_title
    r"\s*\((Automated|Manual)\)"                           # Group 4: automation_status
    r"\s*$"
)

# Table of Contents entry ending: dot leaders followed by a page number
TOC_LINE_RE = re.compile(r"(?:\.{3,}|…+|(?:\.\s){3,})\s*\.?\s*(\d+)\s*$")

# Labels that open a section inside a recommendation body
SECTION_LABEL_RE = re.compile(
    r"^(Profile Applicability|Description|Rationale|Impact|Audit|Remediation|"
    r"Default Value|References|CIS Controls|Additional Information|Note)\s*:"
)

# Page footers / headers that should not end up in rule content
FOOTER_RE = re.compile(r"^(Page\s+\d+(\s+of\s+\d+)?|Internal Only - General)$", re.I)

# Start of the appendix (Summary Table, Change History, ...). Everything after
# it repeats rule headers without bodies, so the state machine stops there.
APPENDIX_RE = re.compile(r"^Appendix\s*:", re.I)

# Section labels used to judge how complete a parsed rule body is
QUALITY_LABELS = ("Profile Applicability:", "Description:", "Audit:", "Remediation:")

# Maximum lines a rule header can be wrapped over in the PDF
MAX_HEADER_LINES = 4

# Maximum chars to accumulate for multi-line header completion
HEADER_BUFFER_LIMIT = 600

# Maximum lines a recovered rule body may span
MAX_RECOVERY_LINES = 1500


# ======================================================================
# PDF LOADING
# ======================================================================

def load_pages(pdf_path):
    """
    Extract text lines for every page once.

    Returns:
        List of {"num": int, "lines": [str], "is_toc": bool}
    """
    pages = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        total_pages = len(pdf.pages)
        print("  [LOAD] Total pages: {}".format(total_pages))

        for page_num, page in enumerate(pdf.pages, start=1):
            if page_num % 100 == 0 or page_num == total_pages:
                print("    Page {}/{}...".format(page_num, total_pages))
            try:
                # Bold text is sometimes drawn twice ("EEnnssuurree")
                text = page.dedupe_chars().extract_text() or ""
            except Exception:
                text = page.extract_text() or ""

            lines = []
            for line in text.split("\n"):
                line = line.strip()
                if line and not FOOTER_RE.match(line):
                    lines.append(line)

            pages.append({
                "num": page_num,
                "lines": lines,
                "toc_lines": sum(1 for l in lines if TOC_LINE_RE.search(l)),
                "has_labels": any(SECTION_LABEL_RE.match(l) for l in lines),
            })

    # Table of Contents page: several lines ending in dot leaders + page number,
    # or a short trailing ToC page right after one. Pages with recommendation
    # section labels (Audit:, Remediation:, ...) are never ToC pages.
    prev_toc = False
    for page in pages:
        is_toc = not page["has_labels"] and (
            page["toc_lines"] >= 3 or (page["toc_lines"] >= 1 and prev_toc))
        page["is_toc"] = prev_toc = is_toc
    return pages


def _is_appendix_start(line):
    """An appendix heading in the body (not a ToC entry pointing to it)."""
    return bool(APPENDIX_RE.match(line)) and not TOC_LINE_RE.search(line)


def body_lines(pages):
    """Flatten non-ToC pages into (page_num, line) up to the appendix."""
    body = []
    seen_rule_id = False
    for page in pages:
        if page["is_toc"]:
            continue
        for line in page["lines"]:
            if seen_rule_id and _is_appendix_start(line):
                return body
            seen_rule_id = seen_rule_id or bool(RULE_ID_PREFIX_RE.match(line))
            body.append((page["num"], line))
    return body


# ======================================================================
# GROUND TRUTH — official list of recommendations in the PDF
# ======================================================================

def _match_header(text, expected_ids=None):
    """
    Match a complete rule header.

    Returns:
        (rule_id, cis_level, rule_title, automation_status) or None
    """
    m = RULE_HEADER_RE.match(text)
    if not m:
        return None
    rule_id = m.group(1)
    title = m.group(3).strip()
    if expected_ids is not None and rule_id not in expected_ids:
        return None
    # Title must contain words, not just numbers / table cells
    if not re.search(r"[A-Za-z]{2,}", title):
        return None
    return (rule_id, (m.group(2) or "").upper(), title, m.group(4))


def _expected_entry(header, page, origin):
    rule_id, cis_level, rule_title, automation_status = header
    return {
        "rule_id": rule_id,
        "cis_level": cis_level,
        "rule_title": rule_title,
        "automation_status": automation_status,
        "page": page,
        "origin": origin,
    }


def expected_from_outline(pdf_path):
    """Read recommendations from the PDF bookmarks (outline)."""
    if PdfReader is None:
        return []
    try:
        reader = PdfReader(str(pdf_path))
        outline = reader.outline
    except Exception as e:
        print("  [TRUTH] Could not read PDF bookmarks: {}".format(e))
        return []

    entries = []

    def walk(items):
        for item in items:
            if isinstance(item, list):
                walk(item)
                continue
            title = " ".join(str(getattr(item, "title", "")).split())
            header = _match_header(title)
            if not header:
                continue
            try:
                page = reader.get_destination_page_number(item) + 1
            except Exception:
                page = None
            entries.append(_expected_entry(header, page, "outline"))

    walk(outline)
    return entries


def expected_from_toc(pages):
    """Read recommendations from the Table of Contents pages."""
    entries = []
    buf = ""
    for page in pages:
        if not page["is_toc"]:
            continue
        for line in page["lines"]:
            if RULE_ID_PREFIX_RE.match(line):
                buf = line                 # a new ToC entry starts
            elif buf:
                buf += " " + line          # wrapped ToC entry
            else:
                continue

            m_end = TOC_LINE_RE.search(buf)
            if m_end:
                entry_text = buf[:m_end.start()].rstrip(" .")
                header = _match_header(entry_text)
                if header:
                    entries.append(_expected_entry(header, int(m_end.group(1)), "toc"))
                buf = ""
            elif len(buf) > HEADER_BUFFER_LIMIT:
                buf = ""
    return entries


def build_expected(pdf_path, pages):
    """Merge bookmarks and ToC into one ordered dict: rule_id -> entry."""
    outline = expected_from_outline(pdf_path)
    toc = expected_from_toc(pages)
    print("  [TRUTH] Recommendations in bookmarks: {} | in Table of Contents: {}".format(
        len(outline), len(toc)))

    expected = OrderedDict()
    for entry in outline + toc:
        if entry["rule_id"] not in expected:
            expected[entry["rule_id"]] = entry
    return expected


# ======================================================================
# STATE MACHINE PARSER
# ======================================================================

def _title_key(text):
    """Normalized title prefix used to compare a body line with the official title."""
    text = re.sub(r"^\((?i:L1|L2|NG|BL)\)\s*", "", text.strip())
    return re.sub(r"[^a-z0-9]", "", text.lower())[:24]


def _opens_rule(line, expected, exclude_id=None):
    """
    True if the line starts the header of an official recommendation: its ID
    is official AND the text after it matches the start of the official title.
    This keeps body lines that merely start with an ID (e.g. a CIS Controls
    row "5.2 Use Unique Passwords" in a benchmark that also has rule 5.2)
    from being taken as a new rule.
    """
    m = RULE_ID_PREFIX_RE.match(line)
    if not m or m.group(1) == exclude_id or m.group(1) not in expected:
        return False
    line_key = _title_key(line[m.end():])
    title_key = _title_key(expected[m.group(1)]["rule_title"])
    n = min(len(line_key), len(title_key))
    return n >= min(6, len(title_key)) and line_key[:n] == title_key[:n]


def _is_header_start(line, expected):
    """
    Check if a line looks like the START of a (possibly wrapped) rule header.
    With a ground-truth list, only real recommendation headers qualify, so
    section titles ("1.1.1 Configure Filesystem Kernel Modules") and CIS
    Controls table rows ("9.2 Ensure Only Approved Ports ...") are ignored.
    """
    if expected is not None:
        return _opens_rule(line, expected)
    if not RULE_ID_PREFIX_RE.match(line):
        return False
    return bool(re.match(r"^\d+(?:\.\d+)+\s*(?:\([A-Za-z0-9]{2}\)\s*)?[A-Z\"'\u2018\u201c]", line))


def parse_body(pages, meta, expected=None):
    """
    Parse recommendation bodies using a line-by-line state machine.

    The state machine has 3 states:
      1. SCANNING     — Looking for the start of a new rule header
      2. BUFFERING    — Accumulating a multi-line rule header (max 4 lines)
      3. ACCUMULATING — Appending content lines to the current rule

    Args:
        pages:        Output of load_pages()
        meta:         Dict with os metadata (source, os_family, os_name, etc.)
        expected:     Official rules {rule_id: entry}, or None for ungated parsing

    Returns:
        List of parsed rule dicts (may contain duplicates per rule_id)
    """
    rules = []
    current_rule = None
    header_buffer = []
    header_start_page = None
    expected_ids = set(expected) if expected is not None else None

    def add_content(line, page_num):
        if current_rule is not None:
            current_rule["content_for_vector"] += line + "\n"
            if page_num not in current_rule["metadata"]["source_pages"]:
                current_rule["metadata"]["source_pages"].append(page_num)

    def start_rule(header, page_num):
        nonlocal current_rule
        if current_rule is not None:
            rules.append(current_rule)
        rule_id, cis_level, rule_title, automation_status = header
        current_rule = _init_rule(rule_id, cis_level, rule_title,
                                  automation_status, page_num, meta)

    for page in pages:
        if page["is_toc"]:
            continue
        page_num = page["num"]

        for line in page["lines"]:
            # ── Appendix: stop, it only repeats headers without bodies ──
            if current_rule is not None and _is_appendix_start(line):
                for buffered in header_buffer:
                    add_content(buffered, header_start_page)
                if current_rule is not None:
                    rules.append(current_rule)
                return rules

            # ── STATE: Try COMPLETE header match ──
            header = _match_header(line, expected_ids)
            if header:
                for buffered in header_buffer:
                    add_content(buffered, header_start_page)
                header_buffer = []
                start_rule(header, page_num)
                continue

            # ── STATE: Check for PARTIAL header start (also restarts a buffer) ──
            if _is_header_start(line, expected):
                for buffered in header_buffer:
                    add_content(buffered, header_start_page)
                header_buffer = [line]
                header_start_page = page_num
                continue

            # ── STATE: BUFFERING — try to complete header ──
            if header_buffer:
                if SECTION_LABEL_RE.match(line) or len(header_buffer) >= MAX_HEADER_LINES:
                    # Not a header after all — give the lines back as content
                    for buffered in header_buffer:
                        add_content(buffered, header_start_page)
                    header_buffer = []
                else:
                    header_buffer.append(line)
                    completed = _match_header(" ".join(header_buffer), expected_ids)
                    if completed:
                        start_rule(completed, header_start_page)
                        header_buffer = []
                    continue

            # ── STATE: ACCUMULATING regular content ──
            add_content(line, page_num)

    # ── End of PDF: flush remaining state ──
    for buffered in header_buffer:
        add_content(buffered, header_start_page)
    if current_rule is not None:
        rules.append(current_rule)
    return rules


def _init_rule(rule_id, cis_level, rule_title, automation_status, page_num, meta,
               parse_method="state_machine"):
    """Create a new rule dictionary."""
    header_line = "{} {} {} ({})".format(
        rule_id,
        "({}) ".format(cis_level) if cis_level else "",
        rule_title,
        automation_status
    ).replace("  ", " ")

    return {
        "rule_id": rule_id,
        "rule_title": rule_title,
        "content_for_vector": header_line + "\n",
        "sections": {
            "audit_text": "",
            "remediation_text": "",
        },
        "text_embedding": [],  # Populated by batch embedding step
        "metadata": {
            "cis_level": cis_level,  # "" for RHEL, filled by post-processing
            "automation_status": automation_status,
            "profile_applicability": [],
            "source_pages": [page_num],
            "source": meta["source"],
            "os_family": meta["os_family"],
            "os_name": meta["os_name"],
            "benchmark": meta["benchmark"],
            "version": meta["version"],
            "parse_method": parse_method,
        },
    }


def _quality(rule):
    """Rank duplicate candidates: complete bodies first, then longer text."""
    content = rule["content_for_vector"]
    return (sum(1 for label in QUALITY_LABELS if label in content), len(content))


def select_best(rules):
    """Keep the most complete candidate per rule_id."""
    best = OrderedDict()
    for rule in rules:
        rid = rule["rule_id"]
        if rid not in best or _quality(rule) > _quality(best[rid]):
            best[rid] = rule
    return best


# ======================================================================
# RECOVERY — rebuild recommendations the state machine missed
# ======================================================================

def recover_rule(rule_id, entry, body, starts, expected, meta):
    """
    Locate a missing recommendation by its ID in the body lines and take
    every line until the next official recommendation header.

    Args:
        body:   Output of body_lines()
        starts: {rule_id: [line indexes in body starting with that ID]}
    """
    best = None
    for i in starts.get(rule_id, []):
        page_num = body[i][0]
        rule = _init_rule(rule_id, entry["cis_level"], entry["rule_title"],
                          entry["automation_status"], page_num, meta,
                          parse_method="recovered")
        for j in range(i + 1, min(len(body), i + MAX_RECOVERY_LINES)):
            next_page, next_line = body[j]
            if _opens_rule(next_line, expected, exclude_id=rule_id):
                break
            rule["content_for_vector"] += next_line + "\n"
            if next_page not in rule["metadata"]["source_pages"]:
                rule["metadata"]["source_pages"].append(next_page)
        if best is None or _quality(rule) > _quality(best):
            best = rule

    if best is not None and _quality(best)[0] > 0:
        return best
    return None


def _trim_at_next_rule(rule, expected):
    """Cut rule content at the first line that opens another official rule."""
    lines = rule["content_for_vector"].split("\n")
    for i, line in enumerate(lines[1:], start=1):
        if _opens_rule(line, expected, exclude_id=rule["rule_id"]):
            rule["content_for_vector"] = "\n".join(lines[:i]) + "\n"
            return


# ======================================================================
# PER-PDF PIPELINE
# ======================================================================

def parse_pdf(pdf_path, meta):
    """
    Parse one CIS Benchmark PDF and verify it against its own ground truth.

    Returns:
        (rules, coverage) — list of rule dicts in document order, and a
        coverage dict for the report.
    """
    print("  [PARSE] Opening: {}".format(pdf_path.name))
    pages = load_pages(pdf_path)
    expected = build_expected(pdf_path, pages)
    expected_ids = set(expected)

    # Gated pass (only official IDs can open a header) avoids hijacked
    # headers; the ungated pass catches rules missing from the ToC/bookmarks.
    candidates = parse_body(pages, meta, expected) if expected else []
    candidates += parse_body(pages, meta, None)
    best = select_best(candidates)

    # ── Drop false positives: IDs that are not official recommendations
    #    and have no recommendation body. Unlisted IDs WITH a real body
    #    (Profile Applicability) are kept and reported as not_in_ground_truth.
    dropped = []
    trust_expected = bool(expected) and len(expected) >= 0.5 * len(best)
    if trust_expected:
        for rid in [r for r in best if r not in expected_ids]:
            if "Profile Applicability:" in best[rid]["content_for_vector"]:
                continue
            dropped.append({"rule_id": rid, "rule_title": best[rid]["rule_title"]})
            del best[rid]
    elif expected:
        print("  [WARN] Ground truth list looks incomplete ({} entries vs {} parsed) — "
              "keeping all parsed rules.".format(len(expected), len(best)))

    # ── Recover recommendations that are missing or have no body ──
    body = body_lines(pages)
    starts = {}
    for i, (_, line) in enumerate(body):
        m = RULE_ID_PREFIX_RE.match(line)
        if m:
            starts.setdefault(m.group(1), []).append(i)

    recovered = []
    title_only = []
    for rid, entry in expected.items():
        if rid in best and _quality(best[rid])[0] > 0:
            continue
        rule = recover_rule(rid, entry, body, starts, expected, meta)
        if rule is not None:
            best[rid] = rule
            recovered.append(rid)
        elif rid not in best:
            # Last resort: keep at least the official title so the control exists
            title_only.append(rid)
            best[rid] = _init_rule(rid, entry["cis_level"], entry["rule_title"],
                                   entry["automation_status"], entry["page"] or 0, meta,
                                   parse_method="title_only")

    # A missed header makes the previous rule swallow the next body — cut it off
    if trust_expected:
        for rule in best.values():
            _trim_at_next_rule(rule, expected)

    # Official titles are cleaner than text reconstructed from wrapped lines
    for rid, entry in expected.items():
        rule = best[rid]
        rule["rule_title"] = entry["rule_title"]
        if entry["cis_level"] and not rule["metadata"]["cis_level"]:
            rule["metadata"]["cis_level"] = entry["cis_level"]

    # ── Document order: official order first, then anything else ──
    ordered = [best[rid] for rid in expected if rid in best]
    ordered += [rule for rid, rule in best.items() if rid not in expected_ids]

    without_body = [r["rule_id"] for r in ordered if _quality(r)[0] == 0]
    coverage = {
        "source": meta["source"],
        "filename": pdf_path.name,
        "expected": len(expected),
        "parsed": len(ordered),
        "missing": [rid for rid in without_body if rid in expected_ids],
        "recovered": recovered,
        "title_only": title_only,
        "without_body": without_body,
        "dropped_false_positives": dropped,
        "not_in_ground_truth": [r["rule_id"] for r in ordered if r["rule_id"] not in expected_ids],
    }
    print_coverage(coverage)
    return ordered, coverage


def print_coverage(cov):
    print("  [COVERAGE] {}".format(cov["source"]))
    print("    Expected (bookmarks/ToC) : {:>5,d}".format(cov["expected"]))
    print("    Parsed                   : {:>5,d}".format(cov["parsed"]))
    print("    Recovered by fallback    : {:>5,d} {}".format(
        len(cov["recovered"]), _preview(cov["recovered"])))
    print("    Without body             : {:>5,d} {}".format(
        len(cov["without_body"]), _preview(cov["without_body"])))
    print("    Dropped false positives  : {:>5,d} {}".format(
        len(cov["dropped_false_positives"]),
        _preview([d["rule_id"] for d in cov["dropped_false_positives"]])))
    if cov["not_in_ground_truth"]:
        print("    Not in ground truth      : {:>5,d} {}".format(
            len(cov["not_in_ground_truth"]), _preview(cov["not_in_ground_truth"])))
    print("    MISSING (no body found)  : {:>5,d} {}".format(
        len(cov["missing"]), _preview(cov["missing"])))


def _preview(ids, limit=10):
    if not ids:
        return ""
    more = " ... (+{})".format(len(ids) - limit) if len(ids) > limit else ""
    return "[" + ", ".join(ids[:limit]) + more + "]"


# ======================================================================
# POST-PROCESSING — Extract sections & metadata from raw content
# ======================================================================

def post_process_rule(rule):
    """
    Run regex extraction on rule["content_for_vector"] to populate
    the sections and metadata fields.

    Extraction targets:
      - sections.audit_text
      - sections.remediation_text
      - metadata.profile_applicability
      - metadata.cis_level (backfill from Profile Applicability for RHEL)
    """
    content = rule["content_for_vector"]

    # ── 1. Audit Text ────────────────────────────────────────────────
    # Match between "Audit:" and "Remediation:" (case-insensitive start)
    audit_match = re.search(
        r"(?:^|\n)Audit:\s*\n(.*?)(?=\nRemediation:|\Z)",
        content,
        re.DOTALL,
    )
    if audit_match:
        rule["sections"]["audit_text"] = audit_match.group(1).strip()

    # ── 2. Remediation Text ──────────────────────────────────────────
    remediation_match = re.search(
        r"(?:^|\n)Remediation:\s*\n(.*?)(?=\nDefault Value:|\nImpact:|\nReferences:|\nCIS Controls:|\Z)",
        content,
        re.DOTALL,
    )
    if remediation_match:
        rule["sections"]["remediation_text"] = remediation_match.group(1).strip()

    # ── 3. Profile Applicability ─────────────────────────────────────
    profile_match = re.search(
        r"Profile Applicability:\s*\n(.*?)(?=\nDescription:|\Z)",
        content,
        re.DOTALL,
    )
    if profile_match:
        raw_block = profile_match.group(1)
        # Match bullet points at line start: Unicode bullets, plain dashes, or
        # unmapped glyphs that pdfplumber renders as "(cid:127)". Anchoring to
        # the line start keeps the "-" in "Level 1 - Server" from matching.
        bullets = re.findall(
            r"^[^\S\n]*(?:[•·‣\u25cf\u2022\uf0b7\?\-\*]|\(cid:\d+\))\s*(.+)",
            raw_block, re.MULTILINE,
        )
        if not bullets:
            # Fallback: match lines starting with "Level"
            bullets = re.findall(r"(Level\s+\d+\s*.+)", raw_block)
        rule["metadata"]["profile_applicability"] = [
            _to_snake_case(b) for b in bullets if b.strip()
        ]

        # ── Backfill cis_level from Profile Applicability (for RHEL) ──
        if not rule["metadata"]["cis_level"]:
            level_text = " ".join(bullets).lower()
            if "level 1" in level_text and "level 2" not in level_text:
                rule["metadata"]["cis_level"] = "L1"
            elif "level 2" in level_text and "level 1" not in level_text:
                rule["metadata"]["cis_level"] = "L2"
            elif "level 1" in level_text and "level 2" in level_text:
                # Rule appears in both L1 and L2 profiles — mark as L1
                # (L1 is a subset of L2, so L1 takes priority)
                rule["metadata"]["cis_level"] = "L1"

    return rule


def _to_snake_case(text):
    """
    Convert profile applicability text to lowercase snake_case.
    Example: "Level 1 - Domain Controller" -> "level_1_domain_controller"
    """
    result = re.sub(r"[^a-z0-9]+", "_", text.strip().lower())
    return result.strip("_")


# ======================================================================
# STATISTICS & QUALITY REPORT
# ======================================================================

def print_statistics(all_rules):
    """Print a detailed quality report of parsed rules."""
    if not all_rules:
        print("\n  No rules to report.")
        return

    total = len(all_rules)
    print("\n" + "=" * 60)
    print("  QUALITY REPORT")
    print("=" * 60)

    # ── Per-OS breakdown ──
    os_counter = Counter(r["metadata"]["source"] for r in all_rules)
    print("\n  Rules per OS:")
    for os_name, count in sorted(os_counter.items()):
        print("    {:<25s} {:>5,d} rules".format(os_name, count))
    print("    {:<25s} {:>5,d} rules".format("TOTAL", total))

    # ── CIS Level breakdown ──
    level_counter = Counter(r["metadata"]["cis_level"] for r in all_rules)
    print("\n  Rules per CIS Level:")
    for level, count in sorted(level_counter.items()):
        label = level if level else "(unknown)"
        print("    {:<10s} {:>5,d} rules ({:.1f}%)".format(label, count, count / total * 100))

    # ── Automation Status breakdown ──
    auto_counter = Counter(r["metadata"]["automation_status"] for r in all_rules)
    print("\n  Automation Status:")
    for status, count in sorted(auto_counter.items()):
        print("    {:<12s} {:>5,d} rules ({:.1f}%)".format(status, count, count / total * 100))

    # ── Section extraction quality ──
    has_audit = sum(1 for r in all_rules if r["sections"]["audit_text"])
    has_remed = sum(1 for r in all_rules if r["sections"]["remediation_text"])
    has_profile = sum(1 for r in all_rules if r["metadata"]["profile_applicability"])
    has_embed = sum(1 for r in all_rules if r["text_embedding"])

    print("\n  Section Extraction Coverage:")
    print("    audit_text              {:>5,d} / {:,d} ({:.1f}%)".format(
        has_audit, total, has_audit / total * 100))
    print("    remediation_text        {:>5,d} / {:,d} ({:.1f}%)".format(
        has_remed, total, has_remed / total * 100))
    print("    profile_applicability   {:>5,d} / {:,d} ({:.1f}%)".format(
        has_profile, total, has_profile / total * 100))
    print("    text_embedding          {:>5,d} / {:,d} ({:.1f}%)".format(
        has_embed, total, has_embed / total * 100))
    total_passages = sum(len(r.get("passages", [])) for r in all_rules)
    print("    passages (vectors)      {:>5,d} for {:,d} rules ({:.1f} per rule)".format(
        total_passages, total, total_passages / total))

    # ── Content length stats ──
    lengths = [len(r["content_for_vector"]) for r in all_rules]
    avg_len = sum(lengths) / len(lengths)
    min_len = min(lengths)
    max_len = max(lengths)

    print("\n  Content Length (chars):")
    print("    Average: {:,.0f}".format(avg_len))
    print("    Min:     {:,.0f}".format(min_len))
    print("    Max:     {:,.0f}".format(max_len))

    # ── Multi-page rules ──
    multi_page = sum(1 for r in all_rules if len(r["metadata"]["source_pages"]) > 1)
    print("\n  Multi-page rules: {:,d} / {:,d} ({:.1f}%)".format(
        multi_page, total, multi_page / total * 100))

    # ── Sample output ──
    print("\n  Sample Rule (first parsed):")
    sample = all_rules[0]
    print("    rule_id:    {}".format(sample["rule_id"]))
    print("    rule_title: {}".format(
        sample["rule_title"][:80] + "..." if len(sample["rule_title"]) > 80
        else sample["rule_title"]
    ))
    print("    cis_level:  {}".format(sample["metadata"]["cis_level"]))
    print("    status:     {}".format(sample["metadata"]["automation_status"]))
    print("    pages:      {}".format(sample["metadata"]["source_pages"]))
    print("    profiles:   {}".format(sample["metadata"]["profile_applicability"][:3]))
    embed_dims = len(sample["text_embedding"])
    print("    embedding:  [{} dims] first 5 values: {}".format(
        embed_dims, sample["text_embedding"][:5]
    ))
    audit_preview = sample["sections"]["audit_text"][:100]
    print("    audit:      {}...".format(
        audit_preview.encode("ascii", errors="replace").decode("ascii")
    ))


# ======================================================================
# MAIN
# ======================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="CIS Benchmark PDF parser + embedder")
    parser.add_argument("--strict", action="store_true",
                        help="Exit with code 1 if any official recommendation has no body")
    parser.add_argument("--no-embed", action="store_true",
                        help="Skip embedding generation (quick coverage check). "
                             "No NDJSON is written unless --output is given.")
    parser.add_argument("--only", nargs="+", metavar="SOURCE",
                        choices=[e["source"] for e in PDF_FILES],
                        help="Only process these sources, e.g. --only windows_server_2025. "
                             "Writes output.<source>.ndjson and coverage_report.<source>.json. "
                             "Choices: %(choices)s")
    parser.add_argument("--pdf-dir", type=Path, default=PDF_DIR,
                        help="Folder containing the CIS PDFs (default: %(default)s)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Output NDJSON file (default: {}; with --only: "
                             "output.<source>.ndjson)".format(OUTPUT_NDJSON))
    parser.add_argument("--coverage-report", type=Path, default=None,
                        help="Coverage report JSON (default: {}; with --only: "
                             "coverage_report.<source>.json)".format(COVERAGE_REPORT))
    args = parser.parse_args()

    # A partial run gets its own coverage report, so the full run's is kept
    if args.coverage_report is None:
        if args.only:
            args.coverage_report = SCRIPT_DIR / "coverage_report.{}.json".format("_".join(args.only))
        else:
            args.coverage_report = COVERAGE_REPORT

    # Never overwrite the full, embedded dataset with a partial run
    if args.output is None and not args.no_embed:
        if args.only:
            args.output = SCRIPT_DIR / "output.{}.ndjson".format("_".join(args.only))
        else:
            args.output = OUTPUT_NDJSON
    return args


def _token_count(tokenizer, text):
    return len(tokenizer.encode(text, add_special_tokens=False))


def _passage_header(rule):
    """'<rule_id> (<level>) <title> (<status>)' — same wording as the rule header."""
    meta = rule["metadata"]
    return " ".join(part for part in (
        rule["rule_id"],
        "({})".format(meta["cis_level"]) if meta.get("cis_level") else "",
        rule["rule_title"],
        "({})".format(meta["automation_status"]) if meta.get("automation_status") else "",
    ) if part)


def _split_long_line(line, tokenizer, budget):
    """
    Cut a line longer than the budget at word boundaries, keeping the
    original text. A single word longer than the budget is cut by tokens.
    """
    pieces = []
    words, words_len = [], 0
    for word in line.split(" "):
        n = _token_count(tokenizer, word)
        if n > budget:
            if words:
                pieces.append((" ".join(words), words_len))
                words, words_len = [], 0
            ids = tokenizer.encode(word, add_special_tokens=False)
            i = 0
            while i < len(ids):
                # A decoded wordpiece slice ("##abc") can re-tokenize to more
                # tokens than the slice, so shrink it until it fits the budget.
                step = budget
                while True:
                    piece = tokenizer.decode(ids[i:i + step])
                    n_piece = _token_count(tokenizer, piece)
                    if n_piece <= budget or step == 1:
                        break
                    step = max(1, step - (n_piece - budget))
                pieces.append((piece, n_piece))
                i += step
            continue
        if words and words_len + n > budget:
            pieces.append((" ".join(words), words_len))
            words, words_len = [], 0
        words.append(word)
        words_len += n
    if words:
        pieces.append((" ".join(words), words_len))
    return pieces


def split_passages(rule, tokenizer, max_tokens):
    """
    Split a rule's full text into passages that fit the embedding model's
    token window, so no part of the rule is truncated away.

    Every passage starts with the rule header (ID, level, title, status) so it
    keeps its context, is packed line by line (lines longer than the budget are
    cut at word boundaries), and repeats up to PASSAGE_OVERLAP_TOKENS from the
    end of the previous passage when that still fits the budget.
    """
    # [CLS] + [SEP] + newline + safety margin for re-tokenization of joined lines
    reserved = 8
    header = _passage_header(rule)
    header_ids = tokenizer.encode(header, add_special_tokens=False)
    if len(header_ids) > max_tokens // 2:
        # Extremely long title: shorten the header, never the content
        header = tokenizer.decode(header_ids[:max_tokens // 2])
        header_ids = tokenizer.encode(header, add_special_tokens=False)
    budget = max_tokens - len(header_ids) - reserved

    lines = []
    for line in rule["content_for_vector"].split("\n")[1:]:   # line 0 = header
        line = line.strip()
        if not line:
            continue
        n = _token_count(tokenizer, line)
        if n <= budget:
            lines.append((line, n))
        else:
            lines.extend(_split_long_line(line, tokenizer, budget))

    passages = []
    current, current_len = [], 0
    for line, n in lines:
        if current and current_len + n > budget:
            passages.append(current)
            # Overlap: carry the tail of the previous passage forward, but never
            # the whole passage and never more than the next line leaves room for
            carry, carry_len = [], 0
            for prev_line, prev_n in reversed(current[1:]):
                if carry_len + prev_n > min(PASSAGE_OVERLAP_TOKENS, budget - n):
                    break
                carry.insert(0, (prev_line, prev_n))
                carry_len += prev_n
            current, current_len = carry, carry_len
        current.append((line, n))
        current_len += n
    if current or not passages:
        passages.append(current)

    return [header + ("\n" + "\n".join(l for l, _ in p) if p else "") for p in passages]


def embed_rules(all_rules):
    """
    Generate normalized embeddings for every rule (in place).

    all-MiniLM-L6-v2 only reads its first 256 tokens, while a CIS rule is
    often 1,000-3,000 tokens. Each rule is therefore split into passages
    that fit the window and every passage is embedded:
      - rule["passages"]       — [{chunk_id, vector}] for nested kNN search
      - rule["text_embedding"] — normalized mean of the passage vectors
                                 (single-vector fallback covering the whole rule)
    """
    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("=" * 60)
        print("  ERROR: sentence-transformers is not installed.")
        print("  Run: pip install torch --index-url https://download.pytorch.org/whl/cpu")
        print("       pip install sentence-transformers")
        print("=" * 60)
        sys.exit(1)

    print("\n" + "-" * 60)
    print("  [EMBED] Loading model: {} ...".format(EMBEDDING_MODEL))
    model = SentenceTransformer(EMBEDDING_MODEL)
    max_tokens = model.max_seq_length
    print("  [EMBED] Model loaded ({} dimensions, {} token window)".format(
        EMBEDDING_DIMS, max_tokens))

    # ── Split every rule into passages that fit the token window ──
    rule_passages = [split_passages(r, model.tokenizer, max_tokens) for r in all_rules]
    texts = [t for passages in rule_passages for t in passages]
    total = len(texts)
    counts = [len(p) for p in rule_passages]
    print("  [EMBED] {:,d} rules -> {:,d} passages (avg {:.1f}, max {} per rule)".format(
        len(all_rules), total, total / len(all_rules), max(counts)))

    total_batches = (total + BATCH_SIZE_EMBED - 1) // BATCH_SIZE_EMBED
    print("  [EMBED] Encoding {:,d} passages in {} batches (batch_size={})...".format(
        total, total_batches, BATCH_SIZE_EMBED
    ))

    all_embeddings = []
    for i in range(0, total, BATCH_SIZE_EMBED):
        batch_num = (i // BATCH_SIZE_EMBED) + 1
        vectors = model.encode(
            texts[i : i + BATCH_SIZE_EMBED],
            show_progress_bar=False,
            normalize_embeddings=True,
        )
        all_embeddings.extend(vectors.tolist())

        if batch_num % 10 == 0 or batch_num == total_batches:
            print("    Batch {}/{} done ({:,d}/{:,d} passages)".format(
                batch_num, total_batches, min(i + BATCH_SIZE_EMBED, total), total
            ))

    # ── Assign passage vectors and the whole-rule mean vector ──
    pos = 0
    for rule, passages in zip(all_rules, rule_passages):
        vectors = all_embeddings[pos:pos + len(passages)]
        pos += len(passages)
        rule["passages"] = [
            {"chunk_id": i, "vector": vector} for i, vector in enumerate(vectors)
        ]
        mean = np.mean(np.array(vectors), axis=0)
        rule["text_embedding"] = (mean / (np.linalg.norm(mean) or 1.0)).tolist()

    print("  [EMBED] All {:,d} passages embedded for {:,d} rules.".format(total, len(all_rules)))


def main():
    args = parse_args()
    start_time = datetime.now()

    print("=" * 60)
    print("  CIS Benchmark - State Machine PDF Parser")
    print("  Mode: Document-per-Rule (1 rule = 1 JSON document)")
    print("  Output: {}".format(args.output or "(none — coverage check only)"))
    print("  Started: {}".format(start_time.strftime("%Y-%m-%d %H:%M:%S")))
    if PdfReader is None:
        print("  [WARN] pypdf not installed — PDF bookmarks will not be used as ground truth.")
        print("         Run: pip install pypdf")
    print("=" * 60)

    pdf_files = [e for e in PDF_FILES if not args.only or e["source"] in args.only]

    all_rules = []
    coverage_reports = []
    processed_count = 0
    skipped_count = 0

    for entry in pdf_files:
        path = args.pdf_dir / entry["filename"]
        if not path.is_file():
            print("\n  SKIP - File not found: {}".format(path.name))
            skipped_count += 1
            continue

        processed_count += 1
        print("\n" + "-" * 60)
        print("  [{}/{}] Processing: {}".format(
            processed_count, len(pdf_files), entry["filename"]
        ))
        print("-" * 60)

        # ── Step 1: Parse PDF and verify against bookmarks / ToC ──
        rules, coverage = parse_pdf(path, entry)
        coverage_reports.append(coverage)

        # ── Step 2: Post-process each rule (regex extraction) ──
        print("  [POST] Extracting sections & metadata for {} rules...".format(len(rules)))
        for rule in rules:
            post_process_rule(rule)

        all_rules.extend(rules)
        print("  [DONE] {} rules added (running total: {:,d})".format(len(rules), len(all_rules)))

    # ── Guard: no rules parsed ──
    if not all_rules:
        print("\n" + "=" * 60)
        print("  [INFO] BRING YOUR OWN DATA (BYOD) REQUIREMENT")
        print("=" * 60)
        print("  No CIS Benchmark PDF documents were found in the folder:")
        print("    {}".format(args.pdf_dir))
        print("\n  To run this ingestion pipeline, please:")
        print("  1. Register at the official CIS portal:")
        print("     https://workbench.cisecurity.org/")
        print("  2. Download the official PDF Benchmark files for:")
        print("     - Windows Server (2016, 2019, or 2022)")
        print("     - Red Hat Enterprise Linux (7, 8, or 9)")
        print("  3. Place your downloaded PDFs inside the folder:")
        print("     {}".format(args.pdf_dir))
        print("  4. Rerun this script: python 1_parser_and_ingest/ingest_cis.py")
        print("=" * 60)
        return 0

    # ── Step 3: Save coverage report ──
    with open(args.coverage_report, "w", encoding="utf-8") as f:
        json.dump(coverage_reports, f, indent=2, ensure_ascii=False)
    print("\n  [COVERAGE] Report written to {}".format(args.coverage_report))

    # ── Step 4: Generate embeddings ──
    if args.no_embed:
        print("\n  [EMBED] Skipped (--no-embed). Output is NOT ready for Elasticsearch.")
    else:
        embed_rules(all_rules)

    # ── Step 5: Save output (Logstash NDJSON) ──
    file_size_mb = 0.0
    if args.output is not None:
        print("\n" + "-" * 60)
        print("  [SAVE] Writing Logstash NDJSON lines to {}".format(args.output.name))
        with open(args.output, "w", encoding="utf-8") as f:
            for rule in all_rules:
                f.write(json.dumps(rule, ensure_ascii=False) + "\n")
        file_size_mb = args.output.stat().st_size / (1024 * 1024)

    # ── Step 6: Print quality report ──
    print_statistics(all_rules)

    total_missing = sum(len(c["missing"]) for c in coverage_reports)

    # ── Final summary ──
    elapsed = datetime.now() - start_time
    print("\n" + "=" * 60)
    print("  COMPLETED{}".format(" SUCCESSFULLY!" if not total_missing else " WITH GAPS"))
    print("  Total rules parsed   : {:,d}".format(len(all_rules)))
    for c in coverage_reports:
        print("    {:<22s} expected {:>4,d} | parsed {:>4,d} | missing {:>3,d}".format(
            c["source"], c["expected"], c["parsed"], len(c["missing"])))
    print("  Embedding model      : {}".format(EMBEDDING_MODEL if not args.no_embed else "(skipped)"))
    print("  Output NDJSON File   : {}".format(args.output or "(not written)"))
    print("  Output NDJSON Size   : {:.1f} MB".format(file_size_mb))
    print("  Coverage report      : {}".format(args.coverage_report))
    print("  Elapsed time         : {}".format(str(elapsed).split(".")[0]))
    print("=" * 60)
    print("""
  Next steps:
  1. Inspect sample rule (first line of NDJSON):
       python -c "import json; d=json.loads(open('1_parser_and_ingest/output.ndjson','r',encoding='utf-8').readline()); print('Metadata keys:', list(d.keys())); print('Embedding dimensions:', len(d['text_embedding']))"

  2. Stream dataset via Logstash to Elasticsearch using:
       2_elasticsearch_config/cis_benchmark.conf

  3. Verify every rule reached the index:
       python 1_parser_and_ingest/verify_es_coverage.py
""")

    if args.strict and total_missing:
        print("  [STRICT] {} recommendation(s) have no body — see {}".format(
            total_missing, args.coverage_report))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
