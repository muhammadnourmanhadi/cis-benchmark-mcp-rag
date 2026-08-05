#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ingest_cis.py — State Machine CIS Benchmark PDF Parser + Embedder
=================================================================
Production-ready parser that converts CIS Benchmark PDFs into structured
JSON documents using a line-by-line State Machine approach, then generates
dense vector embeddings for each rule using sentence-transformers.

Architecture:
    PDF  →  pdfplumber (extract text per page)
         →  State Machine (detect rule headers, accumulate content)
         →  Post-Processing (regex extraction of sections & metadata)
         →  Batch Embedding (sentence-transformers/all-MiniLM-L6-v2)
         →  JSON output (one document per CIS rule + text_embedding)

Key Architecture Benefit:
    Each parsed CIS rule corresponds directly to 1 complete JSON document. This preserves context integrity and prevents critical information from being split mid-sentence.

Supported Header Formats:
    WINDOWS: "1.2.1 (L1) Ensure 'xyz' is set to 'abc' (Automated)"
    RHEL:    "1.1.1.7 Ensure udf kernel module is not available (Automated)"

Output:
    1_parser_and_ingest/cis_rules.json — Structured JSON Lines array for Vector RAG

Dependencies:
    pip install pdfplumber sentence-transformers torch

Usage:
    python 1_parser_and_ingest/ingest_cis.py
"""

import re
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter

try:
    import pdfplumber
except ImportError:
    print("=" * 60)
    print("  ERROR: pdfplumber is not installed.")
    print("  Run: pip install pdfplumber")
    print("=" * 60)
    sys.exit(1)

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("=" * 60)
    print("  ERROR: sentence-transformers is not installed.")
    print("  Run: pip install sentence-transformers torch")
    print("=" * 60)
    sys.exit(1)


# ======================================================================
# CONFIGURATION
# ======================================================================

SCRIPT_DIR  = Path(__file__).resolve().parent
PDF_DIR     = SCRIPT_DIR / "cis_benchmarks"

PDF_FILES = [
    # ── Windows Server ──────────────────────────────────────────────────
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
OUTPUT_NDJSON = SCRIPT_DIR / "output.ndjson"

# --- Embedding Model ---
EMBEDDING_MODEL  = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIMS   = 384
BATCH_SIZE_EMBED = 64     # Reduce if RAM runs out


# ======================================================================
# REGEX PATTERNS
# ======================================================================

# ---------------------------------------------------------------------------
# FORMAT A (Windows): "1.2.1 (L1) Ensure 'xyz' is set to 'abc' (Automated)"
#   Groups: (1) rule_id, (2) cis_level, (3) rule_title, (4) automation_status
# ---------------------------------------------------------------------------
RULE_HEADER_WIN_RE = re.compile(
    r"^(\d+(?:\.\d+)+)"             # Group 1: rule_id  e.g. "1.2.1"
    r"\s+\(([Ll][12])\)\s+"         # Group 2: cis_level e.g. "L1"
    r"(.+)"                         # Group 3: rule_title (greedy)
    r"\s+\((Automated|Manual)\)"    # Group 4: automation_status
    r"\s*$"
)

# Partial header start for Windows (multi-line detection)
RULE_START_WIN_RE = re.compile(
    r"^(\d+(?:\.\d+)+)\s+\(([Ll][12])\)\s+(.+)"
)

# ---------------------------------------------------------------------------
# FORMAT B (RHEL/Linux): "1.1.1.7 Ensure udf kernel module is not available (Automated)"
#   No (L1)/(L2) in header — level is extracted from Profile Applicability section.
#   Groups: (1) rule_id, (2) rule_title, (3) automation_status
# ---------------------------------------------------------------------------
RULE_HEADER_LINUX_RE = re.compile(
    r"^(\d+(?:\.\d+)+)"             # Group 1: rule_id  e.g. "1.1.1.7"
    r"\s+"                           # whitespace
    r"(Ensure\s.+|Disable\s.+|Enable\s.+|Configure\s.+|Set\s.+|Verify\s.+|"
    r"Restrict\s.+|Audit\s.+|Collect\s.+|Record\s.+|Remediate\s.+|"
    r"Remove\s.+|Install\s.+|Uninstall\s.+)"  # Group 2: title starting with action verb
    r"\s*\((Automated|Manual)\)"     # Group 3: automation_status
    r"\s*$"
)

# Partial header start for Linux (multi-line detection)
RULE_START_LINUX_RE = re.compile(
    r"^(\d+(?:\.\d+)+)\s+"
    r"(Ensure\s|Disable\s|Enable\s|Configure\s|Set\s|Verify\s|"
    r"Restrict\s|Audit\s|Collect\s|Record\s|Remediate\s|"
    r"Remove\s|Install\s|Uninstall\s)"
)

# Maximum chars to accumulate for multi-line header completion
HEADER_BUFFER_LIMIT = 600


# ======================================================================
# STATE MACHINE PARSER
# ======================================================================

def _try_match_header(line, os_family):
    """
    Try to match a complete rule header line.

    Returns:
        (rule_id, cis_level, rule_title, automation_status) or None
    """
    if os_family == "windows":
        m = RULE_HEADER_WIN_RE.match(line)
        if m:
            return (m.group(1), m.group(2).upper(), m.group(3).strip(), m.group(4))
    else:
        # Try Windows format first (some Linux PDFs may use it)
        m = RULE_HEADER_WIN_RE.match(line)
        if m:
            return (m.group(1), m.group(2).upper(), m.group(3).strip(), m.group(4))
        # Then try Linux format
        m = RULE_HEADER_LINUX_RE.match(line)
        if m:
            return (m.group(1), "", m.group(2).strip(), m.group(3))
    return None


def _try_match_partial(line, os_family):
    """
    Check if a line looks like the START of a rule header but is incomplete.
    Returns True if it looks like a partial header.
    """
    if os_family == "windows":
        return bool(RULE_START_WIN_RE.match(line))
    else:
        if RULE_START_WIN_RE.match(line):
            return True
        return bool(RULE_START_LINUX_RE.match(line))


def parse_pdf(pdf_path, meta):
    """
    Parse a single CIS Benchmark PDF using a line-by-line state machine.

    The state machine has 3 states:
      1. SCANNING     — Looking for the start of a new rule header
      2. BUFFERING    — Accumulating a multi-line rule header
      3. ACCUMULATING — Appending content lines to the current rule

    Args:
        pdf_path: Path to the CIS Benchmark PDF file
        meta:     Dict with os metadata (source, os_family, os_name, etc.)

    Returns:
        List of parsed rule dicts (before post-processing)
    """
    rules = []
    current_rule = None
    header_buffer = ""
    header_start_page = None
    os_family = meta["os_family"]

    print("  [PARSE] Opening: {}".format(pdf_path.name))

    with pdfplumber.open(str(pdf_path)) as pdf:
        total_pages = len(pdf.pages)
        print("  [PARSE] Total pages: {}".format(total_pages))

        for page_num, page in enumerate(pdf.pages, start=1):
            if page_num % 100 == 0 or page_num == total_pages:
                print("    Page {}/{}...".format(page_num, total_pages))

            text = page.extract_text() or ""
            
            # Skip Table of Contents pages dynamically
            if text.count(".....") > 3:
                continue

            lines = text.split("\n")

            for line in lines:
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                # ── STATE: Try COMPLETE header match ──
                header_result = _try_match_header(line_stripped, os_family)
                if header_result:
                    # Flush any pending buffer
                    if header_buffer and current_rule:
                        current_rule["content_for_vector"] += header_buffer + "\n"
                    header_buffer = ""

                    # Save previous rule
                    if current_rule:
                        rules.append(current_rule)

                    # Initialize new rule
                    rule_id, cis_level, rule_title, automation_status = header_result
                    current_rule = _init_rule(
                        rule_id, cis_level, rule_title,
                        automation_status, page_num, meta
                    )
                    continue

                # ── STATE: Check for PARTIAL header start ──
                if not header_buffer and _try_match_partial(line_stripped, os_family):
                    header_buffer = line_stripped
                    header_start_page = page_num
                    continue

                # ── STATE: BUFFERING — try to complete header ──
                if header_buffer:
                    header_buffer += " " + line_stripped
                    completed = _try_match_header(header_buffer, os_family)
                    if completed:
                        if current_rule:
                            rules.append(current_rule)
                        rule_id, cis_level, rule_title, automation_status = completed
                        current_rule = _init_rule(
                            rule_id, cis_level, rule_title,
                            automation_status, header_start_page, meta
                        )
                        header_buffer = ""
                        continue
                    elif len(header_buffer) > HEADER_BUFFER_LIMIT:
                        # Too long — not a valid header, dump as content
                        if current_rule:
                            current_rule["content_for_vector"] += header_buffer + "\n"
                            if page_num not in current_rule["metadata"]["source_pages"]:
                                current_rule["metadata"]["source_pages"].append(page_num)
                        header_buffer = ""
                    continue

                # ── STATE: ACCUMULATING regular content ──
                if current_rule:
                    current_rule["content_for_vector"] += line_stripped + "\n"
                    if page_num not in current_rule["metadata"]["source_pages"]:
                        current_rule["metadata"]["source_pages"].append(page_num)

        # ── End of PDF: flush remaining state ──
        if header_buffer and current_rule:
            current_rule["content_for_vector"] += header_buffer + "\n"

        if current_rule:
            rules.append(current_rule)

    print("  [PARSE] Extracted {} rules from {}".format(len(rules), pdf_path.name))
    return rules


def _init_rule(rule_id, cis_level, rule_title, automation_status, page_num, meta):
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
        },
    }


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
        # Match bullet points with various Unicode bullets or plain dashes
        bullets = re.findall(r"[^\S\n]*[•·‣\u25cf\u2022\?\-\*]\s*(.+)", raw_block)
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

def main():
    start_time = datetime.now()

    print("=" * 60)
    print("  CIS Benchmark - State Machine PDF Parser")
    print("  Mode: Document-per-Rule (1 rule = 1 JSON document)")
    print("  Output: {}".format(OUTPUT_NDJSON))
    print("  Started: {}".format(start_time.strftime("%Y-%m-%d %H:%M:%S")))
    print("=" * 60)

    all_rules = []
    processed_count = 0
    skipped_count = 0

    for entry in PDF_FILES:
        path = PDF_DIR / entry["filename"]
        if not path.is_file():
            print("\n  SKIP - File not found: {}".format(path.name))
            skipped_count += 1
            continue

        processed_count += 1
        print("\n" + "-" * 60)
        print("  [{}/{}] Processing: {}".format(
            processed_count, len(PDF_FILES), entry["filename"]
        ))
        print("-" * 60)

        # ── Step 1: Parse PDF with state machine ──
        rules = parse_pdf(path, entry)

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
        print("    {}".format(PDF_DIR))
        print("\n  To run this ingestion pipeline, please:")
        print("  1. Register at the official CIS portal:")
        print("     https://workbench.cisecurity.org/")
        print("  2. Download the official PDF Benchmark files for:")
        print("     - Windows Server (2016, 2019, or 2022)")
        print("     - Red Hat Enterprise Linux (7, 8, or 9)")
        print("  3. Place your downloaded PDFs inside the folder:")
        print("     {}".format(PDF_DIR))
        print("  4. Rerun this script: python 1_parser_and_ingest/ingest_cis.py")
        print("=" * 60)
        return

    # ── Step 2.5: Deduplicate (Keep only the longest content per rule_id + source) ──
    print("\n" + "-" * 60)
    print("  [DEDUPLICATE] Filtering out Table of Contents and Appendix duplicates...")
    dedup_map = {}
    for rule in all_rules:
        key = (rule["rule_id"], rule["metadata"]["source"])
        # Keep the record with the longest text content
        if key not in dedup_map or len(rule["content_for_vector"]) > len(dedup_map[key]["content_for_vector"]):
            dedup_map[key] = rule
            
    original_count = len(all_rules)
    all_rules = list(dedup_map.values())
    print("  [DEDUPLICATE] Retained {:,d} unique rules (filtered out {:,d} duplicates)".format(
        len(all_rules), original_count - len(all_rules)
    ))

    # ── Step 3: Generate embeddings ──────────────────────────────────
    print("\n" + "-" * 60)
    print("  [EMBED] Loading model: {} ...".format(EMBEDDING_MODEL))
    model = SentenceTransformer(EMBEDDING_MODEL)
    print("  [EMBED] Model loaded ({} dimensions)".format(EMBEDDING_DIMS))

    texts = [r["content_for_vector"] for r in all_rules]
    total_rules = len(texts)
    total_batches = (total_rules + BATCH_SIZE_EMBED - 1) // BATCH_SIZE_EMBED

    print("  [EMBED] Encoding {:,d} rules in {} batches (batch_size={})...".format(
        total_rules, total_batches, BATCH_SIZE_EMBED
    ))

    all_embeddings = []
    for i in range(0, total_rules, BATCH_SIZE_EMBED):
        batch_num = (i // BATCH_SIZE_EMBED) + 1
        batch_texts = texts[i : i + BATCH_SIZE_EMBED]
        vectors = model.encode(
            batch_texts,
            show_progress_bar=False,
            normalize_embeddings=True,
        )
        all_embeddings.extend(vectors.tolist())

        if batch_num % 10 == 0 or batch_num == total_batches:
            print("    Batch {}/{} done ({:,d}/{:,d} rules)".format(
                batch_num, total_batches,
                min(i + BATCH_SIZE_EMBED, total_rules), total_rules
            ))

    # Assign embeddings to each rule
    for rule, embedding in zip(all_rules, all_embeddings):
        rule["text_embedding"] = embedding

    print("  [EMBED] All {:,d} embeddings generated successfully.".format(total_rules))

    # ── Step 4: Save output (Logstash NDJSON) ──
    print("\n" + "-" * 60)
    print("  [SAVE] Writing Logstash NDJSON lines to {}".format(OUTPUT_NDJSON.name))
    with open(OUTPUT_NDJSON, "w", encoding="utf-8") as f:
        for rule in all_rules:
            f.write(json.dumps(rule, ensure_ascii=False) + "\n")

    file_size_mb = OUTPUT_NDJSON.stat().st_size / (1024 * 1024)

    # ── Step 5: Print quality report ──
    print_statistics(all_rules)

    # ── Final summary ──
    elapsed = datetime.now() - start_time
    print("\n" + "=" * 60)
    print("  COMPLETED SUCCESSFULLY!")
    print("  Total rules parsed   : {:,d}".format(len(all_rules)))
    print("  Embedding model      : {}".format(EMBEDDING_MODEL))
    print("  Output NDJSON File   : {}".format(OUTPUT_NDJSON))
    print("  Output NDJSON Size   : {:.1f} MB".format(file_size_mb))
    print("  Elapsed time         : {}".format(str(elapsed).split(".")[0]))
    print("=" * 60)
    print("""
  Next steps:
  1. Inspect sample rule (first line of NDJSON):
       python -c "import json; d=json.loads(open('1_parser_and_ingest/output.ndjson','r',encoding='utf-8').readline()); print('Metadata keys:', list(d.keys())); print('Embedding dimensions:', len(d['text_embedding']))"

  2. Stream dataset via Logstash to Elasticsearch using:
       2_elasticsearch_config/cis_benchmark.conf
""")


if __name__ == "__main__":
    main()
