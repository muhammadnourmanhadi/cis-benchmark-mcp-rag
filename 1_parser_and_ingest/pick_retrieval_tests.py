#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pick_retrieval_tests.py — Build retrieval test questions from output.ndjson
===========================================================================
Picks random rules and, for each, one command/config line from its audit or
remediation text that sits more than --min-offset characters into the rule
(by default 1,200 — beyond what a single 256-token embedding would read).

Ask your MCP-connected AI agent, for each printed line:
    "In CIS <OS>, which rule's audit/remediation contains `<line>`? Give the rule ID."
and compare the answer with the printed [rule_id]. With passage embeddings the
expected rule should rank in the top 1-3 results.

Dependencies: none (standard library only)

Usage:
    python 1_parser_and_ingest/pick_retrieval_tests.py
    python 1_parser_and_ingest/pick_retrieval_tests.py --source rhel_9 --count 20
"""

import re
import sys
import json
import random
import argparse
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description="Pick deep-text retrieval test questions")
    parser.add_argument("--ndjson", type=Path, default=SCRIPT_DIR / "output.ndjson")
    parser.add_argument("--source", help="Only rules of this source, e.g. rhel_9")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--min-offset", type=int, default=1200,
                        help="Minimum character position of the line inside the rule")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    if not args.ndjson.is_file():
        print("ERROR: {} not found — run ingest_cis.py first.".format(args.ndjson))
        return 1

    random.seed(args.seed)
    picked = []
    with open(args.ndjson, "r", encoding="utf-8") as f:
        for line in f:
            rule = json.loads(line)
            if args.source and rule["metadata"]["source"] != args.source:
                continue
            content = rule["content_for_vector"]
            text = rule["sections"]["audit_text"] + "\n" + rule["sections"]["remediation_text"]
            candidates = [
                l.strip() for l in text.split("\n")
                if 25 <= len(l.strip()) <= 120
                and content.find(l.strip()) > args.min_offset
                and re.search(r"[/=#]|^\w+ -", l)                 # looks like a command/config
                and l.strip().lower() not in rule["rule_title"].lower()
            ]
            if candidates:
                picked.append((rule["metadata"]["source"], rule["rule_id"],
                               rule["rule_title"], random.choice(candidates)))

    if not picked:
        print("No suitable lines found (try a lower --min-offset).")
        return 1

    for source, rule_id, title, text in random.sample(picked, min(args.count, len(picked))):
        print("[{}] {} — {}\n    -> {}".format(source, rule_id, title, text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
