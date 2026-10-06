#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
verify_es_coverage.py — Check that every parsed CIS rule reached Elasticsearch
==============================================================================
Compares output.ndjson (and coverage_report.json, if present) with the
documents stored in the Elasticsearch index.

Reports per source:
  - rules in output.ndjson that are NOT in the index (ingestion gaps)
  - documents in the index that are NOT in output.ndjson (stale documents
    from an older run, e.g. wrongly numbered rules — delete & reindex)

Document IDs follow the Logstash pipeline: "%{rule_id}-%{[metadata][source]}"

Configuration (environment variables, same as the MCP server):
    ES_HOST         default https://127.0.0.1:9200
    ES_USER / ES_PASSWORD
    ES_FINGERPRINT  SHA-256 fingerprint of the ES HTTP certificate
    ES_CA_CERT      path to the ES CA certificate (alternative to fingerprint)
    ES_INDEX        default cis_benchmark

Dependencies:
    pip install "elasticsearch>=8.0.0,<10.0.0"

Usage:
    python 1_parser_and_ingest/verify_es_coverage.py
    python 1_parser_and_ingest/verify_es_coverage.py --ndjson path/to/output.ndjson
"""

import os
import sys
import json
import argparse
from pathlib import Path
from collections import OrderedDict

SCRIPT_DIR = Path(__file__).resolve().parent


def get_es():
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        print("ERROR: elasticsearch is not installed. Run: pip install \"elasticsearch>=8.0.0,<10.0.0\"")
        sys.exit(1)

    kwargs = {"hosts": [os.getenv("ES_HOST", "https://127.0.0.1:9200")], "request_timeout": 60}
    if os.getenv("ES_FINGERPRINT"):
        kwargs["ssl_assert_fingerprint"] = os.getenv("ES_FINGERPRINT")
    elif os.getenv("ES_CA_CERT"):
        kwargs["ca_certs"] = os.getenv("ES_CA_CERT")
    if os.getenv("ES_USER") and os.getenv("ES_PASSWORD"):
        kwargs["basic_auth"] = (os.getenv("ES_USER"), os.getenv("ES_PASSWORD"))
    return Elasticsearch(**kwargs)


def load_ndjson(path):
    """Return {source: OrderedDict(doc_id -> rule_id)}"""
    by_source = OrderedDict()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            doc = json.loads(line)
            source = doc["metadata"]["source"]
            doc_id = "{}-{}".format(doc["rule_id"], source)
            by_source.setdefault(source, OrderedDict())[doc_id] = doc["rule_id"]
    return by_source


def ids_in_index(es, index, doc_ids):
    """Return the subset of doc_ids that exist in the index."""
    found = set()
    doc_ids = list(doc_ids)
    for i in range(0, len(doc_ids), 500):
        resp = es.mget(index=index, ids=doc_ids[i:i + 500], source=False)
        found.update(d["_id"] for d in resp["docs"] if d.get("found"))
    return found


def ids_for_source(es, index, source):
    """Return every document ID stored for one source."""
    ids = set()
    resp = es.search(index=index, query={"term": {"metadata.source": source}},
                     source=False, size=1000, scroll="2m")
    scroll_id = resp.get("_scroll_id")
    try:
        while resp["hits"]["hits"]:
            ids.update(h["_id"] for h in resp["hits"]["hits"])
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = resp.get("_scroll_id")
    finally:
        if scroll_id:
            es.clear_scroll(scroll_id=scroll_id)
    return ids


def main():
    parser = argparse.ArgumentParser(description="Verify CIS rules in Elasticsearch")
    parser.add_argument("--ndjson", type=Path, default=SCRIPT_DIR / "output.ndjson")
    parser.add_argument("--coverage-report", type=Path, default=SCRIPT_DIR / "coverage_report.json")
    parser.add_argument("--index", default=os.getenv("ES_INDEX", "cis_benchmark"))
    args = parser.parse_args()

    if not args.ndjson.is_file():
        print("ERROR: {} not found — run ingest_cis.py first.".format(args.ndjson))
        return 1

    coverage = {}
    if args.coverage_report.is_file():
        with open(args.coverage_report, "r", encoding="utf-8") as f:
            coverage = {c["source"]: c for c in json.load(f)}

    es = get_es()
    by_source = load_ndjson(args.ndjson)
    total_gaps = 0

    print("=" * 60)
    print("  Elasticsearch coverage check — index: {}".format(args.index))
    print("=" * 60)

    for source, docs in by_source.items():
        found = ids_in_index(es, args.index, docs.keys())
        missing = [docs[d] for d in docs if d not in found]
        stale = sorted(ids_for_source(es, args.index, source) - set(docs))
        total_gaps += len(missing)

        print("\n  [{}]".format(source))
        if source in coverage:
            c = coverage[source]
            print("    Official recommendations (PDF) : {:>5,d}".format(c["expected"]))
            print("    Without body in parser         : {:>5,d} {}".format(
                len(c["missing"]), c["missing"][:10] if c["missing"] else ""))
        print("    Rules in output.ndjson         : {:>5,d}".format(len(docs)))
        print("    Rules found in index           : {:>5,d}".format(len(found)))
        print("    MISSING in index               : {:>5,d} {}".format(
            len(missing), missing[:20] if missing else ""))
        print("    Stale docs (not in NDJSON)     : {:>5,d} {}".format(
            len(stale), stale[:20] if stale else ""))

    print("\n" + "=" * 60)
    if total_gaps:
        print("  RESULT: {} rule(s) missing from the index. Check the Logstash log".format(total_gaps))
        print("  (mapping errors) and re-run the pipeline.")
    else:
        print("  RESULT: every rule in output.ndjson is in the index.")
    print("  Stale docs: delete the index, re-register the template, re-run Logstash.")
    print("=" * 60)
    return 1 if total_gaps else 0


if __name__ == "__main__":
    sys.exit(main())
