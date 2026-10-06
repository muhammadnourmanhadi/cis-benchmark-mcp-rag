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
    ES_CA_CERT      path to the ES HTTP CA certificate (takes precedence over
                    ES_FINGERPRINT; use it when the cluster does not send its CA)
    ES_INDEX        default cis_benchmark

Values not exported in the shell are read from 3_mcp_server/.env (or --env-file),
so the same settings as the MCP server work without re-typing them.

Dependencies:
    pip install "elasticsearch>=8.0.0,<10.0.0"

Usage:
    python 1_parser_and_ingest/verify_es_coverage.py
    python 1_parser_and_ingest/verify_es_coverage.py --ndjson path/to/output.ndjson
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from collections import OrderedDict

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = SCRIPT_DIR.parent / "3_mcp_server" / ".env"


def load_env_file(path):
    """
    Load KEY=VALUE pairs from an .env file (the MCP server's by default).
    Variables already set in the environment win over the file.
    """
    if not path or not Path(path).is_file():
        return False
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            value = value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value
    return True


def get_es():
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        print("ERROR: elasticsearch is not installed. Run: pip install \"elasticsearch>=8.0.0,<10.0.0\"")
        sys.exit(1)

    host = os.getenv("ES_HOST", "https://127.0.0.1:9200")
    kwargs = {"hosts": [host], "request_timeout": 60}
    if os.getenv("ES_CA_CERT"):
        # The CA file wins over a fingerprint: it does not depend on the cluster
        # sending its CA in the TLS chain, and survives certificate renewal.
        kwargs["ca_certs"] = os.getenv("ES_CA_CERT")
        tls = "CA certificate {} (ES_CA_CERT)".format(os.getenv("ES_CA_CERT"))
    elif os.getenv("ES_FINGERPRINT"):
        kwargs["ssl_assert_fingerprint"] = os.getenv("ES_FINGERPRINT")
        tls = "certificate fingerprint (ES_FINGERPRINT)"
    else:
        tls = "system CA store (set ES_FINGERPRINT or ES_CA_CERT for a self-signed cluster)"
    if os.getenv("ES_USER") and os.getenv("ES_PASSWORD"):
        kwargs["basic_auth"] = (os.getenv("ES_USER"), os.getenv("ES_PASSWORD"))
    print("  Elasticsearch : {}".format(host))
    if host.startswith("https"):
        print("  TLS verify    : {}".format(tls))
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


def count_without_passages(es, index, source):
    """Documents of one source that have no passage vectors (full-text search misses them)."""
    mapping = next(iter(es.indices.get_mapping(index=index).values()))["mappings"]
    if mapping.get("properties", {}).get("passages", {}).get("type") != "nested":
        return None   # index predates passages — reported once in main()
    query = {"bool": {
        "filter": [{"term": {"metadata.source": source}}],
        "must_not": [{"nested": {"path": "passages", "query": {"exists": {"field": "passages.vector"}}}}],
    }}
    return es.count(index=index, query=query)["count"]


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


def sources_in_index(es, index):
    """Return {source: doc_count} for every source stored in the index."""
    resp = es.search(index=index, size=0,
                     aggs={"sources": {"terms": {"field": "metadata.source", "size": 100}}})
    return {b["key"]: b["doc_count"] for b in resp["aggregations"]["sources"]["buckets"]}


def main():
    parser = argparse.ArgumentParser(description="Verify CIS rules in Elasticsearch")
    parser.add_argument("--ndjson", type=Path, default=SCRIPT_DIR / "output.ndjson")
    parser.add_argument("--coverage-report", type=Path, default=SCRIPT_DIR / "coverage_report.json")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE,
                        help="Read ES_* settings from this file when they are not exported "
                             "(default: %(default)s)")
    parser.add_argument("--index", default=None)
    args = parser.parse_args()

    if load_env_file(args.env_file):
        print("  Env file      : {}".format(args.env_file))
    args.index = args.index or os.getenv("ES_INDEX", "cis_benchmark")

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

    try:
        index_exists = es.indices.exists(index=args.index)
    except Exception as e:
        if "Fingerprints did not match" in str(e):
            presented = re.findall(r'"([0-9a-fA-F:]{40,})"', str(e))[1:]
            print("ERROR: ES_FINGERPRINT does not match any certificate the cluster sends.")
            print("  ES_FINGERPRINT       : {}".format(os.getenv("ES_FINGERPRINT")))
            print("  Cluster presents     : {}".format(", ".join(presented) or "?"))
            if len(presented) == 1:
                print("  The cluster sends only its own certificate, not the CA chain, so a CA")
                print("  fingerprint can never match. Use one of:")
                print("    1. Verify against the CA file (recommended, survives cert renewal):")
                print("         ES_CA_CERT=/path/to/http_ca.crt   (copy of /etc/elasticsearch/certs/http_ca.crt)")
                print("       and remove ES_FINGERPRINT.")
                print("    2. Pin the certificate the cluster presents (changes when it is renewed):")
                print("         ES_FINGERPRINT={}".format(presented[0]))
            return 1
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            print("ERROR: TLS certificate verification failed — the cluster uses a self-signed CA.")
            print("  Set ES_FINGERPRINT (HTTP CA SHA-256 fingerprint) or ES_CA_CERT, either")
            print("  exported in this shell (export ES_FINGERPRINT=...) or in {}.".format(args.env_file))
            print("  Get the fingerprint with:")
            print("    openssl x509 -fingerprint -sha256 -noout -in /etc/elasticsearch/certs/http_ca.crt")
            return 1
        raise
    if not index_exists:
        print("ERROR: index '{}' does not exist — register the template and run Logstash.".format(
            args.index))
        return 1

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
        no_passages = count_without_passages(es, args.index, source)
        if no_passages is None:
            print("    Passage vectors                : index has no nested 'passages' mapping —")
            print("                                     delete it and recreate from index_template.json")
        else:
            print("    Docs without passage vectors   : {:>5,d}".format(no_passages))

    # Sources in the index that this NDJSON does not cover at all
    for source, count in sorted(sources_in_index(es, args.index).items()):
        if source not in by_source:
            print("\n  [{}] {:,d} docs in index, source not in {} — stale or from "
                  "another run.".format(source, count, args.ndjson.name))

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
