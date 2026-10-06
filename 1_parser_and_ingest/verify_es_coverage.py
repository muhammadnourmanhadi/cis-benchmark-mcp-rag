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
import ssl
import sys
import json
import socket
import hashlib
import subprocess
import argparse
from urllib.parse import urlparse
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


class FingerprintMismatch(Exception):
    """ES_FINGERPRINT matches none of the certificates the cluster sends."""

    def __init__(self, presented, chain_read=True):
        super().__init__("Fingerprints did not match")
        self.presented = presented
        self.chain_read = chain_read


def _chain_via_openssl_cli(hostname, port):
    """
    Read the certificates the server sends with the openssl CLI. Used on
    Python < 3.10, whose ssl module cannot return the peer's chain.
    """
    try:
        out = subprocess.run(
            ["openssl", "s_client", "-connect", "{}:{}".format(hostname, port),
             "-servername", hostname, "-showcerts"],
            input=b"", capture_output=True, timeout=15,
        ).stdout.decode("ascii", "replace")
    except (OSError, subprocess.SubprocessError):
        return []
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", out, re.S)
    return [ssl.PEM_cert_to_DER_cert(pem) for pem in pems]


def presented_chain(host):
    """
    Return (certificates the server actually sends as DER, leaf first;
    whether the full chain could be read). Read without verification, so it
    does not depend on the private "verified chain" APIs elastic_transport
    uses, whose result differs between Python/OpenSSL versions (and which do
    not exist at all before Python 3.10).
    """
    url = urlparse(host)
    port = url.port or 9200
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    chain = []
    with socket.create_connection((url.hostname, port), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=url.hostname) as tls:
            leaf = tls.getpeercert(True)
            try:
                if hasattr(tls, "get_unverified_chain"):            # Python 3.13+
                    chain = [bytes(c) for c in tls.get_unverified_chain()]
                elif hasattr(tls._sslobj, "get_unverified_chain"):  # Python 3.10-3.12
                    chain = [c.public_bytes(ssl._ssl.ENCODING_DER)
                             for c in tls._sslobj.get_unverified_chain()]
            except Exception:
                chain = []
    if not chain:                                                   # Python < 3.10
        chain = _chain_via_openssl_cli(url.hostname, port)
    chain_read = bool(chain)
    if not chain or chain[0] != leaf:
        chain.insert(0, leaf)
    return chain, chain_read


def fingerprint_tls(host, fingerprint):
    """
    Resolve ES_FINGERPRINT against the certificates the server sends:
      - matches the server certificate -> pin it (ssl_assert_fingerprint)
      - matches a CA in the chain       -> verify the chain against that CA
    """
    wanted = fingerprint.replace(":", "").strip().lower()
    chain, chain_read = presented_chain(host)
    prints = [hashlib.sha256(der).hexdigest() for der in chain]
    if wanted == prints[0]:
        return {"ssl_assert_fingerprint": wanted}, "server certificate fingerprint (ES_FINGERPRINT)"
    if wanted in prints[1:]:
        ca_pem = ssl.DER_cert_to_PEM_cert(chain[prints.index(wanted)])
        ctx = ssl.create_default_context(cadata=ca_pem)
        # Pinned private CA: same trust model as a fingerprint, so no hostname
        # check (the ES_HOST name/IP may not be in the certificate SANs).
        ctx.check_hostname = False
        # Python 3.13 enables strict X.509 checks that some self-signed
        # Elasticsearch CAs fail (e.g. missing key usage extension).
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        return {"ssl_context": ctx}, "CA fingerprint (ES_FINGERPRINT), CA taken from the TLS chain"
    raise FingerprintMismatch(prints, chain_read)


def get_es():
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        print("ERROR: elasticsearch is not installed. Run: pip install \"elasticsearch>=8.0.0,<10.0.0\"")
        sys.exit(1)

    host = os.getenv("ES_HOST", "https://127.0.0.1:9200")
    kwargs = {"hosts": [host], "request_timeout": 60}
    print("  Elasticsearch : {}".format(host))
    print("  Python/OpenSSL: {} / {}".format(sys.version.split()[0], ssl.OPENSSL_VERSION))
    if os.getenv("ES_CA_CERT"):
        # The CA file wins over a fingerprint: it does not depend on the cluster
        # sending its CA in the TLS chain, and survives certificate renewal.
        kwargs["ca_certs"] = os.getenv("ES_CA_CERT")
        tls = "CA certificate {} (ES_CA_CERT)".format(os.getenv("ES_CA_CERT"))
    elif os.getenv("ES_FINGERPRINT") and host.startswith("https"):
        extra, tls = fingerprint_tls(host, os.getenv("ES_FINGERPRINT"))
        kwargs.update(extra)
    else:
        tls = "system CA store (set ES_FINGERPRINT or ES_CA_CERT for a self-signed cluster)"
    if os.getenv("ES_USER") and os.getenv("ES_PASSWORD"):
        kwargs["basic_auth"] = (os.getenv("ES_USER"), os.getenv("ES_PASSWORD"))
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

    by_source = load_ndjson(args.ndjson)
    total_gaps = 0

    try:
        es = get_es()
        index_exists = es.indices.exists(index=args.index)
    except Exception as e:
        if isinstance(e, FingerprintMismatch) or "Fingerprints did not match" in str(e):
            presented = getattr(e, "presented", None) or \
                re.findall(r'"([0-9a-fA-F:]{40,})"', str(e))[1:]
            print("ERROR: ES_FINGERPRINT does not match any certificate the cluster sends.")
            print("  ES_FINGERPRINT       : {}".format(os.getenv("ES_FINGERPRINT")))
            print("  Cluster presents     : {}".format(", ".join(presented) or "?"))
            if len(presented) == 1 and not getattr(e, "chain_read", True):
                print("  Python {} cannot read the certificate chain (needs 3.10+) and the".format(
                    sys.version.split()[0]))
                print("  openssl CLI was not available, so only the server certificate was")
                print("  compared. Use Python 3.10+ for this venv, or one of:")
            elif len(presented) == 1:
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
