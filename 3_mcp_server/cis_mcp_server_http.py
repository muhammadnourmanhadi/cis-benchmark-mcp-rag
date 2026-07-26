#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
cis_mcp_server_http.py
======================
MCP Server using HTTP transport (streamable-http).
Designed to be run as a standalone Docker container.

An AI Agent (e.g. Hermes-agent) inside the Docker network connects via:
    http://cis-mcp-server:8765/mcp

Configuration snippet in your Agent client config file (e.g., ~/.hermes/config.yaml):
    mcp_servers:
      cis-benchmark:
        url: "http://cis-mcp-server:8765/mcp"
"""

import os
import logging
from typing import Optional, List

from mcp.server.fastmcp import FastMCP

# ======================================================================
# CONFIGURATION — retrieved from environment variables
# ======================================================================
ES_HOST        = os.getenv("ES_HOST",     "https://127.0.0.1:9200")
ES_USER        = os.getenv("ES_USER",     "")
ES_PASSWORD    = os.getenv("ES_PASSWORD", "")
ES_FINGERPRINT = os.getenv("ES_FINGERPRINT", "")
ES_INDEX       = os.getenv("ES_INDEX",    "cis_benchmark")
MCP_PORT       = int(os.getenv("MCP_PORT", "8765"))
MCP_HOST       = os.getenv("MCP_HOST",    "0.0.0.0")

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
# ======================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ======================================================================
# Lazy-load model and Elasticsearch client
# ======================================================================
_model = None
_es    = None


def get_model():
    global _model
    if _model is None:
        log.info(f"Loading embedding model: {EMBEDDING_MODEL}")
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(EMBEDDING_MODEL)
        log.info("Embedding model loaded OK")
    return _model


def get_embedding(query: str) -> List[float]:
    """
    Helper function to convert the text query into a 384-dimensional vector.
    """
    model = get_model()
    return model.encode(query, normalize_embeddings=True).tolist()


def get_es():
    global _es
    if _es is None:
        from elasticsearch import Elasticsearch
        kwargs = {
            "hosts": [ES_HOST],
            "request_timeout": 30,
        }
        
        # Use SSL Fingerprint verification if available, otherwise disable verification
        if ES_FINGERPRINT:
            kwargs["ssl_assert_fingerprint"] = ES_FINGERPRINT
        else:
            kwargs["verify_certs"] = False
            kwargs["ssl_show_warn"] = False

        if ES_USER and ES_PASSWORD:
            kwargs["basic_auth"] = (ES_USER, ES_PASSWORD)
            
        _es = Elasticsearch(**kwargs)
        log.info(f"Elasticsearch client initialized → {ES_HOST}")
    return _es


# ======================================================================
# Initialize FastMCP server
# ======================================================================
mcp = FastMCP(
    name="cis-benchmark-search",
    host=MCP_HOST,
    port=MCP_PORT,
    instructions=(
        "This server provides access to the CIS Benchmark database "
        "(Windows Server 2016/2019/2022 and RHEL 7/8/9). "
        "Routing guide: "
        "(1) Rule CONTENT / detailed guidance queries → use search_cis_benchmark. "
        "(2) Rule COUNT / total rules queries → use count_cis_rules. "
        "(3) Rule BREAKDOWN per category/section → use breakdown_cis_rules. "
        "(4) Global statistics and audits → use get_cis_statistics."
    )
)


# ======================================================================
# Tool definitions
# ======================================================================

@mcp.tool()
def search_cis_benchmark(
    query: str,
    cis_level: Optional[str] = None,
    profile: Optional[str] = None,
    is_automated: Optional[bool] = None,
    os_filter: Optional[str] = None,
    top_k: int = 5
) -> dict:
    """
    Search relevant information from CIS Benchmarks using hybrid k-NN vector search and metadata filtering.

    Args:
        query: Topic or security configuration question to search.
        cis_level: Filter by CIS level. Valid values: 'L1', 'L2' (case-insensitive).
        profile: Filter by target profile (e.g., 'domain_controller', 'member_server', 'server', 'workstation').
        is_automated: Filter by automation status (True for Automated, False for Manual).
        os_filter: Filter by specific OS/platform (e.g., 'windows_server_2022', 'rhel_9').
        top_k: Maximum number of results to return (default: 5, max: 20).

    Returns:
        Dict containing cleanly formatted search results for LLM agents.
    """
    top_k = min(max(int(top_k), 1), 20)
    log.info(f"search_cis_benchmark: query='{query}' cis_level={cis_level} profile={profile} is_automated={is_automated} os_filter={os_filter} top_k={top_k}")

    # 1. Vectorize query
    try:
        query_vector = get_embedding(query)
    except Exception as e:
        log.error(f"Vectorization failed: {e}")
        return {"error": f"Failed to vectorize query: {str(e)}"}

    # 2. Build pre-filters within kNN query block
    filters = []

    if cis_level:
        # Support case-insensitive query (L1/l1, L2/l2)
        lvl_val = cis_level.strip().upper()
        filters.append({"terms": {"metadata.cis_level": [lvl_val, lvl_val.lower()]}})

    if profile:
        # profile_applicability contains snake_case values like:
        # 'level_1_member_server', 'level_1_domain_controller', etc.
        # LLMs may only send 'member_server' or 'domain_controller'.
        # Use wildcard for partial matching.
        prof_val = profile.strip().lower().replace(" ", "_")
        filters.append({
            "wildcard": {
                "metadata.profile_applicability": f"*{prof_val}*"
            }
        })

    if is_automated is not None:
        status_terms = ["automated"] if is_automated else ["manual"]
        # Support case variations (Automated/automated, Manual/manual)
        status_terms.extend([s.capitalize() for s in status_terms])
        filters.append({"terms": {"metadata.automation_status": status_terms}})

    if os_filter:
        filters.append({"term": {"metadata.source": os_filter.strip().lower()}})

    # Construct the Elasticsearch search payload using the new schema
    knn_payload = {
        "field": "text_embedding",
        "query_vector": query_vector,
        "k": top_k,
        "num_candidates": top_k * 10
    }

    if filters:
        knn_payload["filter"] = {
            "bool": {
                "filter": filters
            }
        }

    es = get_es()
    try:
        response = es.search(
            index=ES_INDEX,
            knn=knn_payload,
            source=[
                "rule_id", "rule_title", "metadata.profile_applicability", 
                "sections.audit_text", "sections.remediation_text", "metadata.source"
            ]
        )
    except Exception as e:
        log.error(f"Elasticsearch search failed: {e}")
        return {
            "error": str(e),
            "query": query,
            "results": [],
            "total_found": 0
        }

    # 3. Format the output cleanly for the LLM
    hits = response["hits"]["hits"]
    formatted_results = []
    
    for hit in hits:
        src = hit["_source"]
        rule_id = src.get("rule_id", "N/A")
        rule_title = src.get("rule_title", "N/A")
        
        # Metadata
        meta = src.get("metadata", {})
        profiles = meta.get("profile_applicability", [])
        
        # Sections
        sections = src.get("sections", {})
        audit = sections.get("audit_text", "No specific audit information provided.")
        remediation = sections.get("remediation_text", "No specific remediation steps provided.")
        
        formatted_str = (
            f"Rule ID: {rule_id} | Title: {rule_title}\n"
            f"Applicability: {profiles}\n"
            f"Audit: {audit}\n"
            f"Remediation: {remediation}"
        )
        formatted_results.append(formatted_str)

    log.info(f"Returned {len(formatted_results)} results for query: '{query}'")
    return {
        "query": query,
        "total_found": len(formatted_results),
        "results": formatted_results
    }


@mcp.tool()
def list_available_sources() -> dict:
    """
    List available platforms/OS indexed inside Elasticsearch along with their rule counts.

    Returns:
        Dict containing index name, total registered rules, and cataloged platforms.
    """
    log.info("list_available_sources called")
    es = get_es()
    try:
        response = es.search(
            index=ES_INDEX,
            size=0,
            aggs={
                "sources": {
                    "terms": {"field": "metadata.source", "size": 20}
                },
                "os_families": {
                    "terms": {"field": "metadata.os_family", "size": 10}
                }
            }
        )
        platforms = [
            {
                "source_id":  b["key"],
                "doc_count":  b["doc_count"]
            }
            for b in response["aggregations"]["sources"]["buckets"]
        ]
        total = response["hits"]["total"]["value"]

        return {
            "index":        ES_INDEX,
            "total_rules":  total,
            "platforms":    platforms,
            "note":         "Use 'source_id' value as 'os_filter' parameter in search_cis_benchmark"
        }
    except Exception as e:
        log.error(f"list_available_sources failed: {e}")
        return {"error": str(e), "platforms": []}


@mcp.tool()
def get_cis_statistics(os_filter: Optional[str] = None) -> dict:
    """
    Calculate real-time global statistics of CIS rules indexed in the database.

    Args:
        os_filter: Optional filter to narrow down to a specific platform (e.g., 'windows_server_2022').
    Returns:
        Dict containing total rules and breakdown statistics of CIS levels (L1/L2).
    """
    log.info(f"get_cis_statistics called with os_filter={os_filter}")
    es = get_es()
    
    # Base queries
    total_query = {"query": {"match_all": {}}}
    l1_query = {"query": {"term": {"metadata.cis_level": "L1"}}}
    l2_query = {"query": {"term": {"metadata.cis_level": "L2"}}}
    
    if os_filter:
        os_val = os_filter.strip().lower()
        total_query = {"query": {"term": {"metadata.source": os_val}}}
        l1_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"metadata.cis_level": "L1"}},
                        {"term": {"metadata.source": os_val}}
                    ]
                }
            }
        }
        l2_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"metadata.cis_level": "L2"}},
                        {"term": {"metadata.source": os_val}}
                    ]
                }
            }
        }

    try:
        total_resp = es.count(index=ES_INDEX, body=total_query)
        l1_resp = es.count(index=ES_INDEX, body=l1_query)
        l2_resp = es.count(index=ES_INDEX, body=l2_query)
        
        total_rules = total_resp["count"]
        l1_count = l1_resp["count"]
        l2_count = l2_resp["count"]
        unknown_count = total_rules - (l1_count + l2_count)
        
        return {
            "os_filter": os_filter or "all",
            "total_rules": total_rules,
            "cis_level_breakdown": {
                "L1": l1_count,
                "L2": l2_count,
                "unknown_or_other": unknown_count
            }
        }
    except Exception as e:
        log.error(f"get_cis_statistics failed: {e}")
        return {"error": str(e)}


@mcp.tool()
def count_cis_rules(
    cis_level: Optional[str] = None,
    profile: Optional[str] = None,
    os_filter: Optional[str] = None,
    is_automated: Optional[bool] = None,
) -> dict:
    """
    Calculate the exact count of CIS Benchmark rules matching specific metadata filters.

    IMPORTANT: Use this tool (and NOT search_cis_benchmark) when queries ask for statistics or numbers, e.g.:
    - "How many Level 1 member server rules exist for Windows 2022?"
    - "What is the total count of automated rules in RHEL 9?"
    - "How many L2 rules are there in Windows Server 2019?"

    Args:
        cis_level: Filter by CIS level. Valid values: 'L1', 'L2'.
        profile: Filter by target profile (e.g., 'member_server', 'domain_controller'). Partial matching is supported.
        os_filter: Filter by platform OS (e.g., 'windows_server_2022', 'rhel_9').
        is_automated: True for Automated, False for Manual.

    Returns:
        Dict containing total count matching the criteria and applied filters description.
    """
    log.info(f"count_cis_rules: cis_level={cis_level} profile={profile} os_filter={os_filter} is_automated={is_automated}")
    es = get_es()

    # Build bool filter clauses
    must_clauses = []

    if cis_level:
        lvl_val = cis_level.strip().upper()
        must_clauses.append({"terms": {"metadata.cis_level": [lvl_val, lvl_val.lower()]}})

    if profile:
        # profile_applicability contains values like: 'level_1_member_server', 'level_1_domain_controller'
        # Use wildcard partial match so 'member_server' matches 'level_1_member_server'
        prof_val = profile.strip().lower().replace(" ", "_")
        must_clauses.append({
            "wildcard": {
                "metadata.profile_applicability": f"*{prof_val}*"
            }
        })

    if os_filter:
        os_val = os_filter.strip().lower()
        must_clauses.append({"term": {"metadata.source": os_val}})

    if is_automated is not None:
        status_terms = ["automated", "Automated"] if is_automated else ["manual", "Manual"]
        must_clauses.append({"terms": {"metadata.automation_status": status_terms}})

    # Build query
    if must_clauses:
        query = {"query": {"bool": {"filter": must_clauses}}}
    else:
        query = {"query": {"match_all": {}}}

    try:
        response = es.count(index=ES_INDEX, body=query)
        total_count = response["count"]

        # Build readable filter description
        filter_desc = []
        if cis_level:
            filter_desc.append(f"Level: {cis_level.upper()}")
        if profile:
            filter_desc.append(f"Profile: *{profile}*")
        if os_filter:
            filter_desc.append(f"OS: {os_filter}")
        if is_automated is not None:
            filter_desc.append("Status: Automated" if is_automated else "Status: Manual")

        return {
            "total_count": total_count,
            "filters_applied": filter_desc if filter_desc else ["none (all rules)"],
            "answer": f"Found {total_count} CIS Benchmark rules matching filters: {', '.join(filter_desc) if filter_desc else 'all rules'}."
        }

    except Exception as e:
        log.error(f"count_cis_rules failed: {e}")
        return {"error": str(e)}


@mcp.tool()
def list_cis_rules(
    os_filter: Optional[str] = None,
    cis_level: Optional[str] = None,
    profile: Optional[str] = None,
    section: Optional[str] = None,
    is_automated: Optional[bool] = None,
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """
    Retrieve the full list of CIS rules matching criteria using cursor/offset pagination.

    Use this tool when users require:
    - Lists of ALL rules (not just semantically matched top-K)
    - Exporting rule catalogs per OS/level/section
    - Navigating page-by-page ("show the next 50 rules")

    Difference from search_cis_benchmark:
    - search_cis_benchmark -> queries based on semantic relevance (max top-K matches)
    - list_cis_rules       -> pulls ALL matching documents using database paging

    Args:
        os_filter:    Filter by OS platform (e.g., 'windows_server_2022', 'rhel_9').
        cis_level:    Filter by CIS level ('L1' or 'L2').
        profile:      Filter by profile (e.g., 'member_server', 'domain_controller').
        section:      Filter by specific category section prefix (e.g. '18' for Admin Templates, '2' for Local Policies).
        is_automated: True for Automated, False for Manual.
        page:         Page number to retrieve (starts at 1). Default: 1.
        page_size:    Number of rules per page (max 100). Default: 50.

    Returns:
        Dict containing cataloged rules list and pagination details.
    """
    page = max(1, int(page))
    page_size = min(max(1, int(page_size)), 100)
    from_offset = (page - 1) * page_size

    log.info(f"list_cis_rules: os={os_filter} level={cis_level} profile={profile} "
             f"section={section} page={page} page_size={page_size}")
    es = get_es()

    # Build filter clauses
    filter_clauses = []

    if os_filter:
        filter_clauses.append({"term": {"metadata.source": os_filter.strip().lower()}})

    if cis_level:
        lvl_val = cis_level.strip().upper()
        filter_clauses.append({"terms": {"metadata.cis_level": [lvl_val, lvl_val.lower()]}})

    if profile:
        prof_val = profile.strip().lower().replace(" ", "_")
        filter_clauses.append({"wildcard": {"metadata.profile_applicability": f"*{prof_val}*"}})

    if is_automated is not None:
        status_terms = ["automated", "Automated"] if is_automated else ["manual", "Manual"]
        filter_clauses.append({"terms": {"metadata.automation_status": status_terms}})

    if section:
        # Filter by section prefix of rule_id (e.g., section="18" matches "18.x.x.x")
        filter_clauses.append({"prefix": {"rule_id": section.strip() + "."}})

    query_body = {
        "from": from_offset,
        "size": page_size,
        "query": {"bool": {"filter": filter_clauses}} if filter_clauses else {"match_all": {}},
        "_source": ["rule_id", "rule_title", "metadata.cis_level",
                    "metadata.automation_status", "metadata.profile_applicability",
                    "metadata.source"],
        "sort": [{"rule_id": {"order": "asc"}}]
    }

    try:
        response = es.search(index=ES_INDEX, body=query_body)
        total_hits = response["hits"]["total"]["value"]
        hits = response["hits"]["hits"]

        rules_list = []
        for hit in hits:
            src = hit["_source"]
            meta = src.get("metadata", {})
            rid = src.get("rule_id", "")
            # Extract section number from rule_id
            sec_num = rid.split(".")[0] if "." in rid else rid
            rules_list.append({
                "rule_id":    rid,
                "section":    sec_num,
                "cis_level":  meta.get("cis_level", ""),
                "automation": meta.get("automation_status", ""),
                "title":      src.get("rule_title", ""),
            })

        total_pages = (total_hits + page_size - 1) // page_size

        # Build filter description
        filter_desc = []
        if os_filter:   filter_desc.append(f"OS: {os_filter}")
        if cis_level:   filter_desc.append(f"Level: {cis_level.upper()}")
        if profile:     filter_desc.append(f"Profile: *{profile}*")
        if section:     filter_desc.append(f"Section: {section}")

        return {
            "filters_applied":  filter_desc if filter_desc else ["none (all rules)"],
            "total_matching":   total_hits,
            "page":             page,
            "page_size":        page_size,
            "total_pages":      total_pages,
            "has_next_page":    page < total_pages,
            "rules":            rules_list,
            "pagination_hint":  (
                f"Showing {len(rules_list)} of {total_hits} rules "
                f"(page {page}/{total_pages}). "
                f"{'Use page=' + str(page + 1) + ' to fetch the next page.' if page < total_pages else 'This is the last page.'}"
            )
        }

    except Exception as e:
        log.error(f"list_cis_rules failed: {e}")
        return {"error": str(e)}


# CIS Benchmark Section Name Map (nomor section → nama kategori)
_CIS_SECTION_NAMES = {
    "1":  "Account Policies",
    "2":  "Local Policies",
    "3":  "Event Log",
    "4":  "Restricted Groups / System Services",
    "5":  "System Services",
    "6":  "Registry",
    "7":  "File System",
    "8":  "Wired Network Policies",
    "9":  "Windows Firewall",
    "10": "Network List Manager Policies",
    "11": "Wireless Network Policies",
    "12": "Public Key Policies",
    "13": "Software Restriction Policies",
    "14": "Network Access Protection",
    "15": "Application Control Policies",
    "16": "IP Security Policies",
    "17": "Advanced Audit Policy Configuration",
    "18": "Administrative Templates (Machine)",
    "19": "Administrative Templates (User)",
    # RHEL / Linux sections
    "1.1":  "Filesystem Configuration",
    "1.2":  "Software and Patch Management",
    "1.3":  "Mandatory Access Control",
    "1.4":  "Boot Settings",
    "1.5":  "Additional Process Hardening",
    "1.6":  "Mandatory Access Control",
    "1.7":  "Warning Banners",
    "2.1":  "Time Synchronization",
    "2.2":  "Special Purpose Services",
    "2.3":  "Service Clients",
    "3.1":  "Network Parameters (Host Only)",
    "3.2":  "Network Parameters (Host and Router)",
    "3.3":  "IPv6",
    "3.4":  "Uncommon Network Protocols",
    "3.5":  "Firewall Configuration",
    "4.1":  "Configure System Accounting (auditd)",
    "4.2":  "Configure Logging",
    "5.1":  "Configure cron",
    "5.2":  "SSH Server Configuration",
    "5.3":  "Configure PAM",
    "5.4":  "User Accounts and Environment",
    "5.5":  "Root Login",
    "6.1":  "System File Permissions",
    "6.2":  "User and Group Settings",
}


@mcp.tool()
def breakdown_cis_rules(
    os_filter: Optional[str] = None,
    cis_level: Optional[str] = None,
    profile: Optional[str] = None,
) -> dict:
    """
    Retrieve a breakdown of the number of CIS Benchmark rules grouped by category section.

    Use this tool when users ask:
    - "Breakdown of rules per category for Windows 2022"
    - "Show RHEL 9 rule counts by section"
    - "Show the distribution of rules per section"

    Args:
        os_filter: Filter by OS platform (e.g., 'windows_server_2022', 'rhel_9').
        cis_level: Filter by CIS level. Valid values: 'L1', 'L2'.
        profile: Filter by target profile (e.g., 'member_server', 'domain_controller').

    Returns:
        Dict containing rules count breakdown per section/category, ordered by key.
    """
    log.info(f"breakdown_cis_rules: os_filter={os_filter} cis_level={cis_level} profile={profile}")
    es = get_es()

    # Build filter clauses
    filter_clauses = []

    if os_filter:
        filter_clauses.append({"term": {"metadata.source": os_filter.strip().lower()}})

    if cis_level:
        lvl_val = cis_level.strip().upper()
        filter_clauses.append({"terms": {"metadata.cis_level": [lvl_val, lvl_val.lower()]}})

    if profile:
        prof_val = profile.strip().lower().replace(" ", "_")
        filter_clauses.append({"wildcard": {"metadata.profile_applicability": f"*{prof_val}*"}})

    # Build query with script aggregation to extract top-level section from rule_id
    query_body = {
        "size": 0,
        "query": {"bool": {"filter": filter_clauses}} if filter_clauses else {"match_all": {}},
        "aggs": {
            "by_section": {
                "terms": {
                    # Extract the first number before the first dot from rule_id
                    "script": {
                        "source": """
                            def rid = doc['rule_id'].value;
                            def dot = rid.indexOf('.');
                            return dot > 0 ? rid.substring(0, dot) : rid;
                        """,
                        "lang": "painless"
                    },
                    "size": 50,
                    "order": {"_key": "asc"}
                }
            },
            "total_rules": {
                "value_count": {"field": "rule_id"}
            }
        }
    }

    try:
        response = es.search(index=ES_INDEX, body=query_body)
        buckets = response["aggregations"]["by_section"]["buckets"]
        total = response["aggregations"]["total_rules"]["value"]

        # Build human-readable breakdown
        breakdown = []
        for bucket in buckets:
            section_key = bucket["key"]
            count = bucket["doc_count"]
            section_name = _CIS_SECTION_NAMES.get(section_key, f"Section {section_key}")
            pct = round(count / total * 100, 1) if total > 0 else 0
            breakdown.append({
                "section": section_key,
                "name": section_name,
                "count": count,
                "percentage": f"{pct}%"
            })

        # Build filter description
        filter_desc = []
        if os_filter:    filter_desc.append(f"OS: {os_filter}")
        if cis_level:    filter_desc.append(f"Level: {cis_level.upper()}")
        if profile:      filter_desc.append(f"Profile: *{profile}*")

        return {
            "filters_applied": filter_desc if filter_desc else ["none (all rules)"],
            "total_rules": total,
            "breakdown_by_section": breakdown,
            "summary": (
                f"Total of {total} rules distributed across {len(breakdown)} sections. "
                f"Largest section: {breakdown[0]['section']} ({breakdown[0]['name']}) "
                f"with {breakdown[0]['count']} rules ({breakdown[0]['percentage']})."
                if breakdown else "No rules found matching criteria."
            )
        }

    except Exception as e:
        log.error(f"breakdown_cis_rules failed: {e}")
        return {"error": str(e)}


# ======================================================================
# Entry point
# ======================================================================
if __name__ == "__main__":
    log.info("="*60)
    log.info("  CIS Benchmark MCP Server (HTTP transport)")
    log.info(f"  Listening on: http://{MCP_HOST}:{MCP_PORT}/mcp")
    log.info(f"  ES_HOST  : {ES_HOST}")
    log.info(f"  ES_INDEX : {ES_INDEX}")
    log.info("="*60)

    # Pre-load model on startup to prevent slow first requests
    try:
        get_model()
        log.info("Embedding model pre-loaded successfully")
    except Exception as e:
        log.warning(f"Could not pre-load model (will load on first request): {e}")

    mcp.run(
        transport="streamable-http"
    )
