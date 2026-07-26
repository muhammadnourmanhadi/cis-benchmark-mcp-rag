---
name: cis-benchmark-search
description: Search CIS Benchmark (Windows Server & RHEL) security guidelines via Elasticsearch semantic search
version: 1.0.0
metadata:
  hermes:
    tags: [security, compliance, cis, elasticsearch, rag]
    category: security
---

# CIS Benchmark Search

This skill enables hybrid semantic vector searches against the CIS Benchmark database indexed inside Elasticsearch, covering **Windows Server 2016/2019/2022** and **RHEL 7/8/9**.

## When to Use This Skill

Activate this skill when user queries ask about:
- OS security configurations (Windows Server or RHEL/Linux)
- Password policies, account lockout parameters, audit policies
- Firewall rules, network security settings
- Service hardening (disabling services, file system permissions)
- CIS compliance checklists
- Comparing recommendations across different OS versions

## Tools Reference

You have access to the following tools from the `cis-benchmark` MCP server:

1. **`search_cis_benchmark`**
   - **Purpose**: Search for relevant guidelines using hybrid Semantic Vector Search and metadata pre-filtering.
   - **Usage**: Content-oriented questions (e.g., *"What is the password length requirement?"*, *"How do I harden SSH?"*).
   - **Arguments**:
     - `query` (string, required): Search query topic (e.g., "password policy").
     - `cis_level` (string, optional): Target CIS Level ('L1' or 'L2').
     - `profile` (string, optional): Profile filter (e.g., 'domain_controller', 'member_server', 'server', 'workstation').
     - `is_automated` (boolean, optional): Automation status filter (True/False).
     - `os_filter` (string, optional): OS platform code (e.g., "windows_server_2022").
     - `top_k` (integer, optional): Number of rules to retrieve (max 20, default 5).

2. **`count_cis_rules`**
   - **Purpose**: Calculate exact counts of rules matching specific metadata filters.
   - **Usage**: Quantity or statistics questions (e.g., *"How many L1 member server rules exist for Windows 2022?"*, *"How many rules are automated?"*).
   - **Arguments**:
     - `cis_level` (string, optional): 'L1' or 'L2'.
     - `profile` (string, optional): 'member_server', 'domain_controller', etc. (partial matches allowed).
     - `os_filter` (string, optional): 'windows_server_2022', 'rhel_9', etc.
     - `is_automated` (boolean, optional): True/False.

3. **`breakdown_cis_rules`**
   - **Purpose**: Group rule distributions by primary numbered sections using script aggregation.
   - **Usage**: Breakdown queries (e.g., *"Show the breakdown of RHEL 9 rules by section"*).
   - **Arguments**:
     - `os_filter` (string, optional): 'windows_server_2022', 'rhel_9', etc.
     - `cis_level` (string, optional): 'L1' or 'L2'.
     - `profile` (string, optional): target profile.

4. **`list_cis_rules`**
   - **Purpose**: Fetch paginated catalogs of rules matching criteria without hitting token limit context.
   - **Usage**: Incremental listing requests (e.g., *"List all Windows 2022 L1 rules"*).
   - **Arguments**:
     - `os_filter` (string, optional): target OS.
     - `cis_level` (string, optional): 'L1' or 'L2'.
     - `profile` (string, optional): target profile.
     - `section` (string, optional): prefix filter (e.g., "18").
     - `page` (integer, optional): page number to retrieve.
     - `page_size` (integer, optional): items per page (max 100, default 50).

5. **`list_available_sources`**
   - **Purpose**: Return active indexed platforms along with their respective rule counts.
   - **Arguments**: None.

6. **`get_cis_statistics`**
   - **Purpose**: Return quick global count details and L1/L2 distribution statistics.
   - **Arguments**:
     - `os_filter` (string, optional): target platform.

## Routing Guide — Which Tool to Call?

| User Query Scenario | Target Tool to Call |
|---|---|
| "What is the policy config for password length?" | `search_cis_benchmark` |
| "How do I secure SSH services on Linux?" | `search_cis_benchmark` |
| "How **many** L1 member server rules in Windows 2022?" | `count_cis_rules` |
| "What is the **total** count of automated RHEL 9 rules?" | `count_cis_rules` |
| "**Breakdown** rules per category in Windows 2022" | `breakdown_cis_rules` |
| "**Distribution** of rules per section for L1 RHEL 9" | `breakdown_cis_rules` |
| "Show a **list of all** Windows 2022 L1 rules" | `list_cis_rules` |
| "Fetch the **next 50 rules** / page 2" | `list_cis_rules` (page=2) |
| "List all rules under section 18" | `list_cis_rules` (section="18") |
| "Which platforms are indexed in the database?" | `list_available_sources` |
| "Provide a global audit **statistics** report" | `get_cis_statistics` |

## Response Orchestration Procedure

1. **Identify the query type** using the routing guide table above.
2. **Execute the corresponding tool** with appropriate parameters:
   - Platform mentioned → pass `os_filter` (e.g., `windows_server_2022`).
   - Security level mentioned → pass `cis_level` (`L1` or `L2`).
   - Profile mentioned → pass `profile` (e.g., `member_server`, `domain_controller`).
3. **Format the answer** using the recommended templates below.

## Recommended Response Formats

**For content queries (search_cis_benchmark):**
```
According to **[rule_title]** (Rule ID: [rule_id]):

**Audit:** [audit_text]

**Remediation:** [remediation_text]

📄 Applicability: [profile_applicability]
```

**For counts (count_cis_rules):**
```
Found **[total_count] rules** matching the criteria: [filter_applied].
```

**For breakdowns (breakdown_cis_rules):**
```
Breakdown of rules per section:
| Section | Category Name | Rules Count | Percentage |
|---|---|---|---|
| 1 | Account Policies | 12 | 5.2% |
| 18 | Administrative Templates | 210 | 48.5% |
```

## Pitfalls to Avoid

- Do not use `search_cis_benchmark` to count rules (semantic searches are limited to top-K matches).
- Do not use `get_cis_statistics` for section breakdowns (it only returns global L1/L2 statistics).
- Profile arguments support partial matching (e.g., passing `member_server` will successfully match `level_1_member_server`).

## Verification

Confirm tool functionality by calling:
```
list_available_sources()
```
The output should return the registered active platforms and total documents.
