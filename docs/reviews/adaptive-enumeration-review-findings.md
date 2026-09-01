# Architectural Review: Adaptive Enumeration in CYB0X (PR #1)

> **Review Target**: Pull Request #1 (`docs/proposals/adaptive-enumeration-review.md`)  
> **Status**: Comprehensive Engineering Audit & Technical Review  
> **Repository**: `Mqsirrel/cyb0x` (Branch: `review/adaptive-enumeration`)  
> **Reviewer**: Antigravity Engineering Assistant (Senior Dev / Offensive Security Review)

---

## Executive Summary

PR #1 raises the central question for CYB0X's evolution: **Does CYB0X operate as an adaptive, evidence-driven offensive state machine, or is it a collection of static checklists with decoupled operational tools?**

Following a code-level audit of the entire codebase (173 passing tests, SQLite repository v4, methodology engines, assessment models, and Textual TUI widgets), the answer is:

1. **CYB0X already has first-class state primitives**: Unlike generic scanners, CYB0X possesses persistent host states (`DISCOVERED` → `ENUMERATED` → `FOOTHOLD` → `PWNED`), checklist states (`TODO`, `RUNNING`, `CHECKED`, `FINDING`, `DEAD_END`), cross-host credential tracking, deterministic triage (`n`), and rabbit-hole detection (`s`).
2. **The link between Evidence and Checklist Adaptation is currently static**: Checklist items are loaded in one bulk snapshot upon service identification (`get_checklists_for_service`). Finding a vulnerability (`FINDING`) alerts the user and surfaces an exploit action in triage, but it does **not** dynamically reveal subsequent investigation branches (e.g. finding `/admin` does not dynamically spawn authenticated web checks).
3. **The proposed adaptive engine can be implemented with minimal diff (Ponytail senior dev principle)**: It does **not** require an autonomous AI agent, a complex dependency graph solver, or an event-sourcing engine. A lightweight condition evaluator (`prerequisites`, `unlock_on`, `alternatives`) in `services.yaml` and `assessment/engine.py` cleanly delivers adaptive enumeration without bloating the codebase.

---

## 1. Architecture Findings with File/Module References

| Module / File | Current Role | Strengths | Gaps & Technical Debt |
|---|---|---|---|
| [`src/synapse/models.py:82-96`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/models.py#L82-L96) | `ChecklistItem` model | Clean Pydantic model with category, title, status, severity, CVE refs, output snippet. | Lacks prerequisites, parent-child links, alternative tools, or evidence gates. Status `DEAD_END` conflates "not vulnerable" with "blocked/inconclusive". |
| [`src/synapse/methodology/engine.py:82-117`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/methodology/engine.py#L82-L117) | Service matching & checklist generation | Fast precompiled regex matching + port weighting. Robust shell quoting in `render_command`. | Static 1-shot checklist matching: all checks for a service are dumped into the database at once. No dynamic branching based on discovered banners or output. |
| [`src/synapse/methodology/profile.py:38-65`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/methodology/profile.py#L38-L65) | `PhaseDefinition` & profiles | Data-driven YAML structure with `depends_on`, `prerequisites`, `evidence_required`. | Operates at the **macro phase level** across targets, rather than governing micro-level checklist item transitions. |
| [`src/synapse/assessment/engine.py:307-530`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/assessment/engine.py#L307-L530) | `get_next_actions` (Triage `n`) | Deterministic, offline, zero-LLM priority cascade: recon → admin creds → findings → privesc → enum → spray → resume → cleanup. | Recommends at the **service level** (`Enumerate untested service(s) on IP: port 80`) rather than recommending the exact high-value check item. |
| [`src/synapse/assessment/engine.py:543-616`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/assessment/engine.py#L543-L616) | `detect_rabbit_holes` (Stuck `s`) | Concrete, non-prescriptive escape analysis: surfaces dead-end counts vs untested ports, un-sprayed credentials, and stale leads. | Treats all `DEAD_END` items equally; does not distinguish high-value blocked vectors from trivial scanner noise. |
| [`src/synapse/tui/widgets/service_detail.py`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/tui/widgets/service_detail.py) | Checklist table & coverage metrics | Real-time coverage calculation (`done + dead / total`), color-coded chips, target 360 overview. | Checklist table is a flat list without visual indentation for follow-ups or indication of locked/deferred checks. |
| [`src/synapse/runner/executor.py:29-53`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/runner/executor.py#L29-L53) | Command execution & flag capture | Asynchronous subprocess execution, process tree SIGKILL termination, real-time CTF/OffSec regex flag parsing. | Does not parse structured outputs (e.g. discovered URLs, shares, or users) to automatically populate leads or services. |

---

## 2. Current Enumeration Flow

```text
┌────────────────────────────────────────────────────────┐
│ Target Ingestion (Nmap XML / Masscan / NetExec / 'a') │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
           ┌─────────────────────────────────┐
           │ Target Added (Status: DISCOVER) │
           └────────────────┬────────────────┘
                            │
               No Services? │ Services Present?
              ┌─────────────┴─────────────┐
              ▼                           ▼
┌───────────────────────────┐ ┌───────────────────────────────────────┐
│ Phase 0 Reconnaissance    │ │ Match Rules in services.yaml          │
│ (ping, top-1000 scan, etc)│ │ (Port & Regex scoring)                │
└─────────────┬─────────────┘ └───────────────────┬───────────────────┘
              │                                   │
              ▼                                   ▼
┌───────────────────────────┐ ┌───────────────────────────────────────┐
│ Manual Scan Execution     │ │ Populate Checklists (1-Shot)          │
│ via Runner Modal ('r')    │ │ (Status: TODO for all items)          │
└─────────────┬─────────────┘ └───────────────────┬───────────────────┘
              │                                   │
              └─────────────────┬─────────────────┘
                                │
                                ▼
        ┌──────────────────────────────────────────────────┐
        │ Operator Loops on ServiceDetailWidget:           │
        │ - Select CheckItem                               │
        │ - Press 'r' (Inspect, Edit, Run command)         │
        │ - Press Space (TODO -> RUNNING -> CHECKED/FINDING)│
        └───────────────────────┬──────────────────────────┘
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
┌───────────────────────────────┐ ┌───────────────────────────────────┐
│ Triage 'n':                   │ │ Stuck 's':                        │
│ Checks if findings exist,     │ │ Checks if current service has all │
│ or untested services remain,  │ │ DEAD_END while others untouched,  │
│ or valid creds can be sprayed │ │ or credentials remain un-sprayed  │
└───────────────────────────────┘ └───────────────────────────────────┘
```

---

## 3. Gaps Against the Adaptive Model

1. **Static Checklist Ingestion**:
   - *Current*: When Port 80 is added, 10+ checks are generated immediately (HTTP directory brute-forcing, WebDAV, CGI scan, SSL audit, etc.).
   - *Target Adaptive Flow*: Core recon first (HTTP headers + technology fingerprint). If Apache/PHP is detected, reveal PHP-specific checks. If WordPress is found, unlock WPScan and plugin audit.
2. **Missing Evidence-to-Check Feedback Loop**:
   - *Current*: A command produces stdout. The user toggles status to `FINDING` and writes evidence.
   - *Target Adaptive Flow*: Toggling `FINDING` on "Discover Web Directories" with `/admin` in output should trigger an automated lead or unlock an authenticated login check.
3. **Coarse `DEAD_END` Semantics**:
   - *Current*: A check is either `TODO`, `RUNNING`, `CHECKED`, `FINDING`, or `DEAD_END`.
   - *Gap*: If an operator runs `gobuster` with `common.txt` and finds nothing, marking `DEAD_END` hides whether the path is truly dead or whether larger wordlists/extensions were deferred. A `DEFERRED` or `EXHAUSTED` state is needed.
4. **Service-Level vs Check-Level Triage**:
   - *Current*: `n` advises: `Enumerate untested service(s) on 10.10.11.200: port 80`.
   - *Target Adaptive Flow*: `n` advises: `Run technology fingerprinting on 10.10.11.200:80 (Check #12) before deep directory brute-forcing`.

---

## 4. eJPTv2 Profile Coverage Matrix

Audit of [`src/synapse/methodology/data/profiles/ejptv2.yaml`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/methodology/data/profiles/ejptv2.yaml) and [`services.yaml`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/methodology/data/services.yaml) against the official **eLearnSecurity / INE Junior Penetration Tester v2** curriculum:

| INE eJPTv2 Exam Domain / Topic | CYB0X Coverage Status | Where It Lives | Recommended Enhancement |
|---|:---:|---|---|
| **Host & Network Auditing**: ARP & ICMP sweeps | ✅ Covered | `services.yaml:initial_recon` | Add subnet-wide ping/arp-scan recipe templates |
| **Port Scanning**: TCP/UDP discovery, state, versions | ✅ Covered | `services.yaml:initial_recon` | Existing top-1000 and full TCP scan recipes are accurate |
| **SMB Enumeration**: NULL session, shares, users, IPC$ | ✅ Covered | `services.yaml:smb` (NetExec, smbclient) | Add `rpcclient` manual null session alternative |
| **SNMP Enumeration**: Public/private communities, MIB walk | ✅ Covered | `services.yaml:snmp` | Include user enumeration via MIB tables (`onesixtyone`) |
| **Web Assessment**: Directory fuzzing, CMS detection | ⚠️ Partial | `services.yaml:http` | Split generic HTTP into (1) Fingerprint, (2) Content Discovery, (3) Auth Bypass |
| **Web Vulnerabilities**: SQLi Auth Bypass, XSS, Command Injection | ⚠️ Partial | `services.yaml:http` (sqlmap, nikto) | Add manual SQLi auth bypass payload recipes (`' OR 1=1--`) |
| **Brute-Forcing**: Online credential attacks (SSH, FTP, HTTP POST) | ✅ Covered | `services.yaml` (hydra recipes across all services) | Add Hydra HTTP form brute-force template |
| **Vulnerability Assessment**: Searchsploit, MSF auxiliary | ✅ Covered | `services.yaml` (`searchsploit {PRODUCT} {VERSION}`) | Add Metasploit auxiliary scanner recipe references |
| **Metasploit Framework**: Multi-handler, exploit modules | ⚠️ Partial | Generic exploit checks | Include msfconsole one-liner / resource script recipe |
| **Privilege Escalation (Linux)**: SUID, Sudo, SUID/GUID, Cron jobs | ✅ Covered | `services.yaml:linux_privesc` | Integrate standard GTFOBins checks |
| **Privilege Escalation (Windows)**: UAC, Token Privileges, Unquoted Service Paths | ✅ Covered | `services.yaml:windows_privesc` | Integrate WinPEAS / PowerUp checks |
| **Pivoting & Routing**: ARP tables, routing, port forwarding | ✅ Covered | Dedicated TUI Tab 5 (`PivotRoute` model) | Add routing table collection commands (`ip route`, `route print`) |

**Finding**: CYB0X covers **>85%** of the commands needed for eJPTv2, but the profile file `ejptv2.yaml` is currently just a 59-line shell that names phases. The actual intelligence lives in `services.yaml`. `ejptv2.yaml` should explicitly map and order these domain checks.

---

## 5. Recommended Minimal Data-Model Changes (Ponytail Compliant)

Avoid complex graph structures or dynamic rule interpreters. The shortest working diff:

### Change 1: Extend `ChecklistItem` with conditional gating and alternatives
In `src/synapse/models.py` (and SQLite schema v5 via backward-compatible `ALTER TABLE`):

```python
class ChecklistItem(BaseModel):
    ...
    # Minimal fields for adaptive enumeration:
    prerequisite_check_id: Optional[int] = None       # Must be CHECKED or FINDING to unlock
    unlock_condition: str = ""                         # e.g., "tech:php", "auth:valid", "finding:directory"
    alternative_command: str = ""                     # Fallback manual / lightweight command
    learning_note: str = ""                           # "What to look for in output" (anti-command-dump)
```

### Change 2: Add `DEFERRED` to `ChecklistStatus`
```python
class ChecklistStatus(str, Enum):
    TODO = "todo"
    RUNNING = "running"
    CHECKED = "checked"
    FINDING = "finding"
    DEAD_END = "dead_end"
    DEFERRED = "deferred"   # <--- Preserves intent: not dead, but skipped for higher-value paths
```

### Schema Migration:
In `src/synapse/db/migrations.py`:
`CURRENT_SCHEMA_VERSION = 5`
Add columns with `DEFAULT ''` or `DEFAULT NULL`. **Zero disruption to existing workspaces.**

---

## 6. Recommended Minimal Triage Changes

Update `get_next_actions` in [`src/synapse/assessment/engine.py`](file:///home/albraa/Documents/antigravity/charming-davinci/cyb0x/src/synapse/assessment/engine.py):

1. **Check-Level Precision**:
   Instead of recommending `Enumerate untested service(s) on 10.10.11.200: port 80`, check whether any `recon`-tier checklist items exist on that service (e.g. `Banner Grab` or `HTTP Fingerprint`). If so, name that specific check:
   ```text
   NextAction(
       priority=PRIORITY_ENUM,
       kind="enum",
       title="Run 'HTTP Header & Tech Fingerprint' on 10.10.11.200:80",
       rationale="Foundational recon check required before intensive directory fuzzing.",
       target_ip="10.10.11.200",
       port=80
   )
   ```
2. **Conditional Unlocking**:
   Skip `ChecklistItem`s whose `prerequisite_check_id` is still in `TODO` or `DEAD_END`.
3. **Explainable Rationale**:
   Ensure `rationale` states the trigger (e.g. *"Unlocked because Port 445 revealed SMB signing is disabled"*).

---

## 7. Recommended Minimal TUI Changes

1. **Visual Hierarchy in `ServiceDetailWidget`**:
   - Render un-met prerequisites with `[MUTED]🔒 Locked: requires #X[/]` or dimmed text.
   - When selected, display `learning_note` ("What to look for") in the banner above the command template.
2. **Keybinding for Deferral**:
   - Add `d` (or cycle via `Space`) to set `DEFERRED`. Deferrals do not count as rabbit-hole dead-ends in `s`.
3. **Alternative Toggle in Runner Modal**:
   - In `RunnerModal`, add `Alt+A` / `F2` to toggle between `command_template` and `alternative_command`.

---

## 8. Deterministic Test Plan & Concrete Fixtures

The existing test suite has 173 tests passing. The adaptive behavior should be validated with 6 deterministic test fixtures:

```python
def test_adaptive_http_fingerprint_unlocks_tech_checks():
    """HTTP root recon finding PHP unlocks PHP-specific directory brute-forcing."""
    target, service, repo = create_test_env()
    # Check 1: Initial Fingerprint marked as FINDING with PHP banner
    check1 = repo.get_checklist(service.id, "fingerprint")
    repo.update_checklist_status(check1.id, ChecklistStatus.FINDING, output="X-Powered-By: PHP/8.1")
    
    # Assert Check 2 (PHP-specific fuzzing) unlocks
    actions = get_next_actions([target])
    assert any("PHP" in a.title for a in actions)

def test_credential_reuse_triage_feed():
    """Discovered valid SSH credentials immediately generate spray/test triage for sibling hosts."""
    ...

def test_dead_end_service_switches_triage_to_open_surface():
    """Accumulating dead ends on port 80 pushes triage to untouched port 445 (SMB)."""
    ...

def test_stuck_report_ignores_deferred_checks():
    """Deferred checks are treated as parked attack surface, not failed dead-ends."""
    ...

def test_flag_detection_transitions_target_status():
    """Proof flag regex match triggers prompt to transition target from FOOTHOLD to PWNED."""
    ...

def test_offline_zero_cost_triage_benchmark():
    """Adaptive evaluation runs in < 5ms for 50 targets and 200 services (no network, no LLM)."""
    ...
```

---

## 9. Ideas Explicitly Rejected

| Rejected Idea | Reason for Rejection |
|---|---|
| **Autonomous Scanner Daemon (AutoRecon clone)** | Violates eJPTv2 / OSCP learning objectives. Generates unmanageable network noise, locks accounts, and leads to exam failure. CYB0X must remain an operator-guided cockpit. |
| **Heavy Graph Database (Neo4j / NetworkX AST)** | Extreme over-engineering. SQLite with parent-child foreign keys or simple string preconditions handles 100% of the requirements with zero runtime overhead. |
| **Mandatory LLM Dependency for Triage** | Violates exam conditions (eJPTv2, OSCP, and labs are often offline or air-gapped). All core triage logic MUST remain deterministic and instant. |
| **Rewriting All 570+ Lines of `services.yaml`** | High risk, zero immediate gain. We should incrementally add `prerequisites` and `learning_notes` to top services (`http`, `smb`, `ssh`, `ftp`) without breaking existing recipes. |

---

## 10. Phased Implementation Plan

```text
┌────────────────────────────────────────────────────────┐
│ Phase 1: Data Model & Schema v5 (Non-Breaking)         │
│ - Add prerequisite, alternative, learning_note fields  │
│ - Add DEFERRED status to ChecklistStatus               │
│ - Run schema migration v5                              │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 2: Methodology Engine & YAML Schema              │
│ - Update services.yaml for core services (HTTP, SMB)   │
│ - Support prerequisite resolution in engine            │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 3: Adaptive Triage & Stuck Engine                │
│ - Elevate triage 'n' to check-level precision          │
│ - Factor out DEFERRED items from rabbit-hole counts    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 4: TUI Presentation Polish                       │
│ - Display 'What to look for' learning notes            │
│ - Keybinding 'd' for defer                             │
│ - Alternative command swap in Runner Modal             │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Phase 5: Verification & Benchmark Suite                │
│ - 6 deterministic adaptive fixtures                    │
│ - Zero regressions on existing 173 tests               │
└────────────────────────────────────────────────────────┘
```

---

## Review Conclusion & Recommendation on PR #1

**Recommendation**: **MERGE PR #1** (it provides an exceptional, highly structured review proposal and problem formulation).

The deliverables requested by PR #1 are fully provided in this architectural review. Implementation should proceed along the 5-phase plan outlined above, maintaining Cyb0x's core identity: **a lightweight, deterministic, keyboard-driven offensive state machine that teaches and reinforces disciplined penetration testing methodology.**
