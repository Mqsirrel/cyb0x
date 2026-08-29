# CYB0X TUI/UX Consolidation

## Purpose

This document turns the existing TUI proposal and the Pentesting/eJPTv2 Master Guide into one coherent interaction model.

It is intentionally **not another feature list**. It defines how the existing Cyb0x capabilities should fit together so the application feels like one continuous pentesting workspace rather than five tabs plus a collection of modals.

The implementation must reuse the existing domain, persistence, methodology, runner, and assessment systems. This document does not authorize a parallel state model or a second recommendation engine.

---

# 1. Product Mental Model

The primary object the user is operating is an **investigation workspace**.

```text
LAB
└── ATTEMPT
    ├── TARGETS
    │   ├── SERVICES
    │   ├── CREDENTIALS
    │   ├── SESSIONS
    │   ├── FINDINGS
    │   └── EVIDENCE
    ├── INVESTIGATIONS
    ├── COMMAND RUNS
    └── ACTIVITY
```

The user should not need to think about database records while working.

The TUI is a set of views into this same workspace.

## Primary navigation hierarchy

```text
Lab → Attempt → Target → Investigation → Object
```

Methodology phases remain useful metadata and guidance, but **must not force a linear UI workflow**.

A tester may move freely from HTTP → credential → SMB → another host → back to HTTP.

---

# 2. The Default Screen Is an Investigation Workspace

Do not make the five existing functional tabs the user's main mental model.

The default workbench should provide:

```text
┌────────────────────────────────────────────────────────────────────┐
│ LAB › ATTEMPT › TARGET › SERVICE                    SCOPE ✓         │
├───────────────┬────────────────────────────────────────────────────┤
│ TARGETS       │ NOW                                                │
│               │ HTTP enumeration                                   │
│ ● 10.10.10.20 │                                                    │
│   10.10.10.30 │ BEFORE                                             │
│   10.10.20.5  │ Apache discovered · /backup found                 │
│               │                                                    │
│               │ NEXT                                               │
│               │ → Inspect /backup                                  │
│               │ → Test discovered credential                       │
│───────────────│                                                    │
│ SESSIONS      │ RESULT / DETAILS                                   │
│ www-data      │ 23 paths discovered                                │
│               │                                                    │
│ FINDINGS      │ [Inspect] [Evidence] [Run Again]                   │
├───────────────┴────────────────────────────────────────────────────┤
│ > command...                       Ctrl+K Actions  / Search  ? Help │
└────────────────────────────────────────────────────────────────────┘
```

The exact layout must respond to terminal size. The conceptual hierarchy is the requirement; exact panel dimensions are implementation details.

---

# 3. Persistent Context Is Mandatory

Every normal workspace view should make the active context obvious:

```text
LAB: eJPT-07 › ATTEMPT: #2 › TARGET: 10.10.10.20 › HTTP :80
```

Where useful, also show:

- scope state
- active methodology profile
- active session
- running jobs
- unreviewed result count

Never make the user infer the active target from a selected row several panels away.

---

# 4. NOW / BEFORE / NEXT

The active investigation should expose three compact pieces of orientation.

### NOW
What the user is currently investigating.

### BEFORE
The important observations or events that led to it.

### NEXT
Useful available actions derived from existing assessment state.

Example:

```text
NOW
Investigating SMB access

BEFORE
445/tcp open
backup share discovered
credential bob found

NEXT
→ Enumerate shares
→ Test bob against SSH
→ Inspect backup evidence
```

`NEXT` must use the existing assessment engine where possible. Do not create a duplicate recommendation system in the TUI.

Recommendations should expose a short **WHY** explanation.

```text
NEXT MOVE
Test bob against SSH

WHY
• SSH is open
• bob has not been tested against this host
• credential source is already recorded

[Run] [Inspect] [Ignore]
```

---

# 5. Target 360° Is a Core Primitive

Target 360° should not be treated as merely another details screen.

Selecting a target should immediately expose its operational state:

```text
10.10.10.20
────────────────────────────
Linux · web01 · IN-SCOPE

SERVICES
22 SSH      ENUMERATED
80 HTTP     INVESTIGATING
445 SMB     UNTESTED

ACCESS
No shell

CREDENTIALS
bob
  SSH  ?
  SMB  ✗

FINDINGS
2

SESSIONS
0

REACHABILITY
10.10.20.0/24 reachable

CURRENT INVESTIGATION
HTTP enumeration
```

Every item should be drillable without losing target context.

---

# 6. Results Are Objects, Not Just Terminal Text

A command execution has two layers:

```text
COMMAND
   ↓
RAW OUTPUT
   ↓
STRUCTURED RESULT / OBSERVATIONS
   ↓
UPDATED WORKSPACE STATE
```

Raw stdout/stderr must remain accessible.

But the primary UX should surface useful results as objects.

Example:

```text
RESULT
nmap -sV 10.10.10.20

22/tcp  SSH
80/tcp  HTTP
445/tcp SMB

NEW
+ 3 services

ACTIONS
[Open HTTP]
[Investigate SMB]
[Save Evidence]
[View Raw Output]
```

The parser/state layer owns extraction. The TUI must not invent its own interpretation logic.

---

# 7. Background Jobs and Activity Inbox

Long-running commands must not block the workspace.

Provide a compact job tray:

```text
JOBS
● nmap 10.10.10.20      running
● ffuf /backup           running
✓ whatweb                complete
```

Completed background work should enter an activity stream:

```text
ACTIVITY
16:42  nmap completed
16:42  +3 services discovered
16:44  ffuf completed
16:44  +7 HTTP paths
16:45  credential added
```

New output should be marked **UNREVIEWED** until the user inspects it.

Suggested lifecycle:

```text
NEW → REVIEWED → ACTIONED
             ↘ DISMISSED
```

The user must be able to jump directly from an activity item to its source result.

---

# 8. Investigation State Must Be Visible

Use compact semantic states rather than relying only on color.

```text
? UNKNOWN
→ NEXT
◌ INVESTIGATING
✓ CHECKED
! FINDING
× DEAD END
```

Do not silently convert an observation into a finding.

The UI should distinguish:

```text
Observation
Hypothesis / Lead
Test
Conclusion
```

This is particularly important for the Master Guide's triage and methodology workflow.

---

# 9. Do Not Force Methodology Phases

The Master Guide defines Phase 0–8 and methodology profiles. These remain valuable, but the TUI must treat them as **guidance and coverage**, not a wizard.

Bad:

```text
Phase 2 incomplete → prevent Phase 3
```

Good:

```text
Methodology coverage

Recon       ✓
Enumeration 72%
Initial access —
Pivot        —
```

The user can investigate any valid target/service at any time.

---

# 10. Universal Navigation

Use a small set of global primitives:

```text
Ctrl+K       Command palette
Ctrl+P       Jump/search anything
Ctrl+L       Lab / attempt switcher
Esc          Back / close current layer
? / F1       Contextual help
/            Search/filter current scope
```

Existing single-key shortcuts remain available where they are useful, but **must not be the only way to discover actions**.

Contextual actions should be surfaced from the selected object.

Do not require memorizing 30+ bindings.

---

# 11. Preview, Peek, and Drill Down

Selecting an object should update a preview without immediately navigating away.

Use three levels:

```text
SELECT → PREVIEW
          ↓
        PEEK
          ↓
       OPEN / FOCUS
```

### Preview
Small contextual summary.

### Peek
Temporary detailed inspection overlay.

### Open / Focus
Full-screen or dedicated view for large content such as command output or evidence.

`Esc` must return to the exact previous context.

Avoid deep modal chains.

---

# 12. Universal Search / Jump

Search and jump should work across the assessment workspace:

```text
> 10.10.10.20
> ssh
> bob
> /backup
> finding #2
> command #41
```

Results should be grouped by entity type:

```text
TARGETS
10.10.10.20

SERVICES
22/tcp SSH — 10.10.10.20

CREDENTIALS
bob

FINDINGS
/backup
```

Selecting a result should restore the correct context automatically.

---

# 13. Command UX

The command runner should automatically inherit known context where appropriate:

```text
Target: 10.10.10.20
Service: HTTP
Port: 80
```

The user should not repeatedly type values Cyb0x already knows.

Every execution becomes a durable run record containing, where supported:

- command
- target
- service
- timestamp
- status
- exit code
- stdout/stderr
- associated evidence
- associated investigation

Re-running creates a new execution record.

Never overwrite the previous run.

---

# 14. Run Comparison

Repeated tests should support comparison.

```text
NMAP

Run #1   22 80 445
Run #2   22 80 445 8080

CHANGED
+ 8080/tcp
```

This is particularly valuable when the lab state changes or when the user retries an investigation.

---

# 15. Credentials Need Relationship UX

The credential matrix remains useful, but selecting a credential should show relationships:

```text
CREDENTIAL
bob

SOURCE
10.10.10.20 / backup.txt

TEST MATRIX
              SSH      SMB      MySQL
10.10.10.20    ?        ✗         ✓
10.10.10.30    ✓        ?         —

POTENTIAL NEXT
→ Test SSH on 10.10.10.20
```

The UI should make tested vs untested relationships obvious.

---

# 16. Reachability Is Different From Knowledge

For pivoting, the UI must distinguish:

```text
DISCOVERED
10.10.20.5 exists

REACHABLE
10.10.20.5 can be reached

AUTHENTICATED
credentials accepted

SESSION
interactive access exists

PRIVILEGED
privileged access confirmed
```

Do not collapse these into one `PWNED` state.

Use precise labels such as:

```text
DISCOVERED
ENUMERATED
ACCESS
PRIVILEGED ACCESS
OBJECTIVE ACHIEVED
```

---

# 17. Scratchpad vs Structured State

Keep the scratchpad intentionally low friction.

A note does not need to become a Finding or Lead immediately.

But provide promotion actions:

```text
Scratch note
    ↓
[Create Lead]
[Create Finding]
[Attach to Target]
[Attach to Service]
```

This prevents the user from either over-structuring every thought or losing useful observations.

---

# 18. Attempt UX

Treat attempts as first-class user-facing objects:

```text
LAB: eJPT Lab 07

ATTEMPTS
● Attempt 3   IN PROGRESS
  Attempt 2   COMPLETE
  Attempt 1   COMPLETE
```

Support:

```text
Resume
New Attempt
Clone / Reset
Blind Attempt
Compare Attempts
```

The database implementation is an internal detail.

---

# 19. Attempt Comparison

For training, compare attempts at a high level:

```text
ATTEMPT COMPARISON

                    #1      #2
Hosts discovered     2       3
Services             8      11
Credentials          1       4
Initial access        ✓       ✓
Pivot                 ✗       ✓

Key difference
→ SMB was investigated earlier in Attempt #2
```

Do not reveal hidden solution information in blind mode.

---

# 20. Resume UX

Opening a workspace should not simply reopen the last screen.

It should restore the **working context**:

```text
WELCOME BACK

eJPT Lab 07 · Attempt #2

Last context
10.10.10.20 › HTTP

Last activity
ffuf completed

New
7 unreviewed paths

Suggested continuation
→ Review ffuf results

[Resume] [Review New] [Switch Target]
```

---

# 21. Destructive Actions and Recovery

Confirm only genuinely destructive operations.

Prioritize recovery for:

- deleting evidence
- deleting findings
- resetting attempts
- deleting credentials
- deleting workspaces

Where practical, use undo or a recovery path.

Do not add confirmation dialogs to normal pentesting actions.

---

# 22. Information Density Modes

Support at least three conceptual density levels:

```text
COMPACT
COMFORTABLE
FOCUS
```

The same information architecture remains intact; only presentation density changes.

Large terminals can show multiple panels. Small terminals should collapse to one dominant context with overlays.

---

# 23. Visual Hierarchy

The TUI should visually distinguish:

### Primary
Current target / investigation / action.

### Secondary
Supporting state such as services, credentials and history.

### Tertiary
Metadata, timestamps, counts and technical details.

Avoid making every panel equally prominent.

Avoid giant metric dashboards.

---

# 24. Color and Symbols

Never rely on color alone.

Preferred semantic symbols:

```text
✓ confirmed / checked
? unknown / untested
→ next action
! attention / finding
× failed / dead end
● running
```

Themes may change colors, but semantic meaning must remain readable without them.

---

# 25. Mouse Support

Keyboard remains primary.

Mouse should naturally support:

- selecting objects
- clicking actions
- scrolling
- opening previews
- interacting with tables and trees

No important operation should be mouse-only.

---

# 26. What the TUI Must NOT Become

Do not turn Cyb0x into:

- an eJPT tutorial
- a wizard that forces a methodology order
- a giant analytics dashboard
- a terminal emulator replacement
- an AI chat application
- a graph-heavy attack-path visualizer by default
- a collection of unrelated screens
- a second persistence/state system
- a second recommendation engine

The TUI is an interface over the existing assessment state and methodology systems.

---

# 27. Implementation Rules

Before modifying the UI, audit the existing implementation in:

```text
src/synapse/tui/
src/synapse/models.py
src/synapse/assessment/
src/synapse/db/
src/synapse/runner/
src/synapse/methodology/
```

The current application already has a Textual TUI, five functional views, cached workspace snapshots, asynchronous command execution, methodology profiles, target/service selection, and assessment actions. The redesign must preserve those capabilities rather than recreate them. 

### Required implementation order

1. **Context model in the UI** — active lab/attempt/target/service/session.
2. **Workspace navigation and back stack.**
3. **Target 360° / preview / peek behavior.**
4. **Now / Before / Next orientation.**
5. **Command result + job tray + activity/unreviewed results.**
6. **Universal search/jump and command palette.**
7. **Responsive/density behavior.**
8. **Attempt resume/compare UX.**
9. **Polish, accessibility, mouse support and themes.**

Do not implement every item simultaneously.

---

# 28. Acceptance Journeys

The redesign is successful only if these journeys feel fast and natural.

## Journey A — Start a lab

```text
Open Cyb0x
→ choose/create lab
→ choose/new attempt
→ see active workspace
→ add/select target
→ begin investigation
```

## Journey B — Discover a service

```text
Run scan
→ background job
→ result appears
→ new service becomes visible
→ select service
→ preview
→ run relevant action
```

## Journey C — Find a credential

```text
Record credential
→ credential appears in workspace
→ inspect relationships
→ identify untested target/service
→ test
→ result recorded
```

## Journey D — Background result

```text
Launch long command
→ continue working
→ command completes
→ activity indicator appears
→ open result
→ review
→ act / dismiss
```

## Journey E — Switch targets

```text
Ctrl+P / target picker
→ choose target
→ context changes
→ previous target state remains intact
→ Esc returns to previous context
```

## Journey F — Resume

```text
Open lab
→ resume prompt
→ see last target/investigation
→ see new/unreviewed work
→ continue
```

## Journey G — Learn from retry

```text
Attempt 1
→ complete/stop
→ New Attempt
→ work independently
→ Compare Attempts
→ identify process improvement
```

---

# 29. UX Quality Gate

Before calling the redesign complete, manually verify:

- Can the user always identify the active target?
- Can the user always get back without losing context?
- Can a user discover actions without memorizing shortcuts?
- Can a background command finish without interrupting work?
- Can new results be found and marked reviewed?
- Can the user distinguish observation, hypothesis and confirmed finding?
- Can the user switch targets without losing state?
- Can the user rerun a command without destroying its previous result?
- Can the user understand why a suggested next action appeared?
- Can the user resume an old lab immediately?
- Can a second attempt remain isolated from the first?
- Does the interface remain usable on a small terminal?
- Does the interface remain fast on a large terminal?
- Can all important state be understood without color?
- Does the TUI expose existing state rather than maintaining a competing state model?

If several answers are no, do not compensate by adding more features. Fix the interaction model first.

---

# Final Design Principle

> **Cyb0x should feel like one continuous investigation, not five tabs.**

The user should always know:

```text
WHERE AM I?
WHAT DO I KNOW?
WHAT JUST CHANGED?
WHAT AM I INVESTIGATING?
WHAT CAN I DO NEXT?
```

Everything else is secondary.

---

# Appendix A: Implementation Status Matrix & Rejection Register

> Synthesizes `TUI_UX_PROPOSAL.md`, `CORE_SYSTEM_PROPOSAL_HONEST_REVIEW.md`, `EJPTV2_LAB_WORKSPACE_PROPOSAL.md`, and live implementation state as of v0.9.x.

| Component / Proposal Idea | Source | Status | Value | Complexity | Verdict |
|---|---|---|:---:|:---:|---|
| Persistent Multi-Tab Workspace | `TUI_UX_PROPOSAL` | **IMPLEMENTED** | 10 | 4 | **Retained** |
| Target 360° Operational Card | `TUI_UX_PROPOSAL` | **IMPLEMENTED** | 10 | 3 | **Retained** |
| Searchable Command Palette (`Ctrl+K`) | `TUI_UX_PROPOSAL` | **IMPLEMENTED** | 10 | 3 | **Retained** |
| Fuzzy Entity Jump (`Ctrl+P`) | `TUI_UX_PROPOSAL` | **IMPLEMENTED** | 9 | 3 | **Retained** |
| In-App Lab / Workspace Switcher (`Ctrl+L`) | `EJPTV2_LAB_PROPOSAL` | **IMPLEMENTED** | 10 | 4 | **Retained** |
| Persistent Markdown Scratchpad (`.`) | `TUI_UX_PROPOSAL` | **IMPLEMENTED** | 9 | 2 | **Retained** |
| Persistent Command Execution Logging (v4) | `CORE_SYSTEM_PROPOSAL` | **IMPLEMENTED** | 10 | 3 | **Retained** |
| Real-Time CTF/OffSec Flag Extraction | `CORE_SYSTEM_PROPOSAL` | **IMPLEMENTED** | 10 | 2 | **Retained** |
| Deterministic Next-Action Triage (`n`) | `CORE_SYSTEM_PROPOSAL` | **IMPLEMENTED** | 10 | 4 | **Retained** |
| Rabbit-Hole / "I'm Stuck" Detection (`s`) | `CORE_SYSTEM_PROPOSAL` | **IMPLEMENTED** | 9 | 3 | **Retained** |
| Credential Lifecycle Cycling (`t`) | `EJPTV2_LAB_PROPOSAL` | **IMPLEMENTED** | 9 | 3 | **Retained** |
| Environment Doctor CLI (`synapse doctor`) | `TUI_UX_PROPOSAL` | **IMPLEMENTED** | 9 | 2 | **Retained** |
| *Top-Level "Engagement" Rename* | `CORE_SYSTEM_PROPOSAL` | **REJECTED** | 2 | 7 | Workspace model already covers this |
| *Full Event Sourcing & Timeline Replay* | `CORE_SYSTEM_PROPOSAL` | **REJECTED** | 4 | 9 | Command logging + evidence timestamps suffice |
| *AI-Only LLM Recommendation Copilot* | `CORE_SYSTEM_PROPOSAL` | **REJECTED** | 3 | 8 | Deterministic rules are faster, offline, zero-cost |
| *Dynamic ASCII Network Topology Graph* | `TUI_UX_PROPOSAL` | **DEFERRED (v1.1)** | 6 | 7 | Pivot Sentinel tab meets current needs |

---

# Appendix B: Operational State Machine Diagrams

### Target Lifecycle
```text
DISCOVERED (○) ──[Port Scan]──> ENUMERATED (●) ──[Exploit]──> FOOTHOLD (★) ──[Privesc]──> PWNED (✔)
```

### Checklist Item State
```text
TODO [?] ──[r: Execute]──> RUNNING [⟳] ──┬──> CHECKED [✔]
                                          ├──> FINDING [⚡]
                                          └──> DEAD_END [✖]
```

### Credential Testing Lifecycle
```text
UNTESTED (dim) ──[t: Cycle]──┬──> VALID ACCESS [green]
                             └──> INVALID [red]
```

---

# Appendix C: Theme & Palette Governance

All UI elements must use canonical palette constants from `src/synapse/tui/theme.py`:

```python
BACKGROUND     = "#1E1B18"  # Dark charcoal base
SURFACE_RAISED = "#26221E"  # Panel and card surface
TERRACOTTA     = "#D97757"  # Primary accent & action focus
SAGE           = "#8FA876"  # Success, pwned, confirmed valid access
KRAFT          = "#C2B4A3"  # Secondary text & exploratory chips
CREAM          = "#EDE6DA"  # Primary foreground text
MUTED          = "#8C8275"  # Dimmed borders & inactive labels
ERROR_RED      = "#E06C75"  # Critical findings & invalid auth
```

**Prohibition**: No hardcoded ANSI escapes or unmapped hex codes in widget render methods.

---

# Appendix D: Responsive Viewport Guidelines

```text
Compact  (80x24)  → Modal: width 70, height 20
Standard (120x36) → Modal: width 96, height 30
Wide     (160x45) → Modal: width 110, height 36
```

- `#stats-banner`: `height: 2` with `border-bottom: solid $panel`.
- Footer key hints: max 78/80 cols on compact viewport; 8 universal power bindings visible.
- Scrollable lists: `height: 1fr` or explicit max-heights inside dialog containers.

---

# Appendix E: Future Roadmap (v1.1+)

- [ ] Dual-Pane Interactive Command Runner (split-terminal PTY alongside methodology tree)
- [ ] Automated BloodHound / SharpHound JSON Ingestion into Credential Matrix & Pivot Sentinel
- [ ] Custom Checklist YAML Editor (in-TUI modal for per-engagement methodology checks)
- [ ] Subnet ASCII Topology Visualizer (reactive graph of pivot paths in Tab 5)

---

# Appendix F: Verification Record

- **Schema**: Version 4 (forward migrations validated).
- **Test Suite**: 173 passed, 2 skipped (`uv run pytest`).
- **Modal Geometry**: Verified zero overflow on 80x24, 120x36, 160x45.
- **Theme Scan**: 0 raw ANSI tags or hardcoded background hexes remaining.