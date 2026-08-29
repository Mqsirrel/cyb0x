# Cyb0x Core System Evolution Proposal — Needs Honest Review

> **Status: Proposal / review only.**
>
> This document intentionally contains ideas that may be useful, unnecessary, overlapping with existing Cyb0x capabilities, or architecturally too ambitious. **Do not implement this proposal as-is.** Audit the current repository first, validate the real eJPTv2 workflow, and reject ideas that do not materially improve the product.

## Why this exists

Cyb0x already contains substantial assessment, methodology, execution, persistence, parser, evidence, export, AI-advisor, lab, and TUI functionality. The concern is not simply missing features.

The larger question is whether all of those pieces form a coherent pentesting/training environment:

```text
What do I know?
What have I tried?
What can I prove?
What remains unknown?
What should I investigate next?
Why does Cyb0x believe that?
```

This proposal explores ideas around that system-level experience.

---

# 1. Engagement as the Top-Level Concept

Consider whether `Lab` should remain the highest-level abstraction or whether an `Engagement`/`Assessment` concept is more appropriate.

Potential model:

```text
Engagement
├── Scope
├── Objectives
├── Rules / constraints
├── Targets
├── Methodology
├── Assessment state
├── Commands / sessions
├── Findings
├── Evidence
├── Timeline
├── Attempts
└── Reports
```

**Honest review:** This may be unnecessary if the current workspace model already expresses these relationships cleanly. Do not rename core concepts merely for terminology.

---

# 2. Explicit Assessment State

A major possible improvement is distinguishing states such as:

```text
UNKNOWN
DISCOVERED
ENUMERATED
TESTED
CONFIRMED
FAILED
NOT_APPLICABLE
STALE
```

Example:

```text
10.10.10.20 / HTTP

✓ Service discovered
✓ Banner collected
✓ Directory enumeration completed
? Authentication behavior
? Backup files
✗ SQLi — investigated
```

The key distinction is:

> **Not tested is not the same as tested and negative.**

**Review questions:**

- Does the current domain model already represent this sufficiently?
- Would adding explicit states create unnecessary complexity?
- Which states are actually useful to the user?

---

# 3. Deterministic Next-Action / Work Queue

Instead of only showing methodology checklists, consider a dynamic work queue generated from known assessment state.

```text
NEXT ACTIONS

HIGH
→ Test discovered credential against SSH

MEDIUM
→ Enumerate HTTP
→ Investigate MySQL

LOW
→ Resolve hostname
```

The important distinction:

```text
Facts + state + methodology rules
              ↓
       candidate actions
```

Not an opaque AI recommendation engine.

Example rule:

```text
Credential exists
+
SSH service open
+
credential untested
=
Test credential against SSH
```

**Review:** Keep this deterministic and explainable. Avoid building a huge planner unless real workflows prove it is necessary.

---

# 4. Knowledge Relationships

Consider connecting objects rather than keeping targets, credentials, findings, commands, leads, sessions, and evidence as isolated views.

Potential relationship chain:

```text
Command
  ↓
Observation / Fact
  ↓
Lead / Hypothesis
  ↓
Test
  ↓
Credential / Access / Finding
  ↓
Evidence
  ↓
Report
```

Selecting a credential could show:

```text
Discovered by:
  command #42
  /backup/config.php

Tested by:
  SSH #48
  SMB #51

Result:
  SSH VALID
  SMB INVALID
```

**Review:** This should extend existing relationships and provenance rather than introduce a second database or graph system unnecessarily.

---

# 5. Provenance

For important facts, make the source discoverable.

```text
10.10.10.20:80

Source:
Nmap scan #7
2026-08-29 05:31
```

For a credential:

```text
Source:
HTTP response from /backup/config.php
Command #42
```

For a finding:

```text
Evidence:
FTP session #18
```

**Review:** Existing evidence and command-history mechanisms may already cover much of this. First map what exists before designing another provenance layer.

---

# 6. Assessment Timeline

A unified timeline could expose meaningful events:

```text
05:12  Host discovered
05:14  Port 80 discovered
05:19  /backup found
05:21  Credential discovered
05:24  SSH access obtained
05:31  Privilege escalation discovered
05:34  Pivot established
```

Potential uses:

- review an attempt
- understand how a finding was reached
- generate reports
- compare attempts
- debug assessment state

**Review:** Do not jump directly to full event sourcing. A read-only timeline built from existing history may be sufficient.

---

# 7. Attack-Path / Network Graph

Potential view:

```text
Attacker
   │
   ▼
10.10.10.20
   │
   ├── HTTP
   │     └── credential
   │
   └── SSH
         └── shell
               │
               ▼
            pivot
               │
               ▼
       10.10.20.0/24
```

Nodes could represent:

- targets
- services
- credentials
- sessions
- pivots
- findings

Edges should have provenance and not be decorative.

**Review:** This is potentially powerful but also easy to overbuild. A textual relationship view may deliver most of the value before a graphical visualization is attempted.

---

# 8. Negative Knowledge / Dead Ends

Explicitly record what was investigated and ruled out.

```text
SSH
✓ credential tested — invalid

SQLi
✗ investigated — no indication

/admin
✗ investigated — 403
```

This prevents the system from repeatedly suggesting already-exhausted paths.

**Review:** Prefer extending existing lead/checklist state instead of creating a new `DeadEnd` subsystem unless necessary.

---

# 9. Credential Lifecycle

Potential lifecycle:

```text
FOUND
 ↓
UNTESTED
 ↓
TESTING
 ↓
VALID / INVALID
 ↓
USED
 ↓
REUSED
```

Example:

```text
admin : ********

SSH     ✓ VALID
SMB     ✗ INVALID
FTP     ? UNTESTED
MySQL   ✓ VALID
```

This could feed deterministic next-action suggestions.

---

# 10. Session as a First-Class Assessment Object

A shell/session should carry context:

```text
SESSION #3

Target: 10.10.10.20
User: www-data
Type: reverse shell

Created by:
  exploit #12

Used for:
  local enumeration
  credential discovery
  pivot
```

**Review:** Check whether current session support already provides these relationships before adding a new abstraction.

---

# 11. Hypothesis / Decision Layer

Potential training-oriented model:

```text
HYPOTHESIS

Credential X may work on SSH.

Supporting evidence:
+ credential found in config
+ SSH open
+ username matches

Tests:
□ SSH authentication

Result:
✓ Valid
```

And decision records:

```text
DECISION

Test SSH before SMB.

Reason:
22/tcp open
credential appears SSH-compatible
```

**Review:** This could be extremely useful for learning but should not become paperwork. Keep capture friction near zero.

---

# 12. Tool Capability Abstraction

Consider separating methodology intent from a specific binary.

Instead of:

```text
Run gobuster
```

A profile could express:

```text
Capability:
HTTP_CONTENT_ENUMERATION
```

The environment can resolve available tools:

```text
HTTP_CONTENT_ENUMERATION

✓ ffuf
✓ gobuster
✗ feroxbuster

Preferred:
ffuf
```

**Review:** Valuable for portability, but likely P2 unless tool portability is already a real pain point. Do not build a generalized package manager inside Cyb0x.

---

# 13. Environment Doctor

A diagnostic command could validate the environment:

```text
CYB0X DOCTOR

Core
✓ Python
✓ SQLite

Tools
✓ nmap
✓ netexec
✓ ffuf
✗ feroxbuster

Workspace
✓ writable

Database
✓ integrity
✓ migrations

Terminal
✓ color
✓ mouse
```

This should diagnose, not silently install or modify the environment.

---

# 14. Scope as an Execution Boundary

A particularly important safety concept:

```text
DISCOVERED ≠ AUTHORIZED
```

Potential model:

```text
Target
├── discovered: yes
├── in_scope: no
└── execution: blocked
```

Scope enforcement should exist below the TUI so a different interface cannot accidentally bypass it.

**Review:** Treat this as a serious architecture/security requirement, but ensure it matches the intended training environment and does not prevent legitimate lab workflows.

---

# 15. Retest / Verification Lifecycle

Potential finding lifecycle:

```text
DISCOVERED
 ↓
REPRODUCED
 ↓
EVIDENCE CAPTURED
 ↓
IMPACT VERIFIED
 ↓
RETESTED
```

This is especially useful for professional assessments, while training labs may use a lighter model.

**Review:** Avoid forcing professional pentest bureaucracy onto eJPT training unless the user enables it.

---

# 16. Reporting Readiness

Instead of export being a final dump, calculate whether important findings are documented sufficiently:

```text
REPORT READINESS

Findings:        6
Evidence:        6/6
Reproduction:    5/6
Impact:          4/6
Recommendation:  6/6

Completeness: 83%
```

Then generate the report from structured assessment data.

**Review:** This is probably more useful than adding many new report templates.

---

# 17. Lab Attempts / Replay

Training could support multiple attempts:

```text
Lab 07
├── Attempt 1 — 01:23:11
├── Attempt 2 — 00:51:43
└── Attempt 3 — 00:41:08
```

Compare:

```text
Commands
Dead ends
Time
Attack path
Findings
```

A clean/blind attempt could hide previous assessment state while retaining lab scope.

**Review:** Preserve historical data; never make a reset destroy the original attempt.

---

# 18. Learning Analytics

Potentially identify patterns across labs:

```text
Recon              91%
Enumeration        83%
Web                74%
Credentials        88%
Pivoting            52%
Post-exploitation   61%
Documentation      94%
```

More meaningful metrics may include:

- time to first discovery
- repeated actions
- dead ends
- missed opportunities
- time between discovery and exploitation
- methodology areas repeatedly skipped

**Review:** Avoid fake precision. Do not claim a user is `83% skilled` from arbitrary metrics. Use analytics primarily for trends and review.

---

# 19. Training / Assessment / CTF Modes

Consider whether one engine can support different objectives:

```text
TRAINING
→ methodology + learning

AUTHORIZED ASSESSMENT
→ scope + evidence + findings + report

CTF
→ flags + attack path + speed
```

The underlying state model can remain shared while presentation and completion criteria differ.

**Review:** Do not build all three modes now. Validate whether real users actually need the distinction.

---

# 20. AI Boundary

AI should remain advisory and grounded in structured Cyb0x state.

```text
Deterministic state
       ↓
Structured context
       ↓
Optional AI
       ↓
Explanation / summarization / hypothesis
```

Example:

```text
AI suggestion:
Test SSH credential.

Grounding:
22/tcp open
credential exists
credential untested
```

AI should not silently create facts or change assessment state.

**Review:** Keep the deterministic core useful without AI. AI should improve understanding and productivity, not become a hidden dependency.

---

# 21. Cross-System Invariants

This may be more valuable than many individual features.

Example invariant:

```text
Parser discovers service
        ↓
Assessment state updates
        ↓
TUI reflects state
        ↓
Export contains state
        ↓
Import restores equivalent state
```

Build end-to-end tests around complete user journeys, not only isolated modules.

Potential journeys:

```text
Create lab
→ add scope
→ discover target
→ ingest scan
→ enumerate service
→ record finding
→ add credential
→ test credential
→ create session
→ pivot
→ capture evidence
→ export
→ import
→ resume
```

This is likely a **higher-value investment than adding more unit tests without integration coverage**.

---

# 22. Human-Task UX Benchmark

The repository already has TUI workflow/simulation/performance-oriented infrastructure. Use that to measure real tasks.

Examples:

```text
TASK: create a lab
TASK: add target
TASK: find previous command
TASK: record credential
TASK: attach evidence
TASK: switch lab
TASK: resume previous state
TASK: retest a finding
```

Measure:

- task completion
- time
- interaction count
- navigation depth
- context loss
- recovery from mistakes

Do not optimize for minimum keystrokes alone. Optimize for **low cognitive load + fast access to common operations**.

---

# 23. Data Integrity / Recovery

Test failure scenarios:

```text
process killed during command
process killed during database write
terminal closed
machine reboot
migration failure
large output
workspace copied
export/import
```

Desired guarantees:

```text
No silent loss of assessment state
No half-created records
No broken relationships
No corrupted workspace
```

---

# 24. Performance at Realistic Scale

Benchmark representative workloads:

```text
100 hosts
1,000 services
10,000 commands
large command outputs
large evidence sets
```

Measure:

- startup
- search
- navigation
- DB operations
- import/export
- TUI responsiveness

Do not optimize hypothetical scale before measuring real bottlenecks.

---

# 25. What Should Probably NOT Be Added

This proposal is intentionally conservative about scope.

Avoid:

- rewriting the entire architecture just to introduce event sourcing
- building a custom graph database
- turning Cyb0x into an AI autonomous pentester
- making methodology a rigid linear wizard
- duplicating existing evidence/lead/credential models
- adding dozens of tool integrations without user demand
- creating a full plugin marketplace prematurely
- building a web frontend before the core workflow is validated
- adding metrics that do not change decisions
- adding gamification just to make dashboards look impressive

---

# Honest Review Checklist

Before implementing anything from this proposal, answer:

```text
[ ] Does Cyb0x already have this capability?
[ ] Is the problem observable in real usage?
[ ] Does it help the actual pentesting loop?
[ ] Does it improve eJPTv2 training specifically?
[ ] Does it help professional assessment workflows?
[ ] Can it reuse existing models/state?
[ ] Does it introduce duplicated state?
[ ] Does it add meaningful cognitive load?
[ ] Can it be tested end-to-end?
[ ] Is the complexity justified by measurable benefit?
```

If the answer is mostly no, **reject the feature**.

---

# Suggested Review Order

Do not implement this document top-to-bottom.

1. Audit current repository capabilities.
2. Map the actual eJPTv2 workflow against the current engine.
3. Run realistic end-to-end lab tasks.
4. Identify concrete friction/gaps.
5. Select only the highest-value proposals.
6. Prototype the smallest version.
7. Measure whether it improves the workflow.
8. Keep, revise, or delete the proposal based on evidence.

## Guiding Principle

> **Cyb0x should remember the assessment so the tester can focus on the assessment — but every proposed abstraction must earn its complexity.**
