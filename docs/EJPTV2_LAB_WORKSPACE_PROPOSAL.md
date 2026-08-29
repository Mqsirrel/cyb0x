# Cyb0x — eJPTv2 Lab Workspace Enhancement Proposal

## Goal

Review Cyb0x as an **end-to-end practical workspace for eJPTv2 labs**.

The goal is **not** to turn Cyb0x into an eJPT tutorial or guided walkthrough.

Cyb0x already has a methodology/state-machine system. The goal is to make the existing system an excellent **place to actually perform, document, revisit, and repeat pentesting labs**.

Think:

> **Pentesting workbench + persistent lab notebook + command workspace**

rather than:

> eJPT course/guide.

---

## Important Constraint

**Do not duplicate or replace the existing methodology engine.**

Cyb0x already provides methodology recipes, service-specific checks, state tracking, command execution, credentials, leads, evidence, pivoting, and exports.

Before implementing anything:

1. Inspect the existing architecture.
2. Identify what is already supported.
3. Reuse existing abstractions.
4. Avoid duplicate data models/features.
5. Only implement functionality that is genuinely missing or materially improves the workflow.

---

# 1. Lab / Assessment Workspace

Introduce a clear concept of a **Lab / Assessment workspace** if the current architecture does not already provide an equivalent.

A lab should contain:

```text
Lab
├── Scope
├── Targets
├── Hosts
├── Services
├── Commands
├── Findings
├── Credentials
├── Shells / Sessions
├── Pivot / Network information
├── Evidence
├── Notes
└── History
```

Example:

```text
eJPTv2 - Lab 07
│
├── Scope
│   └── 10.10.10.0/24
│
├── Hosts
│   ├── 10.10.10.10
│   ├── 10.10.10.20
│   └── 10.10.10.30
│
├── Credentials
├── Findings
├── Leads
├── Evidence
└── Command History
```

The exact implementation should follow the existing Cyb0x architecture.

---

# 2. Lab Selection & Lifecycle

The **Lab should be the top-level workspace context** rather than merely another target field.

On startup, provide a simple flow such as:

```text
╭──────────────────────────────╮
│           CYB0X              │
│                              │
│  [1] Start New Lab           │
│  [2] Open Lab                │
│  [3] Recent Labs             │
│  [4] Lab History             │
│  [5] Settings                │
╰──────────────────────────────╯
```

Starting a lab should be lightweight:

```text
Start New Lab
────────────────────
Name: eJPTv2 Lab 07
Target / Scope: ____________

[ Create ]
```

The user should be able to **switch between labs without restarting Cyb0x**.

For example:

```text
Ctrl+L

LABS
────────────────────────────
● eJPTv2 Lab 07    ← current
  eJPTv2 Lab 08
  eJPTv2 Lab 09
  HTB Machine
  Practice SMB
────────────────────────────
[New] [Open] [Rename] [Archive]
```

Switching labs should restore the complete state of that lab:

- Targets/IPs
- Hosts
- Services
- Commands + outputs
- Notes
- Credentials
- Findings
- Sessions
- Pivot information
- Evidence
- Methodology state

The user should be able to leave Lab 07, work on Lab 08, then return to Lab 07 and continue **exactly where they stopped**.

### Recent Labs

Provide a quick-access view for active/recent work:

```text
RECENT LABS

● eJPTv2 — Network Pentest       12 min ago
  4 hosts · 13 services

  eJPTv2 — Web Pentest            Yesterday
  2 hosts · 7 services

  eJPTv2 — Pivoting               2 days ago
  5 hosts · 2 networks
```

### Important distinction

A **Lab is not a Target**.

A lab can contain multiple targets:

```text
LAB
└── Targets
    ├── 10.10.10.10
    ├── 10.10.10.20
    └── 10.10.10.30
```

Do not create a new workspace every time a new host is discovered.

---

# 3. Target-Centric Workspace

A tester should be able to select a target and immediately see **everything known about it**.

Example:

```text
10.10.10.20
────────────────────────

OS: Linux
Hostname: web01

OPEN SERVICES
22/tcp   SSH
80/tcp   HTTP
3306/tcp MySQL

Credentials
───────────
user: __________
pass: __________

Findings
────────
• /backup
• ...

Notes
─────
...

Commands
────────
...

Evidence
────────
...
```

All information should remain linked to the target.

Avoid forcing the user to search through unrelated terminal output or files.

---

# 4. Command Workspace

Commands should be treated as persistent assessment objects rather than temporary terminal history.

For each command, retain:

```text
Target
Service
Command
Timestamp
Exit code
stdout
stderr
Status
Notes
```

Example:

```text
Target: 10.10.10.20
Service: HTTP
Command: gobuster ...
Time: 14:32
Status: FINDING
```

The user should be able to:

- Run
- Edit
- Re-run
- Copy
- View previous output
- Compare runs
- Attach a result to a finding

Do not remove the ability to execute arbitrary custom commands.

---

# 5. Re-run / Re-test Workflow

This is especially important for practical training.

If a command or test was previously executed:

```text
[Re-run]
```

should execute the same recipe again using the current target variables.

Ideally retain execution history:

```text
Gobuster
├── Run #1 — 14:32
├── Run #2 — 15:04
└── Run #3 — 16:18
```

This allows the tester to experiment without losing previous results.

---

# 6. Lab Reset / Clone & Attempts

Investigate adding a clean way to practice the same lab repeatedly.

Desired workflow:

```text
Attempt #1
   ↓
Complete Lab
   ↓
Review
   ↓
Reset / Clone
   ↓
Attempt #2
   ↓
Solve again without relying on previous notes
```

Important:

**Do not destroy historical attempts.**

For example:

```text
Lab 07
├── Attempt 1
├── Attempt 2
└── Attempt 3
```

The implementation can use snapshots, cloned workspaces, or another architecture-appropriate mechanism.

A reset should clear the appropriate working state while preserving historical attempts and allowing the user to start cleanly.

---

# 7. Notes That Are Actually Useful

Avoid one giant generic notes field.

Provide contextual notes where appropriate:

```text
Lab Notes
Target Notes
Service Notes
Finding Notes
Credential Notes
Pivot Notes
Command Notes
```

The user should be able to quickly write things such as:

```text
Interesting:
Anonymous FTP works.

Next:
Check files exposed by FTP.
```

or:

```text
Credential found on 10.10.10.20.

Need to test against:
[ ] SSH
[ ] SMB
[ ] FTP
[ ] HTTP
```

Reuse the existing credential matrix where possible.

---

# 8. Shell / Session Tracking

Investigate whether shells/sessions can be represented persistently.

Example:

```text
SESSIONS

#1
Target: 10.10.10.20
User: www-data
Type: reverse shell
Status: active

#2
Target: 10.10.10.30
User: user
Type: SSH
Status: active
```

The purpose is not to replace a terminal multiplexer.

The purpose is to keep **assessment context** attached to the shell:

- Which host?
- Which user?
- How was access obtained?
- What findings were discovered?
- What credentials/routes were found from this session?

---

# 9. Network-Level View

eJPTv2-style labs can involve multiple hosts and internal networks.

The workspace should make it easy to understand:

```text
External
   │
   ▼
10.10.10.20
   │
   │ pivot
   ▼
10.10.20.0/24
   │
   ├── 10.10.20.10
   ├── 10.10.20.20
   └── 10.10.20.30
```

Reuse the existing pivot/network functionality instead of creating another graph system.

The key requirement is that the tester can answer:

> "What do I currently know about this network?"

---

# 10. Evidence Association

Evidence should be associated with the thing it proves.

For example:

```text
Finding
└── Evidence
    ├── Command
    ├── Output
    ├── Screenshot
    └── Timestamp
```

Likewise:

```text
Credential
└── Source
    └── Command / Finding / Host
```

This makes final reporting much easier.

---

# 11. Fast Navigation

The TUI should optimize for the actual workflow of a tester.

The user should be able to quickly move between:

```text
Lab
→ Target
→ Service
→ Command
→ Output
→ Finding
→ Credential
→ Session
→ Pivot
→ Another Target
```

Avoid forcing excessive modal navigation for common operations.

Keyboard-first interaction is one of Cyb0x's strengths and should remain central.

---

# 12. eJPTv2 Training Workflow

Do **not** hard-code a walkthrough for individual labs.

Instead, support this workflow:

```text
Start Lab
   ↓
Enter scope / targets
   ↓
Perform reconnaissance
   ↓
Run commands
   ↓
Record discoveries
   ↓
Enumerate services
   ↓
Create findings/leads
   ↓
Obtain access
   ↓
Track credentials/sessions
   ↓
Post-exploitation
   ↓
Pivot if applicable
   ↓
Discover additional hosts
   ↓
Repeat
   ↓
Document evidence
   ↓
Complete Lab
```

The existing methodology engine should continue deciding/assisting with relevant checks.

The workspace should simply make the process **easy to execute and remember**.

---

# 13. Attempt History

Consider retaining a lightweight history of the user's work.

For example:

```text
Lab 07

Attempt 1
├── 01:42:31
├── 3 hosts discovered
├── Initial access
└── Completed

Attempt 2
├── 00:57:14
├── 3 hosts discovered
├── Initial access
└── Completed

Attempt 3
└── Current
```

Useful metrics could include:

- Time spent
- Hosts discovered
- Services enumerated
- Findings
- Credentials
- Pivot steps
- Commands executed

Keep this optional and lightweight.

---

# 14. "I'm Stuck" Should Remain State-Aware

The existing `s` functionality is valuable.

Do not replace it with generic tutorials.

The ideal behavior is:

```text
Current state:
- Host A enumerated
- Port 80 partially tested
- Port 22 untested
- Credential X discovered
- Host B discovered but not enumerated

Potential next actions:
1. Test credential X against relevant services
2. Complete SSH enumeration
3. Investigate Host B
```

Suggestions should come from **known assessment state**, not generic "try these 50 commands."

---

# 15. Avoid Feature Bloat

Do NOT add features simply because they exist in other pentesting tools.

Prioritize:

1. Lab creation/opening/switching
2. Fast target entry
3. Persistent command execution/history
4. Target/service organization
5. Notes
6. Findings
7. Credentials
8. Sessions
9. Pivot/network context
10. Evidence
11. Re-run
12. Lab reset/clone
13. Attempt history
14. Export

Everything else should be evaluated based on whether it improves the actual lab workflow.

---

# 16. UX Principle

The tester should feel:

> "Everything I discover during this lab automatically has a place."

Not:

> "I need to maintain Cyb0x plus a separate note-taking system plus several terminals."

The ideal experience:

```text
Open Cyb0x
    ↓
Choose existing lab / Start new lab
    ↓
Enter IP
    ↓
Work
    ↓
Everything is automatically organized
    ↓
Switch labs whenever needed
    ↓
Return later
    ↓
Everything is still there
    ↓
Continue exactly where you stopped
```

---

# 17. Review Before Implementation

Before changing code, produce a short audit:

```text
EXISTING
────────
Feature                     Status
Lab workspace               ?
Lab selection/switching     ?
Target tracking             ?
Command history             ?
Re-run                      ?
Notes                       ?
Credential matrix           ?
Session tracking            ?
Pivot tracking              ?
Evidence                    ?
Export                      ?
Reset/clone                 ?
Attempt history             ?

MISSING
───────
...

PARTIALLY IMPLEMENTED
─────────────────────
...

REDUNDANT / DO NOT ADD
──────────────────────
...
```

Then propose the **smallest coherent implementation**.

Do not rewrite the application.

Do not replace the existing methodology engine.

Do not add an eJPT tutorial.

---

# Success Criteria

A successful implementation should allow a user to take an arbitrary eJPTv2 lab and comfortably do:

```text
Choose / create Lab
      ↓
Target entry
      ↓
Recon
      ↓
Scan
      ↓
Enumeration
      ↓
Commands + outputs saved
      ↓
Findings recorded
      ↓
Credentials tracked
      ↓
Initial access
      ↓
Session tracking
      ↓
Post-exploitation
      ↓
Pivot
      ↓
New target
      ↓
Repeat
      ↓
Evidence
      ↓
Export
```

The user should also be able to:

```text
Lab A
 ↓
Switch to Lab B
 ↓
Work on Lab B
 ↓
Switch back to Lab A
 ↓
Resume exactly where they stopped
```

**without needing a separate note-taking system for the assessment.**

The existing Cyb0x methodology should remain the intelligence layer.

The proposed work should strengthen the **workspace/execution/state/history layer** around it.
