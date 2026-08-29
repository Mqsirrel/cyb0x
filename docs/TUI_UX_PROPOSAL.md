# Cyb0x TUI/UX Improvement Proposal

## Purpose

Make Cyb0x feel like a polished, fast, keyboard-first terminal workspace rather than a collection of separate TUI screens.

The goal is **not** feature bloat. The goal is to reduce friction in the real pentesting loop:

```text
LOOK → SELECT → ACT → OBSERVE → RECORD → NEXT
```

Cyb0x already contains substantial pentesting state, methodology, targets, services, findings, credentials, evidence, pivots, command execution, and workspace functionality. This proposal focuses on making those capabilities easier and faster to use.

---

# Design Principles

1. **Optimize for the actual pentest loop.**
2. **Keep the user oriented at all times.**
3. **Prefer preview over navigation when possible.**
4. **Keyboard-first, but not keyboard-only.**
5. **Do not require memorizing dozens of shortcuts.**
6. **Do not duplicate existing domain/state logic.**
7. **Do not block the UI during long-running commands.**
8. **Use progressive disclosure: show what matters now, reveal details on demand.**
9. **Adapt to terminal size.**
10. **Make destructive actions reversible where practical.**

---

# P0 — Navigation Foundation

## 1. Persistent Multi-Panel Workspace

Prefer a stable workspace with panels over constantly replacing the entire screen.

Conceptual layout:

```text
┌─ LAB ─────────┬─ TARGETS ──────────┐
│ Lab 07        │ 10.10.10.20        │
│ 72%           │                     │
│               │ 22 SSH              │
│               │ 80 HTTP             │
├─ NEXT ────────┼─────────────────────┤
│ → HTTP enum   │ OUTPUT / DETAILS    │
│ → test cred   │                     │
│ → Host B      │ command output...   │
└─────────────────────────────────────┘
```

The exact panels should be determined by the existing application architecture and screen size.

## 2. Consistent Navigation Model

Provide a predictable set of universal interactions:

```text
↑ ↓ / j k       Navigate
Enter           Select / open
Esc             Back / close
Tab             Next panel
Shift+Tab       Previous panel
1–9             Jump to panel/section where applicable
?               Contextual help
/               Search/filter
```

Do not break existing useful Cyb0x shortcuts without first auditing them.

## 3. Navigation Stack

`Esc` should normally mean **go back one level**, not jump unpredictably to the main screen.

Example:

```text
LAB 07
 › 10.10.10.20
 › HTTP
 › Command History
 › gobuster #2
```

Back should unwind this stack naturally.

## 4. Breadcrumbs

Always make the current context visible:

```text
LAB 07 › 10.10.10.20 › HTTP › Findings
```

The user should never wonder where they are.

## 5. Global Status Bar

Provide a compact persistent status bar:

```text
LAB: eJPT-07 │ HOSTS 5 │ FINDINGS 6 │ CREDS 3 │ NEXT: HTTP │ ? Help │ / Search
```

Avoid turning it into a giant metrics dashboard.

---

# P0 — Search & Command Discovery

## 6. Global Search

`/` should provide fast search/filtering.

Where practical, search across the current lab rather than only the visible list:

```text
> backup

FINDINGS
10.10.10.20 /backup

COMMANDS
gobuster ... /backup

NOTES
"backup directory interesting"

EVIDENCE
screenshot_04.png

TARGETS
10.10.10.20
```

Use existing data models and indexes where possible.

## 7. Command Palette

Provide a discoverable command palette, e.g. `Ctrl+K` if that does not conflict with existing bindings:

```text
COMMAND PALETTE

> _
────────────────────────────
Open Target
Run Command
Add Finding
Add Credential
Add Note
Add Lead
Show Next Actions
Switch Lab
Search Everything
Open Evidence
Export Lab
Re-run Last Command
```

Typing should filter actions:

```text
> cred

→ Add Credential
→ View Credentials
→ Test Credential
```

This reduces shortcut memorization while retaining power-user shortcuts.

## 8. Contextual `?` Help

`?` should show actions relevant to the current context, not one giant static keymap.

Example inside Credentials:

```text
┌─ CREDENTIALS ──────────────┐
│ ? Keyboard Shortcuts       │
├────────────────────────────┤
│ ↑↓  Navigate               │
│ Enter  Open credential     │
│ t  Test                   │
│ n  Add note                │
│ c  Copy                   │
│ /  Filter                 │
│ Esc Close                 │
└────────────────────────────┘
```

---

# P1 — Information Architecture

## 9. Preview-First Lists

Selecting an item should show a useful preview before requiring `Enter`.

Example:

```text
TARGETS

> 10.10.10.20
  10.10.10.30
  10.10.10.40

────────────────────
PREVIEW

Linux / web01

22 SSH
80 HTTP
3306 MySQL

2 findings
1 credential
1 session
```

Inspired by the preview-oriented interaction model used by terminal file managers.

## 10. Target 360° View

Selecting a target should provide one place for its operational context:

```text
10.10.10.20
────────────────────────
OS: Linux
Hostname: web01
Scope: IN

SERVICES
22 SSH
80 HTTP
3306 MySQL

CREDENTIALS
user@example
 ├─ SSH: UNTESTED
 └─ MySQL: VALID

FINDINGS
• /backup
• weak authentication

SESSIONS
• www-data

PIVOT
• 10.10.20.0/24 reachable

EVIDENCE
7 items
```

Reuse existing target/service/credential/finding/session/pivot/evidence state.

## 11. Contextual Actions

Actions should change based on what is selected.

For an HTTP service:

```text
[Run HTTP checks]
[Command history]
[Add note]
[Add finding]
```

For a credential:

```text
[Test credential]
[View source]
[Add note]
[Copy]
```

Avoid presenting irrelevant actions everywhere.

## 12. Jump-to-Anything

Provide a fast picker, e.g. `Ctrl+P`, for jumping directly to known entities:

```text
> 10.10.10

10.10.10.10
10.10.10.20
10.10.10.30
```

Or:

```text
> ssh

22/tcp — 10.10.10.20
22/tcp — 10.10.10.30
SSH credential
SSH finding
```

This should behave like an assessment-aware fuzzy finder rather than another generic menu.

---

# P1 — Command Execution UX

## 13. Non-Blocking Command Execution

Long-running commands should not freeze the entire interface.

Show live output where practical:

```text
┌─ COMMAND ──────────────────────────┐
│ nmap -sV 10.10.10.20               │
│                                     │
│ PORT    STATE SERVICE               │
│ 22      open  ssh                   │
│ 80      open  http                  │
│                                     │
│ ● Running                           │
└─────────────────────────────────────┘
```

The workspace should remain navigable where technically safe.

## 14. Contextual Command History

Organize command history around assessment context:

```text
10.10.10.20
└── HTTP
    ├── nmap ...
    ├── whatweb ...
    ├── gobuster ...
    └── curl ...
```

Retain, where supported:

- Target
- Service
- Command
- Timestamp
- Exit code
- stdout/stderr
- Notes
- Status

## 15. Re-Run

Every useful previous command should have a low-friction re-run path.

Example:

```text
Gobuster
├── Run #1 — 14:32
├── Run #2 — 15:04
└── Run #3 — 16:18
```

Actions:

```text
[Run again] [Edit] [Copy]
```

Do not destroy previous execution output when re-running.

## 16. Focus Mode

When output or a detailed object needs space, allow a temporary full-screen view:

```text
Ctrl+Space
```

Then:

```text
Esc → return to workspace
```

This prevents small panels from making large command output unusable.

---

# P1 — Pentesting-Specific Interaction

## 17. Quick Scratchpad

Provide a low-friction place for thoughts that are not yet formal Findings or Leads.

```text
SCRATCHPAD

[ ] FTP anonymous access
[ ] Check backup directory
[ ] Try discovered password against SSH
[x] Enumerate SMB shares

"10.10.10.20 seems to be initial foothold."
```

It should persist with the lab and optionally be convertible into structured state.

## 18. Investigated / Dead-End State

The user should distinguish:

- Unknown
- Investigated
- Checked
- Finding
- Dead-end
- Next action

Do not duplicate existing state concepts; extend them if necessary.

Example:

```text
HTTP
├── /admin       FINDING
├── /backup      FINDING
├── SQLi         DEAD-END
└── XSS          INVESTIGATED
```

This helps prevent repeating work.

## 19. Target/Service Context Preservation

When moving from a target to a service, preserve context.

Example:

```text
Target: 10.10.10.20
Service: HTTP
```

A command launched from that context should automatically know which target/service it belongs to where appropriate.

The user should not repeatedly re-enter information Cyb0x already knows.

---

# P1 — Lab UX

## 20. Lab Manager

Provide a clear entry point for creating and switching labs:

```text
CYB0X

[1] Start New Lab
[2] Open Lab
[3] Recent Labs
[4] Lab History
[5] Settings
```

Within the application, allow fast switching without restarting.

## 21. Recent Labs

Show useful metadata:

```text
RECENT LABS

● eJPTv2 — Network Pentest       12 min ago
  4 hosts · 13 services

  eJPTv2 — Web Pentest            Yesterday
  2 hosts · 7 services
```

## 22. Resume State

Opening a lab should answer immediately:

> What was I doing, what did I discover, and what remains?

Example:

```text
CURRENT STATE

✓ Initial reconnaissance
✓ 4/5 hosts enumerated

⚠ 10.10.10.20
   HTTP enumeration incomplete

⚠ Credential found but not tested

→ NEXT
   Test credential against relevant services
```

Use the existing assessment state rather than building a second recommendation engine.

## 23. Lab Overview

Keep the overview compact:

```text
LAB 07

PROGRESS
██████████████░░░░ 72%

HOSTS
● 10.10.10.10   OWNED
● 10.10.10.20   ENUM
● 10.10.10.30   DISCOVERED

SERVICES
17 discovered · 12 enumerated

CREDENTIALS
3 found · 2 tested · 1 untested

FINDINGS 6    EVIDENCE 11

NEXT
→ Enumerate HTTP on 10.10.10.30
```

Do not overload the home screen with every metric.

---

# P1 — Training Workflow

## 24. Attempt History

Treat repeated lab work as separate attempts when useful:

```text
Lab 07
├── Attempt 1
├── Attempt 2
└── Attempt 3
```

Historical attempts should remain available.

## 25. Reset / Clone

Allow a clean attempt without destroying history.

Example:

```text
Lab 07 — Attempt 1 complete
        ↓
Reset / Clone
        ↓
Attempt 2 — clean state
```

Preserve appropriate lab metadata/scope while resetting assessment state.

## 26. Blind Practice

Allow the user to hide previous solution state:

```text
BLIND ATTEMPT

Hide:
☑ Previous findings
☑ Previous credentials
☑ Previous commands
☑ Previous evidence

Keep:
☑ Scope
☑ Lab metadata
```

The previous attempt remains stored.

## 27. Post-Lab Review

After completion, show methodology coverage without turning it into a solution guide:

```text
POST-LAB REVIEW

Completed:
✓ Recon
✓ Enumeration
✓ Initial access
✓ Pivot

Not investigated:
⚠ SMB enumeration
⚠ FTP write permission
⚠ HTTP backup extensions
```

The purpose is to answer:

> What did I actually practice, and what did I skip?

## 28. Attempt Timing

Optionally track time per attempt:

```text
Attempt 1   01:42:31
Attempt 2   00:57:14
Attempt 3   00:41:08
```

Use this for measuring improvement, not unnecessary gamification.

---

# P2 — Safety, Accessibility & Polish

## 29. Confirmation Strategy

Confirm destructive actions only:

```text
Delete Lab
Reset Attempt
Clear Evidence
Delete Credential
```

Do not interrupt normal operations with unnecessary confirmation dialogs.

## 30. Undo Where Practical

For reversible local state changes, consider undo/redo.

Example:

```text
Deleted finding "SQL injection"

Ctrl+Z → Undo
```

Prioritize actions where accidental deletion is realistically costly.

## 31. Do Not Rely on Color Alone

Represent state with text/symbols as well as color:

```text
✓ TESTED
! ATTENTION
? UNKNOWN
× FAILED
→ NEXT
```

This improves readability and accessibility.

## 32. Mouse Support

Keep keyboard-first interaction, but allow mouse interaction where the TUI framework supports it naturally.

The same action should not require mouse-only interaction.

## 33. Terminal-Size Adaptation

Large terminal:

```text
┌───────┬───────────┬─────────────────┐
│ Labs  │ Targets   │ Output          │
└───────┴───────────┴─────────────────┘
```

Small terminal:

```text
┌───────────────────┐
│ Targets           │
│ 10.10.10.20       │
│ 10.10.10.30       │
└───────────────────┘
```

Panels should collapse/reflow rather than become unreadable.

## 34. Accessibility Mode

Consider options such as:

- reduced reliance on color
- clearer state labels
- configurable contrast
- larger/less dense views where practical

Do not make accessibility a separate incompatible UI.

---

# What NOT to Do

Do not:

- turn Cyb0x into an eJPT tutorial
- add another methodology engine
- duplicate target/state persistence
- add dozens of commands solely for completeness
- create a giant dashboard full of metrics
- require memorizing 30+ shortcuts
- hide important state behind deep modal navigation
- freeze the entire TUI during command execution
- force every observation into a formal Finding
- create separate databases/models when existing workspace architecture can support the feature
- redesign the whole application before auditing what already exists

---

# Recommended Implementation Process

Before writing code:

## Phase 1 — Audit

Inspect the current TUI and document:

```text
Existing panels
Existing navigation
Existing keybindings
Existing modals
Existing workspace flow
Existing command execution
Existing search
Existing persistence
Existing target/service views
Existing methodology views
Existing responsive behavior
```

## Phase 2 — UX Map

Map the real workflow:

```text
Start / Open Lab
      ↓
Resume
      ↓
Target
      ↓
Service
      ↓
Command
      ↓
Output
      ↓
Observation
      ↓
Finding / Note / Lead
      ↓
Next
```

Identify unnecessary navigation steps.

## Phase 3 — Prioritize

Implement in this order unless the audit reveals existing equivalents:

### P0
- multi-panel workspace
- consistent navigation
- breadcrumbs
- contextual help
- global search
- command palette
- responsive layout

### P1
- previews
- target 360°
- contextual actions
- non-blocking command execution
- command history/re-run
- focus mode
- scratchpad
- lab manager/resume
- training attempts

### P2
- undo
- jump-to-anything
- mouse polish
- accessibility enhancements
- advanced customization

## Phase 4 — Validate With Real Tasks

Do not judge the redesign by screenshots alone.

Perform realistic tasks:

```text
1. Create a new lab
2. Add scope/IP
3. Discover a host
4. Add services
5. Run reconnaissance
6. Inspect output
7. Record a finding
8. Add a credential
9. Test/re-use it
10. Track a session
11. Record a pivot
12. Switch to another lab
13. Return to the first lab
14. Resume exactly where stopped
15. Re-run an old command
16. Search for an old observation
17. Complete the lab
18. Start a clean/blind attempt
```

Measure:

- number of keypresses
- number of screen transitions
- time to complete common operations
- number of times context must be re-entered
- whether the current context is obvious
- whether the user can recover from mistakes

The goal is not minimum keypresses at all costs. The goal is **low cognitive load with fast access to common actions**.

---

# Final UX Target

Cyb0x should feel like:

```text
┌─────────────────────────────────────────────┐
│ LAB 07 › 10.10.10.20 › HTTP                 │
├────────────┬────────────────────────────────┤
│ TARGETS    │ OUTPUT                          │
│            │                                 │
│ > .20      │ gobuster output...              │
│   .30      │                                 │
│   .40      │                                 │
├────────────┼────────────────────────────────┤
│ NEXT       │ PREVIEW                         │
│ → HTTP     │ 80 HTTP                         │
│ → test     │ 2 findings · 1 credential       │
├────────────┴────────────────────────────────┤
│ / Search │ Ctrl+K Actions │ ? Help │ Tab     │
└─────────────────────────────────────────────┘
```

The user should be able to move naturally from:

**Lab → Target → Service → Command → Output → Finding → Credential → Session → Pivot → Next Target**

without feeling like they are jumping between unrelated applications.

The core principle is:

> **Cyb0x should remember the assessment so the tester can focus on the assessment.**

This proposal is a UX/workflow proposal only. Any implementation should first audit the existing code and reuse current Cyb0x capabilities rather than duplicating them.