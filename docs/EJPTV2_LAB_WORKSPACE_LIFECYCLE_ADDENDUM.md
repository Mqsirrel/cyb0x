# eJPTv2 Lab Workspace Lifecycle Addendum

## Purpose

Make **Lab** the top-level workspace context in Cyb0x without duplicating or replacing the existing methodology engine.

The user should be able to create, open, switch, resume, reset, and review labs easily.

## Startup

Provide a simple flow such as:

```text
CYB0X

[1] Start New Lab
[2] Open Lab
[3] Recent Labs
[4] Lab History
[5] Settings
```

Starting a lab should be lightweight:

```text
Start New Lab
────────────────────
Name: eJPTv2 Lab 07
Target / Scope: ____________

[ Create ]
```

## Lab ≠ Target

A Lab is the top-level assessment workspace and can contain multiple targets:

```text
LAB
└── Targets
    ├── 10.10.10.10
    ├── 10.10.10.20
    └── 10.10.10.30
```

Discovering a new host must not require creating a new lab.

## Easy Lab Switching

The user should be able to switch labs without restarting Cyb0x.

Example:

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

Switching should restore the complete state of the selected lab:

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

A user should be able to leave Lab A, work on Lab B, then return to Lab A and continue exactly where they stopped.

## Recent Labs

Provide quick access to active/recent work:

```text
RECENT LABS

● eJPTv2 — Network Pentest       12 min ago
  4 hosts · 13 services

  eJPTv2 — Web Pentest            Yesterday
  2 hosts · 7 services

  eJPTv2 — Pivoting               2 days ago
  5 hosts · 2 networks
```

## Repeat Practice

A lab should support multiple attempts without destroying history:

```text
Lab 07
├── Attempt 1
├── Attempt 2
└── Attempt 3
```

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

Historical attempts should remain available. The implementation can use snapshots, cloned workspaces, or another architecture-appropriate mechanism.

## UX Principle

The tester should feel:

> "Everything I discover during this lab automatically has a place."

The intended flow is:

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

## Implementation Constraint

Before implementation, inspect the current architecture and identify what already exists. Reuse the existing persistence, state machine, target, credential, evidence, pivot, and export systems wherever possible.

Do not create a second methodology engine or an eJPT walkthrough system. This proposal is about **workspace lifecycle, persistence, organization, and usability** around the existing methodology.
