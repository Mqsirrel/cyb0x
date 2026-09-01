# CYB0X Guide: eJPTv2 and General Lab Workflow

> **Purpose:** Use CYB0X as a pentesting workflow assistant, not as a box solver.
>
> CYB0X should help you remember methodology, preserve assessment state, organize evidence, recognize what you have and have not tested, and choose a sensible next investigation. **You remain responsible for understanding the result and deciding what to do.**

---

## 1. The Core Idea

A normal lab session can become messy very quickly:

- several hosts and IP addresses
- many open ports
- commands spread across terminal tabs
- credentials discovered on one machine but not tested elsewhere
- web directories that need follow-up
- partial shells and pivot routes
- dead ends and rabbit holes
- uncertainty about what you already checked

CYB0X is the state layer around that work.

The intended loop is:

```text
Discover
   ↓
Enumerate
   ↓
Record evidence
   ↓
Interpret the finding
   ↓
Choose the next investigation
   ↓
Exploit when justified
   ↓
Post-exploit / pivot
   ↓
Enumerate again with the new information
```

Do **not** treat the process as a rigid:

```text
Recon → Enumeration → Exploitation → PrivEsc → Done
```

A foothold can create new information, and new information should change what you investigate next.

---

## 2. What CYB0X Is — and Is Not

### CYB0X is

- a methodology copilot
- an assessment state tracker
- an enumeration checklist with prioritization
- a credential and evidence organizer
- a lead/hypothesis tracker
- a command/evidence history
- a way to reduce forgotten checks and unnecessary rabbit holes

### CYB0X is not

- an automatic HTB solver
- an exploit vending machine
- a replacement for learning Nmap, Metasploit, SMB, HTTP, Linux, Windows, etc.
- a reason to blindly execute every suggested command
- a guarantee that the recommended next action is correct

The best use is **human-first**: CYB0X keeps the assessment organized while you do the technical reasoning.

---

## 3. Start a Lab Workspace

For any lab platform, use a dedicated workspace rather than mixing unrelated machines.

Examples:

```text
EJPT-TRAINING
HTB-EASY-BOXES
THM-PRACTICE
HOME-LAB
OSCP-PREP
```

Launch the workspace:

```bash
synapse --workspace EJPT-TRAINING
```

For an existing scan, ingest it first:

```bash
synapse --workspace EJPT-TRAINING ingest scan.xml
```

If you have no scan yet, add the target and use Initial Recon from the TUI.

---

## 4. Phase 0 — Initial Recon

Start with the target and establish the attack surface.

Typical flow:

```text
Target IP
   ↓
Initial reconnaissance
   ↓
Open ports
   ↓
Service/version information
   ↓
CYB0X creates service methodology
```

In the TUI:

- `a` — add a target
- `i` — launch Initial Recon
- `r` — run the selected recipe

A useful starting scan is the one you understand and can interpret. For example:

```bash
nmap -Pn -sC -sV -p- TARGET -oX scan.xml
```

The exact scan is your choice. The important part is that you **understand the output** and feed useful results into CYB0X.

### What CYB0X should give you afterward

```text
TARGET
├── 22/tcp  SSH
├── 80/tcp  HTTP
├── 139/tcp NetBIOS
└── 445/tcp SMB
```

At this point, do not immediately exploit something just because a version was printed. Move into service-specific enumeration.

---

## 5. Phase 1 — Enumerate Systematically

Press:

```text
n
```

Use the triage view to answer:

1. What do I know?
2. What have I already checked?
3. What remains untested?
4. Which remaining check is currently the most useful?

For example:

```text
HTTP
✓ Fingerprinting
✓ Server/version
✓ robots.txt

TODO
→ Content discovery
→ Application identification
→ Authentication surface
```

The point is not to execute every item.

The point is to prevent:

> "I completely forgot to check that."

### Status meanings

```text
TODO       = not investigated yet
RUNNING    = currently being investigated
CHECKED    = investigated without a useful finding
FINDING    = produced useful information
DEAD-END   = investigated and currently exhausted
DEFERRED   = deliberately postponed; not considered a dead end
```

Use `d` when something is worth remembering but is not the best use of your time right now.

---

## 6. How to Enumerate a Service With CYB0X

Suppose you discover FTP.

Do not think:

```text
FTP → run every command
```

Think:

```text
FTP detected
   ↓
What can I learn?
   ↓
Version / banner
Anonymous access
Accessible files
Write/upload capability
Authentication surface
Interesting content
   ↓
Finding?
   ↓
Create a follow-up lead
```

For HTTP:

```text
HTTP detected
   ↓
Fingerprint stack
   ↓
Inspect obvious files
   ↓
Content discovery
   ↓
Identify application
   ↓
Inspect authentication/functionality
   ↓
Follow technology-specific leads
```

For SMB:

```text
SMB detected
   ↓
Enumerate shares
   ↓
Check anonymous/guest access
   ↓
Inspect accessible content
   ↓
Identify users/domain information
   ↓
Look for credentials or useful files
```

CYB0X's methodology should guide the checklist. Your judgment determines how deeply to pursue it.

---

## 7. Record Findings, Not Just Commands

A command is not the end of an investigation.

Bad note:

```text
ran smbclient
```

Useful state:

```text
Finding:
Anonymous SMB access is available.

Evidence:
\\10.10.10.20\backup is accessible.

Next question:
What is inside the share and does it contain configuration,
credentials, backups, or other useful information?
```

Use CYB0X to preserve the result and create a lead when appropriate.

The important transition is:

```text
Command
  ↓
Observation
  ↓
Finding
  ↓
Hypothesis
  ↓
Next action
```

This is the part that turns CYB0X from a command checklist into a methodology assistant.

---

## 8. Credentials — Treat Them as Attack-Surface Data

When you find a credential, save it immediately.

Use:

```text
c
```

Then track where it came from and where it has been tested.

Example:

```text
Credential
admin : Winter2026!
Source: backup/config.php

Target        Service       Result
10.10.10.20   SSH           Untested
10.10.10.20   SMB           Valid
10.10.10.30   SSH           Untested
```

The important question becomes:

> **Where else could this credential legitimately apply?**

Do not blindly spray it everywhere. Stay within the lab's authorized scope and use the methodology appropriate to the environment.

A credential discovered during enumeration can change priorities across the entire assessment.

---

## 9. Leads: Turn Discoveries Into Questions

Use:

```text
l
```

to record a useful hypothesis.

Examples:

```text
HIGH — backup.zip may contain credentials
HIGH — discovered credential has not been tested against SSH
MEDIUM — /admin application needs authentication testing
LOW — service version may warrant vulnerability research
```

A good lead is a **question you can test**, not merely a vague reminder.

Bad:

```text
Try harder on HTTP
```

Better:

```text
/admin exists but authentication behavior is unknown.
Investigate the login flow and identify the application.
```

---

## 10. Use `n` Before You Get Lost

`n` is useful at three moments:

### Beginning of a target

```text
What should I enumerate first?
```

### After a finding

```text
What did this finding make relevant?
```

### When stuck

```text
What remains untested?
```

Do not repeatedly press `n` hoping it will solve the machine.

Use its recommendation as a **methodology prompt**, then make the technical decision yourself.

---

## 11. Use `s` When You Are Stuck

When you feel yourself repeating commands or spending too long on one path:

```text
s
```

Use the output to separate:

```text
PROVEN DEAD END
vs.
UNTESTED SURFACE
vs.
UNTAPPED CREDENTIAL
vs.
OTHER OPEN SERVICE
vs.
EXISTING LEAD
```

This is particularly useful on HTB/THM boxes where one interesting service can consume a large amount of time.

A stuck state should lead to a **change in hypothesis**, not just more random enumeration.

---

## 12. The Anti-Rabbit-Hole Rule

Before spending another 20 minutes on the same idea, ask:

```text
What new information am I getting?
```

If the answer is "none," step back.

Use CYB0X to check:

```text
Other open services?
Untested checklist items?
Unused credentials?
Open leads?
New hosts?
New routes?
New evidence?
```

You do not have to finish every checklist item before moving on.

`DEFERRED` exists specifically for this situation.

---

## 13. Exploitation: Only After You Have a Reason

CYB0X should help you arrive at:

```text
Evidence
   ↓
Plausible attack path
   ↓
Validation
   ↓
Exploitation
```

Not:

```text
Version found
   ↓
Random exploit
```

For example:

```text
HTTP
 ↓
Application identified
 ↓
Version/configuration understood
 ↓
Relevant vulnerability suspected
 ↓
Validate applicability
 ↓
Exploit if justified
```

The goal is to learn the reasoning chain.

---

## 14. After Getting a Shell — Enumerate Again

A foothold is not the end of enumeration.

Immediately ask:

```text
Who am I?
What OS is this?
What interfaces exist?
What routes exist?
What users/groups exist?
What processes/services exist?
What credentials or configuration are accessible?
Is there another network?
What privilege-escalation paths exist?
```

The discovery of a new interface or route can completely change the assessment.

Think:

```text
Initial enumeration
        ↓
Foothold
        ↓
Host enumeration
        ↓
New information
        ↓
New attack surface
```

---

## 15. Pivoting

For eJPT-style labs, pivoting should be treated as another enumeration loop, not just a one-time exploitation trick.

When you discover an internal interface/network:

```text
Current host
   ↓
Internal interface / route
   ↓
New subnet
   ↓
Discover reachable hosts
   ↓
Enumerate services
   ↓
Update CYB0X state
```

Record the route/pivot information in CYB0X so you do not have to reconstruct it from terminal history later.

When you discover a new target through a pivot, treat it as a new target in the same assessment—not as a completely separate note-taking exercise.

---

## 16. Evidence and Screenshots

When something matters, preserve proof while the context is fresh.

Useful evidence includes:

- command output proving a finding
- relevant configuration content
- credential source
- successful authentication
- shell identity
- route/interface information
- proof flags where applicable
- screenshots required by the lab/exam

Use:

```text
e
```

for proof/evidence capture where appropriate.

Do not wait until the end to reconstruct everything from terminal history.

---

## 17. HTB / THM / Other Labs

The same workflow works outside eJPT.

### Hack The Box

Use CYB0X when you want a structured methodology while solving a machine:

```text
Target
 ↓
Nmap
 ↓
Services
 ↓
Enumeration
 ↓
Findings
 ↓
Credentials / Leads
 ↓
Exploit
 ↓
Foothold
 ↓
PrivEsc / Pivot
 ↓
Evidence
```

For very familiar or simple boxes, CYB0X may provide less value. That's normal.

### TryHackMe

Use it as a learning scaffold. When a room teaches a particular service, deliberately use CYB0X's methodology rather than immediately following the walkthrough.

### Home labs / VMs

CYB0X works particularly well when you control the targets and can repeat the same machine multiple times. The first attempt can be messy; later attempts can use your recorded methodology to identify what you missed.

---

## 18. eJPTv2 Training Workflow

A strong learning workflow is:

### Pass 1 — Learn

Use CYB0X heavily.

```text
Read the course material
 ↓
Attack the lab yourself
 ↓
Use CYB0X methodology when stuck
 ↓
Record findings and reasoning
 ↓
Finish the lab
```

### Pass 2 — Repeat

Reset the lab and try again with minimal external help.

The goal is to remember the **method**, not the exact answer.

### Pass 3 — Timed practice

Start a fresh workspace and treat the machine/network like a real engagement:

```text
Scope
 ↓
Recon
 ↓
Enumeration
 ↓
Prioritization
 ↓
Exploitation
 ↓
Post-exploitation
 ↓
Pivoting
 ↓
Evidence
```

Use CYB0X to measure whether you are forgetting methodology rather than to tell you the solution.

---

## 19. Recommended TUI Loop

For most sessions, the following loop is enough:

```text
1. Add target / run Initial Recon
2. Review discovered services
3. Press n
4. Pick a high-value check
5. Press r and run/edit the command
6. Inspect the result yourself
7. Mark the check appropriately
8. Record a finding / credential / lead when needed
9. Press n again
10. Repeat
11. When stuck, press s
12. If a foothold appears, switch to post-exploitation
13. If a new route appears, update pivot state
14. Preserve evidence
15. Export when finished
```

### Keybindings worth remembering

| Key | Purpose |
|---|---|
| `n` | State-aware next-action triage |
| `s` | Stuck/rabbit-hole triage |
| `r` | Run selected command recipe |
| `i` | Initial reconnaissance |
| `a` | Add target/ports |
| `c` | Save credential |
| `l` | Add lead/hypothesis |
| `e` | Capture evidence/proof |
| `d` | Defer/un-defer a checklist item |
| `o` | Toggle target scope |
| `x` | Export workspace |
| `?` / `F1` | Help |

---

## 20. What You Should NOT Do With CYB0X

### Don't blindly execute recommendations

A recommendation is a starting point, not an instruction to turn off your brain.

### Don't mark everything CHECKED just to increase coverage

Coverage is useful only when it represents real investigation.

### Don't use DEAD-END as a synonym for DEFERRED

- `DEAD_END`: you investigated it and currently have no useful path.
- `DEFERRED`: you intentionally postponed it.

### Don't record every terminal command as a finding

Commands are activity. Findings are information that changes your understanding of the target.

### Don't turn CYB0X into a walkthrough viewer

If you need a hint, use the methodology to identify the missing concept and then perform the investigation yourself.

---

## 21. The Learning Rule

When CYB0X recommends something, ask yourself:

> **Why is this the next reasonable thing to investigate?**

If you cannot answer, learn the underlying concept before blindly running it.

Over time, the intended progression is:

```text
Beginner
   ↓
Needs CYB0X methodology frequently
   ↓
Recognizes common service patterns
   ↓
Uses CYB0X mainly for state tracking
   ↓
Can enumerate from memory
   ↓
Uses CYB0X as an assessment notebook / copilot
```

The goal is **not dependency**.

The goal is to make you a better pentester.

---

## 22. A Good Session Looks Like This

```text
┌──────────────────────────────────────────────┐
│ TARGET: 10.10.10.20                         │
├──────────────────────────────────────────────┤
│ SERVICES                                     │
│ 22 SSH     80 HTTP     445 SMB              │
│                                              │
│ FINDINGS                                     │
│ ★ Anonymous SMB share                        │
│ ★ /backup discovered                         │
│                                              │
│ CREDENTIALS                                  │
│ admin : ********                             │
│ SSH → untested                              │
│ SMB → valid                                  │
│                                              │
│ LEADS                                        │
│ HIGH: inspect backup                         │
│ HIGH: test credential against SSH            │
│                                              │
│ NEXT: inspect SMB backup contents             │
└──────────────────────────────────────────────┘
```

At that point CYB0X is doing its job: **you can see the state of the assessment without losing your own reasoning.**

---

## 23. Final Principle

Use CYB0X as the layer between your **thinking** and your **terminal**:

```text
                 YOUR REASONING
                       │
                       ▼
              ┌─────────────────┐
              │      CYB0X      │
              │                 │
              │ State           │
              │ Methodology     │
              │ Evidence        │
              │ Findings        │
              │ Credentials     │
              │ Leads           │
              │ Prioritization  │
              └────────┬────────┘
                       │
                       ▼
                    TERMINAL
                       │
                       ▼
                  NEW EVIDENCE
                       │
                       └──────────→ CYB0X
```

**CYB0X should make the assessment easier to think about, not think for you.**

That is the reason to use it for eJPTv2, HTB, THM, home labs, and other authorized penetration-testing practice.

---

## References / Community Context

These are community reports and discussions that informed this workflow. They are not official exam instructions:

- Reddit — [eJPTv2 exam experience: enumerate extensively, treat it like a real pentest](https://www.reddit.com/r/eLearnSecurity/comments/18xg6mu/)
- Reddit — [eJPTv2 pass report: enumeration before and after exploitation](https://www.reddit.com/r/eLearnSecurity/comments/1cfmfp8/)
- Reddit — [eJPTv2 strategy: working across multiple boxes and keeping structured notes](https://www.reddit.com/r/eLearnSecurity/comments/164ey8d/)
- Reddit — [eJPTv2 pass report: notes, tools, pivoting, and practice](https://www.reddit.com/r/eLearnSecurity/comments/14fd1c1/)
- Reddit — [eJPTv2 pass report: pivoting and organizing notes across machines](https://www.reddit.com/r/eLearnSecurity/comments/158rbgf/)
