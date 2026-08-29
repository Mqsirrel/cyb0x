# CYB0X User Guide

> A practical, beginner-friendly guide to using CYB0X as a pentesting workspace and eJPTv2 training companion.
>
> This document explains **how to use CYB0X**, not how to solve a particular lab. Only use CYB0X against systems you are authorized to test.

---

## Table of Contents

1. [What is CYB0X?](#1-what-is-cyb0x)
2. [The Core Idea](#2-the-core-idea)
3. [Important Concepts](#3-important-concepts)
4. [Before Your First Lab](#4-before-your-first-lab)
5. [Quick Start](#5-quick-start)
6. [Beginner Workflow: I Just Got an IP Address](#6-beginner-workflow-i-just-got-an-ip-address)
7. [Understanding the Investigation Loop](#7-understanding-the-investigation-loop)
8. [Working With Targets](#8-working-with-targets)
9. [Running Commands](#9-running-commands)
10. [Recording What You Discover](#10-recording-what-you-discover)
11. [Credentials](#11-credentials)
12. [Leads and Hypotheses](#12-leads-and-hypotheses)
13. [Evidence and Findings](#13-evidence-and-findings)
14. [Sessions and Shells](#14-sessions-and-shells)
15. [Multiple Targets and Pivoting](#15-multiple-targets-and-pivoting)
16. [Using CYB0X for eJPTv2 Training](#16-using-cyb0x-for-ejptv2-training)
17. [A Complete Example Lab](#17-a-complete-example-lab)
18. [Getting Unstuck](#18-getting-unstuck)
19. [Repeating and Comparing Attempts](#19-repeating-and-comparing-attempts)
20. [Resuming Work](#20-resuming-work)
21. [Navigation and Shortcuts](#21-navigation-and-shortcuts)
22. [Methodology Profiles](#22-methodology-profiles)
23. [Exporting and Reporting](#23-exporting-and-reporting)
24. [Troubleshooting](#24-troubleshooting)
25. [How the Project is Organized](#25-how-the-project-is-organized)
26. [Safety and Scope](#26-safety-and-scope)
27. [FAQ](#27-faq)

---

# 1. What is CYB0X?

CYB0X is a terminal-based pentesting workspace designed to keep the information that normally gets scattered across terminal tabs, text files, screenshots, notes and browser tabs in one place.

Instead of working like this:

```text
Terminal 1  -> nmap
Terminal 2  -> ffuf
Terminal 3  -> shell
notes.txt   -> credentials
screenshots -> evidence
memory      -> what I already tested
```

CYB0X aims to give you one persistent workspace:

```text
Lab
 └── Attempt
      ├── Targets
      ├── Services
      ├── Credentials
      ├── Sessions
      ├── Leads
      ├── Findings
      ├── Evidence
      ├── Commands / Runs
      └── Investigations
```

CYB0X does **not** replace your understanding of penetration testing. It helps you organize and execute your work so that you can concentrate on the investigation itself.

---

# 2. The Core Idea

The most important concept is the **investigation loop**:

```text
OBSERVE
   ↓
RECORD
   ↓
ASK: What does this tell me?
   ↓
CHOOSE A TEST
   ↓
RUN IT
   ↓
REVIEW THE RESULT
   ↓
UPDATE THE TARGET STATE
   ↓
CHOOSE THE NEXT INVESTIGATION
```

For example:

```text
You discover TCP/80
       ↓
Record HTTP service
       ↓
Investigate the web application
       ↓
Discover /admin
       ↓
Record /admin as an observation
       ↓
Investigate authentication
       ↓
Find a credential
       ↓
Record the credential and its source
       ↓
Test it only where authorized
       ↓
Update access state
```

CYB0X is meant to preserve this chain so you can understand **why you did something and what happened afterward**.

---

# 3. Important Concepts

You will see these concepts throughout the application.

| Concept | Meaning |
|---|---|
| **Lab** | The overall environment you are practicing or testing |
| **Attempt** | One independent run through a lab |
| **Target** | A host, IP, hostname or other scoped asset |
| **Service** | Something exposed by a target, such as HTTP, SSH or SMB |
| **Investigation** | The question or line of inquiry you are currently pursuing |
| **Observation** | Something you actually discovered or verified |
| **Credential** | A username/secret/hash/key discovered during authorized testing |
| **Lead** | A hypothesis or possible next avenue to investigate |
| **Finding** | A confirmed security issue or meaningful result |
| **Evidence** | Material proving what you observed or achieved |
| **Session** | A shell or other access obtained during an authorized engagement |
| **Pivot** | A relationship that allows investigation of another network/host through an existing access point |
| **Run** | A command execution and its recorded result |

A useful distinction is:

```text
Observation = I know this happened.
Lead        = I think this might be worth testing.
Finding     = I verified something significant.
Evidence    = I can prove it.
```

Do not turn guesses into findings.

---

# 4. Before Your First Lab

CYB0X is most useful when the surrounding security tools are available.

Start with the project's diagnostic command if supported by your installed version:

```bash
cyb0x doctor
```

The project may use tools such as:

- `nmap`
- `rustscan`
- `masscan`
- `curl`
- `ffuf`
- `gobuster`
- `feroxbuster`
- `whatweb`
- `nikto`
- `sqlmap`
- `smbclient`
- `netexec`
- `enum4linux-ng`
- `rpcclient`
- `hydra`
- `john`
- `hashcat`
- pivot/tunneling tools where required

The exact tools available depend on your operating system and project version. If a tool is missing, CYB0X should not be treated as if the tool ran successfully.

### First principle

Before testing anything, know your **scope**.

For a lab, that normally means the IPs, hostnames or networks provided by the lab. For real systems, you need explicit authorization.

---

# 5. Quick Start

A normal CYB0X session looks like this:

```text
Start CYB0X
   ↓
Create / open a Lab
   ↓
Create an Attempt
   ↓
Add the target(s)
   ↓
Confirm scope
   ↓
Enumerate
   ↓
Record observations
   ↓
Investigate services
   ↓
Record credentials / leads / findings
   ↓
Track sessions and access
   ↓
Pivot when appropriate
   ↓
Capture evidence
   ↓
Review the attempt
   ↓
Export if needed
```

The exact command-line options and shortcuts can vary with the current implementation. **Use the application's built-in help as the authoritative reference for keys available in your installed version.**

---

# 6. Beginner Workflow: I Just Got an IP Address

This is the section to read if you have never used CYB0X before.

Suppose your authorized lab gives you:

```text
Target: 10.10.10.20
```

You should not immediately start running random exploitation commands.

Your first job is to turn:

```text
10.10.10.20
```

into:

```text
What is this host?
What services are exposed?
What technologies are running?
What attack surface should I investigate?
```

## Step 1 — Create or open your lab

Open CYB0X and create a workspace for the lab.

Give it a useful name, for example:

```text
HTB-style-lab-01
```

or:

```text
eJPT-practice-web-01
```

Then create **Attempt 1**.

Why?

Because later you may want to repeat the same lab without destroying the notes and evidence from your first attempt.

---

## Step 2 — Add the IP as a target

Add:

```text
10.10.10.20
```

Record the scope correctly.

A useful target record should answer:

```text
Target: 10.10.10.20
Scope: IN-SCOPE
Status: DISCOVERED
Notes: Initial lab target
```

Do not invent an operating system, service or vulnerability yet. You do not know those things.

---

## Step 3 — Start with enumeration

Your first question is:

> **What is exposed by this host?**

A typical first investigation is service discovery.

For an authorized lab, a common example is:

```bash
nmap -sV -sC 10.10.10.20
```

For a broader TCP assessment when appropriate to the lab:

```bash
nmap -p- 10.10.10.20
```

The exact scan you choose depends on the environment and your training goals. CYB0X should help you record the result; it should not replace your judgment about scanning scope and intensity.

If you run the command through CYB0X, keep both:

1. the raw command output
2. the structured information extracted from it

---

## Step 4 — Turn the scan into a target picture

Imagine your result is:

```text
22/tcp   open  ssh
80/tcp   open  http
445/tcp  open  microsoft-ds
```

Now your target is no longer just:

```text
10.10.10.20
```

You have an initial attack surface:

```text
10.10.10.20
│
├── 22/tcp  SSH
├── 80/tcp  HTTP
└── 445/tcp SMB
```

Record the services in CYB0X.

Do not immediately mark any of them as vulnerable.

At this point you know they are **exposed**, not necessarily vulnerable.

---

## Step 5 — Investigate one service at a time

Now ask:

> What can I learn about this service?

For HTTP, you might investigate:

```text
What web server is running?
What application is present?
What pages/directories exist?
Does authentication exist?
Are there interesting parameters or files?
```

For SMB:

```text
Is anonymous access allowed?
What shares are visible?
What information can be enumerated?
```

For SSH:

```text
What version is running?
Do I have an authorized credential to test?
Is there a reason to investigate it now?
```

The important point is that **enumeration creates questions**.

---

## Step 6 — Record useful observations

Suppose HTTP enumeration discovers:

```text
/admin
/uploads
/backup
```

Do not leave this buried in terminal output.

Record it in CYB0X as an observation or attach it to the relevant service.

Example:

```text
Target: 10.10.10.20
Service: HTTP
Observation:
  /admin discovered
  /uploads discovered
  /backup discovered
Source:
  directory enumeration
Status:
  UNREVIEWED
```

Now your workspace remembers it.

---

## Step 7 — Turn interesting observations into leads

Suppose `/backup` looks interesting.

Create a lead:

```text
Lead:
Investigate /backup for exposed configuration or sensitive files.

Reason:
Directory enumeration discovered the path.

Status:
BACKLOG
```

This is better than writing:

```text
BACKUP!!!
```

in a random text file and forgetting what you meant later.

---

## Step 8 — Investigate the lead

Now your active investigation becomes:

```text
NOW
Investigate /backup

BEFORE
Directory enumeration discovered /backup

NEXT
Inspect accessible resources and determine whether useful information is exposed
```

This is the idea behind CYB0X's investigation-oriented UX.

You are not simply following a checklist.

You are building a chain of evidence:

```text
Observation
   ↓
Question
   ↓
Test
   ↓
Result
   ↓
New observation
```

---

## Step 9 — If you discover a credential, record it properly

Suppose an authorized lab reveals:

```text
Username: bob
Password: example-password
Source: /backup/config.txt
```

Store it as a credential and record its source.

Do not merely write:

```text
bob:example-password
```

because later you will forget:

- where it came from
- which host it belongs to
- whether it has been tested
- whether it worked

A useful credential record is:

```text
Username: bob
Secret: ********
Source: 10.10.10.20 /backup/config.txt
Status: UNTESTED
```

Only test credentials against systems that are inside your authorized scope.

---

## Step 10 — Update your state after every important result

If the credential works on an authorized SSH service, update the state:

```text
Credential: bob
Target: 10.10.10.20
Service: SSH
Result: VALID
```

If it fails:

```text
Result: INVALID
```

This matters because the same credential may later be relevant to another target in the lab.

---

## Step 11 — Record access as a session

If you obtain an authorized shell:

```text
Target: 10.10.10.20
Service: SSH
User: bob
Privilege: user
```

Record the session.

Now CYB0X can distinguish:

```text
Credential discovered
```

from:

```text
Credential verified
```

from:

```text
Active session obtained
```

Those are three different facts.

---

## Step 12 — Continue from the new state

Once you have access, your questions change.

For example:

```text
What user am I?
What privileges do I have?
What useful local information exists?
Can I identify other reachable hosts?
Are there credentials or configuration details that matter?
```

Record your observations and leads as you go.

Do not assume every possible technique needs to be attempted. Follow the evidence.

---

# 7. Understanding the Investigation Loop

A good CYB0X workflow is not:

```text
Run 50 tools
Dump everything into notes
Hope something works
```

It is:

```text
KNOWN
  ↓
UNKNOWN
  ↓
TEST
  ↓
RESULT
  ↓
UPDATE STATE
  ↓
NEXT TEST
```

For example:

```text
KNOWN
80/tcp HTTP

UNKNOWN
Application technology

TEST
HTTP fingerprinting

RESULT
Apache + application framework

NEW UNKNOWN
Interesting application endpoints

TEST
Directory discovery
```

This way, every action has a reason.

---

# 8. Working With Targets

A target is more than an IP address.

Over time, a target may contain:

```text
10.10.10.20
│
├── Identity
│   ├── hostname
│   └── OS
│
├── Services
│   ├── 22 SSH
│   ├── 80 HTTP
│   └── 445 SMB
│
├── Credentials
│
├── Sessions
│
├── Findings
│
├── Evidence
│
└── Investigations
```

The target view should therefore be your operational starting point when you need to understand one host.

### Switching targets

When a lab contains multiple hosts, switch targets rather than mixing notes from several machines.

Always know which target your current command, credential, finding and evidence belong to.

---

# 9. Running Commands

CYB0X is not intended to hide the command line from you.

A useful execution model is:

```text
Command
  ↓
Execution
  ↓
Raw Output
  ↓
Structured Result
  ↓
State Update
  ↓
Possible Actions
```

For example:

```text
nmap -sV 10.10.10.20
```

produces raw output.

CYB0X can then represent the meaningful information as:

```text
10.10.10.20
22/tcp SSH
80/tcp HTTP
445/tcp SMB
```

The raw output should remain available so you can verify what actually happened.

### Re-running commands

When repeating a test, keep the run history.

This lets you answer:

```text
What did I run?
When did I run it?
What changed?
Why did I run it again?
```

---

# 10. Recording What You Discover

Use three levels:

### Quick note

Something you want to remember immediately.

```text
/backup looks interesting
```

### Structured observation

Something you actually verified.

```text
HTTP
/backup exists
HTTP 200
```

### Finding

A confirmed security issue or significant result supported by evidence.

```text
Sensitive configuration file accessible without authentication.
```

This separation keeps the workspace trustworthy.

---

# 11. Credentials

A credential should have context.

Recommended information:

```text
Username
Secret / hash / key
Domain
Source
Associated target
Test status
Notes
```

Avoid storing credentials in unnecessary exported reports. Treat them as sensitive data.

A credential's lifecycle may look like:

```text
DISCOVERED
   ↓
UNTESTED
   ↓
VALID / INVALID
   ↓
ACCESS
```

---

# 12. Leads and Hypotheses

A lead is a possibility, not a confirmed vulnerability.

Example:

```text
Lead:
Investigate whether the discovered account can access SMB shares.

Why:
Credential was discovered on the same lab host.

Status:
BACKLOG
```

As you work:

```text
BACKLOG
 ↓
IN PROGRESS
 ↓
CONFIRMED
```

or:

```text
BACKLOG
 ↓
IN PROGRESS
 ↓
REJECTED / DEAD END
```

Recording rejected ideas is useful because it prevents you from repeatedly investigating the same dead end.

---

# 13. Evidence and Findings

Evidence answers:

> **How do I prove what I found?**

Useful evidence can include:

- command output
- screenshots
- HTTP responses
- relevant files
- service information
- session output
- proof/flag material when the lab provides it

A finding should connect to evidence.

```text
Finding
  ↓
Why it matters
  ↓
How it was verified
  ↓
Evidence
```

Do not mark something as confirmed merely because a scanner suggested it.

---

# 14. Sessions and Shells

A session represents access you actually obtained.

Record at least:

```text
Target
Access method
User
Privilege level
Time / context
Notes
```

This becomes particularly important when several machines or shells exist.

A useful mental model is:

```text
Credential
   ↓
Successful authentication
   ↓
Session
   ↓
Privilege / local enumeration
```

---

# 15. Multiple Targets and Pivoting

When you discover another authorized target or an internal network, create a separate target record.

For example:

```text
10.10.10.20
  |
  | access / pivot
  ↓
172.16.10.15
```

Keep the relationship explicit.

Record:

```text
Source host
Destination network/host
How reachability was established
Tunnel/session used
What was actually verified
```

This prevents internal targets from becoming a collection of unexplained IP addresses.

---

# 16. Using CYB0X for eJPTv2 Training

CYB0X can be used as a workspace alongside your eJPTv2 learning rather than as a replacement for the course material.

A useful high-level workflow is:

```text
Reconnaissance
    ↓
Enumeration
    ↓
Service / application investigation
    ↓
Vulnerability validation
    ↓
Authorized exploitation
    ↓
Post-exploitation
    ↓
Credential / access tracking
    ↓
Internal enumeration / pivoting where required
    ↓
Evidence and reporting
```

Do not interpret this as a rigid sequence. Real investigations loop back.

For example:

```text
HTTP
 ↓
credential found
 ↓
SMB
 ↓
new information
 ↓
HTTP again
 ↓
foothold
 ↓
local enumeration
 ↓
new target
```

CYB0X should help you move between these investigations without losing context.

---

# 17. A Complete Example Lab

This is a deliberately generic training example. It demonstrates **how to use CYB0X**, not the solution to a particular lab.

## Starting information

You receive:

```text
Target: 10.10.10.20
```

### Create the workspace

```text
Lab: eJPT Practice 01
Attempt: 1
```

### Add target

```text
10.10.10.20
IN-SCOPE
```

### Initial enumeration

Run an appropriate authorized scan.

Suppose you learn:

```text
22/tcp  SSH
80/tcp  HTTP
445/tcp SMB
```

Record the services.

### Investigate HTTP

You identify the web technology and discover:

```text
/admin
/backup
```

Record both observations.

Create a lead:

```text
Investigate /backup.
```

### Investigate the lead

Suppose the lab exposes a configuration file containing a credential.

Record:

```text
Username: example-user
Source: HTTP /backup
Status: UNTESTED
```

### Test the credential where authorized

Suppose it authenticates successfully to SSH.

Update:

```text
Credential → VALID
Session → CREATED
```

### Record the session

```text
10.10.10.20
SSH
example-user
user privilege
```

### Continue investigation

Now investigate the local environment according to your training and the lab's objectives.

Record meaningful observations and leads.

If you identify another reachable host, create it as a separate target and record the relationship.

### Evidence

When you have verified an important result, attach evidence.

### End of attempt

Before closing:

```text
Review targets
Review credentials
Review sessions
Review findings
Review evidence
Review unresolved leads
Export if needed
```

The important outcome is that you can reconstruct the entire investigation later.

---

# 18. Getting Unstuck

When you are stuck, do not immediately run another random tool.

Ask:

```text
What do I know?
What have I not checked?
What did I already rule out?
Which result has not been followed up?
Did I discover a credential that I have not evaluated appropriately?
Is another target now relevant?
```

CYB0X's triage / next-action functionality can help surface unexplored areas.

Treat recommendations as **suggestions**, not truth.

A good recommendation should answer:

```text
WHAT should I investigate?
WHY is it relevant?
WHAT evidence caused the recommendation?
```

If you disagree with it, follow your own investigation path and record why.

---

# 19. Repeating and Comparing Attempts

Repeating a lab is one of the best ways to turn a successful solve into actual skill.

Use separate attempts:

```text
Lab
├── Attempt 1 — solved slowly
├── Attempt 2 — improved enumeration
└── Attempt 3 — timed practice
```

Do not destroy Attempt 1 just to start Attempt 2.

When possible, compare attempts:

```text
Attempt 1
- 60 minutes to discover web service
- missed SMB initially

Attempt 2
- discovered SMB immediately
- reached foothold faster
```

The goal is not merely to solve the box. It is to understand **why the second attempt was better**.

---

# 20. Resuming Work

A persistent workspace should allow you to stop and return later.

When resuming, you should be able to answer:

```text
Which lab?
Which attempt?
Which target?
What was I investigating?
What did I discover last?
What remains unreviewed?
What was my next planned action?
```

A good resume experience takes you back to the investigation rather than simply reopening a random screen.

---

# 21. Navigation and Shortcuts

CYB0X is designed around fast terminal interaction. The exact shortcut set can change as the TUI evolves.

Use:

```text
? / F1
```

for the built-in help in the installed version.

Common concepts include:

| Action | Purpose |
|---|---|
| Command palette | Find actions without memorizing shortcuts |
| Fuzzy search / jump | Find targets, services, credentials and leads |
| Scratchpad | Quickly capture freeform notes |
| Target view | Understand one host and its related state |
| Evidence view | Review proof material |
| Credential view | Review discovered credentials and test state |
| Lead view | Review hypotheses and investigation status |
| Pivot view | Review internal reachability and pivot relationships |

Do not rely on this table if it conflicts with the built-in help of your installed version.

---

# 22. Methodology Profiles

CYB0X can use methodology profiles to organize investigation actions.

The eJPTv2 profile is intended to help organize work around the certification's areas of study.

Other profiles may cover broader network or web application testing.

A methodology profile should be treated as:

```text
A checklist / source of useful investigation ideas
```

not:

```text
A mandatory wizard that prevents you from investigating something else.
```

If evidence points somewhere unexpected, follow the evidence.

---

# 23. Exporting and Reporting

At the end of an engagement or training attempt, useful information includes:

```text
Targets
Services
Commands
Observations
Credentials
Sessions
Findings
Evidence
Leads
Timeline / activity
```

Export only the information appropriate for your destination and audience.

Be especially careful with credentials and other sensitive material.

---

# 24. Troubleshooting

## CYB0X starts but a tool is missing

Run:

```bash
cyb0x doctor
```

Install the missing authorized security tool or configure the environment according to the project documentation.

## A command failed

Check:

```text
Was the tool installed?
Was the command valid?
Was the target reachable?
Was the target in scope?
Did the process actually run?
```

Never treat a failed command as a negative security result.

## I lost track of what I was doing

Return to the active target and inspect:

```text
Current investigation
Recent activity
Unreviewed results
Open leads
Recent command runs
```

## I made a wrong note

Correct the record rather than silently leaving contradictory information.

The goal of the workspace is to remain understandable when you return to it later.

---

# 25. How the Project is Organized

If you are learning the codebase, start by identifying these conceptual layers:

```text
TUI / presentation
       ↓
Application / workflow logic
       ↓
Domain state
       ↓
Persistence
       ↓
External tool execution
```

Methodology profiles belong to the methodology layer rather than being hard-coded into every screen.

When adding a feature, first ask:

1. What user problem does it solve?
2. What domain state does it need?
3. Should the information persist?
4. Which TUI view should expose it?
5. Does it need to be searchable?
6. Does it need evidence/history?
7. Does it work when multiple targets exist?

Avoid putting business logic directly into a visual widget when the behavior should be shared by multiple views.

---

# 26. Safety and Scope

CYB0X is a pentesting and security-training tool.

Only use it against:

- your own systems
- intentionally vulnerable labs
- CTF environments where testing is permitted
- systems for which you have explicit authorization

Keep scope visible.

Before running an active action, know:

```text
WHO authorized the test?
WHAT systems are in scope?
WHAT systems are excluded?
WHAT level of testing is permitted?
```

Do not use credentials, scanning or exploitation against unrelated systems merely because they are reachable.

---

# 27. FAQ

## Should I use CYB0X instead of learning pentesting?

No. Use it to practice and organize what you are learning.

## Should I follow the methodology checklist from top to bottom?

No. It is a guide. Real investigations are iterative.

## What should I do first when I receive an IP?

Confirm scope, create the target, enumerate the exposed attack surface, record the results, and investigate the services systematically.

## Should every command become a finding?

No. Commands create evidence and observations. Findings should represent verified results.

## Why record dead ends?

So you do not waste time repeating the same investigation and so your later review shows how you reached the conclusion.

## Why separate attempts?

To preserve previous work and make repeated practice measurable.

## What is the most important CYB0X habit?

After every meaningful action, ask:

> **What did I learn, and what does that change about what I should investigate next?**

---

# Final Mental Model

If you remember only one thing, remember this:

```text
             CYB0X
               │
             LAB
               │
            ATTEMPT
               │
            TARGET
               │
        INVESTIGATION
               │
       ┌───────┴────────┐
       │                │
    OBSERVE           ACT
       │                │
       └───────┬────────┘
               ↓
             RESULT
               ↓
             RECORD
               ↓
          UPDATE STATE
               ↓
          NEXT QUESTION
               │
               └──────────→ repeat
```

CYB0X should make that loop easier to execute, easier to remember, and easier to reconstruct later.

**Start with the target. Learn what is exposed. Record what you actually discover. Turn interesting observations into investigations. Keep evidence attached to the things it proves. Let the state of the workspace tell you what you have already done — and then make the next decision from the evidence.**
