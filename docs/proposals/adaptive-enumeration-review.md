# CYB0X Adaptive Enumeration Review Proposal

## Purpose

This proposal is intentionally a **review plan, not an implementation**. The goal is to have an engineering/review agent inspect CYB0X against real pentesting enumeration workflows and determine what should be changed before implementing an adaptive enumeration engine.

## Why this review exists

Practitioner discussions consistently describe enumeration as a methodology problem rather than a command-dumping problem: people want service-specific checklists, memory aids, notes/state, alternatives when a check fails, and protection against rabbit holes. Recent discussions also emphasize adapting the next action to what has already been discovered rather than blindly running every scanner.

CYB0X already has several strong primitives:

- service-driven methodology checklists
- persistent check state (`TODO`, `RUNNING`, `CHECKED`, `FINDING`, `DEAD_END`)
- target/service state
- credential tracking
- leads/hypotheses
- next-action triage
- workspace persistence

The review should determine whether these primitives are actually connected into a coherent adaptive enumeration system, rather than assuming that the presence of the features is sufficient.

## Core design question

Can CYB0X answer this question at any point in an engagement?

> **Given everything discovered so far, what should I enumerate next, why is it relevant, what evidence would change the next branch, and when is this line of enumeration sufficiently covered?**

If the answer is no, identify the smallest architectural changes required to make it yes.

---

## Review scope

### 1. Repository architecture

Inspect the actual implementation, not only README claims.

Review:

- methodology/profile loading
- `ejptv2.yaml` and other profiles
- service/port models
- target state models
- check execution/state transitions
- Nmap/scan ingestion
- finding extraction
- credential vault and credential-to-target relationships
- lead/hypothesis system
- `n` triage logic
- workspace persistence
- TUI navigation and discoverability
- tests and fixtures

Flag any README feature that is not implemented, partially implemented, or implemented differently from the documented behavior.

### 2. Enumeration methodology model

Determine whether a methodology item currently has enough structure to represent more than a command.

Evaluate whether each check can express:

- objective / question being answered
- service and protocol applicability
- prerequisites
- command(s)
- expected evidence
- useful findings
- follow-up checks triggered by findings
- alternative/manual technique
- completion criteria
- stop/defer conditions
- priority/confidence
- safety/destructiveness classification

Do not add all of these blindly. Recommend the minimum useful schema.

### 3. Adaptive enumeration

Design-review the transition from static checklists to conditional workflows.

Example:

```text
HTTP detected
  -> fingerprint stack
  -> PHP discovered
  -> enable PHP-relevant content discovery
  -> /backup discovered
  -> create investigation lead
  -> credentials found
  -> add credential-reuse checks to relevant services
  -> recalculate next actions
```

The engine should not merely mark checks complete. Findings should be capable of changing what becomes relevant next.

### 4. Evidence-driven state

Review whether CYB0X can distinguish:

- not checked
- checked with no useful result
- checked and evidence collected
- finding discovered
- finding investigated
- blocked/deferred
- not applicable

Assess whether `DEAD_END` is being used too broadly. A dead end should not erase the fact that a service was enumerated; it should record the result/context.

### 5. Next-action triage

Audit the `n` system.

It should prioritize based on the actual state rather than hard-coded service popularity.

Consider inputs such as:

- exposed service
- service/version confidence
- untested checks
- findings
- credentials available
- credential reuse opportunities
- newly discovered hostnames/domains
- accessible shares/files
- authentication state
- existing foothold
- pivot routes
- previous dead ends
- estimated value/cost of a check

The review should explicitly test whether the recommendation engine can explain **why** it selected an action.

### 6. Rabbit-hole handling

Audit `s` / stuck behavior.

A useful system should detect patterns such as:

- repeated work on one low-value service
- many dead ends while another service remains unexplored
- credentials discovered but never tested elsewhere
- a finding with no follow-up investigation
- exhaustive checks on one service before basic checks elsewhere
- repeated equivalent commands

Avoid making the system overly prescriptive. It should surface evidence and alternatives, not pretend to know the single correct attack path.

### 7. eJPTv2 profile accuracy

Review `ejptv2.yaml` against the current official eJPTv2 objectives/materials available to the project owner.

Produce a mapping:

```text
Objective
  -> CYB0X methodology profile item
  -> command/technique
  -> evidence/findings
  -> missing coverage
```

Do not claim certification alignment merely because a YAML profile is named `ejptv2`.

Separate:

- required/core eJPTv2 coverage
- useful supporting pentesting knowledge
- advanced material that belongs in other profiles

This is especially important because the repository currently advertises broader OSCP/AD/pivoting capabilities.

### 8. Human learning vs automation

Review CYB0X against the common failure mode of becoming an AutoRecon-style command launcher.

The system should preserve learning value by exposing:

- what the check is trying to discover
- why it was selected
- what to look for in output
- what findings mean
- what follow-up paths are possible

Avoid automatically running every possible enumeration command.

### 9. Manual alternatives and tool independence

For important enumeration checks, determine whether the profile unnecessarily couples the methodology to one tool.

Example structure:

```text
Goal: enumerate SMB shares

Preferred:
  nxc / smbclient

Alternative:
  rpcclient / enum4linux-ng / manual protocol query

Why:
  tool failure, missing package, unexpected output, learning value
```

The review should recommend where alternatives are valuable and where they would only create noise.

### 10. TUI/UX review

Evaluate whether the user can understand the attack surface quickly.

Important questions:

- Can a user see what is known vs unknown?
- Can they see why a check is recommended?
- Can they jump from finding -> related checks?
- Can they distinguish service coverage from exploitation status?
- Can they defer low-value checks without marking them as failures?
- Can they recover from a rabbit hole without losing context?
- Can they inspect methodology without leaving the workbench?

Do not add UI features unless they solve a demonstrated workflow problem.

---

## Proposed acceptance criteria for the eventual implementation

These are review targets, not a mandate to implement all of them.

### A. Evidence-to-next-action chain

A finding should be able to produce at least one relevant follow-up action or explain why none exists.

### B. Conditional applicability

Checks should be able to become relevant/irrelevant based on discovered facts without requiring the user to manually maintain the entire dependency graph.

### C. Explainable triage

`n` should show the reason for its top recommendation, not only the command.

### D. No command-dump architecture

The methodology engine must remain useful when automated scanners fail, produce incomplete output, or miss the intended path.

### E. Persistent context

State must survive workspace switching/restarts and preserve enough context to understand why a check was completed, deferred, or abandoned.

### F. eJPT separation

The eJPTv2 profile should remain certification-focused while broader techniques stay in broader profiles.

### G. Testability

The adaptive logic should be testable with deterministic fixtures, e.g.:

1. HTTP only -> web enumeration becomes available.
2. HTTP + PHP -> PHP-specific checks become available.
3. SMB + anonymous access -> share/file investigation becomes high priority.
4. Credential found -> credential-reuse checks appear for applicable services/hosts.
5. One service has many dead ends + another has TODO checks -> triage prefers the unexplored surface.
6. Finding produces no known follow-up -> system explicitly says so instead of inventing one.

---

## Explicit non-goals

Do **not** turn this review into:

- a mass addition of tools
- an automatic exploitation framework
- an AI agent that autonomously attacks targets
- a replacement for learning enumeration manually
- a giant checklist with hundreds of mandatory commands
- an assertion that every pentesting technique belongs in eJPTv2

The goal is a compact, explainable methodology/state engine.

## Deliverables requested from the review agent

1. Architecture findings with file/module references.
2. Current enumeration flow diagram.
3. Gaps between current behavior and the adaptive model above.
4. eJPTv2 profile coverage matrix.
5. Recommended minimal data-model changes.
6. Recommended minimal triage changes.
7. Recommended minimal TUI changes.
8. Test plan with concrete fixtures.
9. Explicitly rejected ideas and why they should not be implemented.
10. A phased implementation plan ordered by dependency and risk.

## Research context

Reddit practitioner discussions were used only as workflow/experience signals, not as authoritative certification requirements. Recurring themes include service-specific checklists, detailed methodology notes, manual follow-up after automated enumeration, avoiding rabbit holes, and using what has already been discovered to determine the next move.

The strongest recurring lesson is:

> Enumeration is not just running more commands. It is maintaining an accurate model of the attack surface and using new evidence to decide what to investigate next.
