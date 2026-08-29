# Gemini Agent Prompt — Review All Cyb0x Proposals

You are reviewing the Cyb0x repository as a **senior cybersecurity tooling architect, TUI/UX engineer, and software architecture reviewer**.

Your task is NOT to implement the proposals immediately.

Your task is to inspect the **actual current repository**, understand what already exists, then critically review all proposal documents together and determine what is genuinely worth building.

## Primary objective

Find the strongest fundamental direction for Cyb0x without turning it into an over-engineered project.

Cyb0x is intended to be a practical, stateful penetration-testing/training workspace, especially useful for eJPTv2-style labs. The goal is not merely to create a prettier TUI or a larger checklist collection.

## Read first

Inspect:

1. `README.md`
2. All proposal/design documents under `docs/`
3. The actual source tree
4. Existing domain models
5. Database/schema/migrations
6. Methodology implementation
7. Parsers
8. Execution/runner/session systems
9. Leads/findings/evidence/credential systems
10. TUI/navigation/state management
11. CLI
12. Tests, fixtures, simulations and benchmarks

Do not trust proposal claims until verified against code.

## Proposals to review together

At minimum, review:

- `docs/TUI_PROPOSAL.md` if present
- `docs/TUI_UX_PROPOSAL.md` if present
- `docs/CORE_SYSTEM_PROPOSAL_HONEST_REVIEW.md`
- any other proposal/design documents found under `docs/`

Treat all of them as hypotheses, not requirements.

---

# Part 1 — Current Architecture Audit

Explain what Cyb0x actually is today.

Produce:

```text
Current architecture
├── core/domain
├── persistence
├── execution
├── methodology
├── parsing
├── assessment
├── TUI
├── CLI
├── AI
└── tests
```

For each area identify:

- what exists
- what is mature
- what is duplicated
- what is tightly coupled
- what is missing
- what is surprisingly well designed
- what would be dangerous to rewrite

Use actual file/module references.

Do not recommend restructuring merely because another folder layout looks cleaner.

---

# Part 2 — Proposal Deduplication

Create a matrix:

| Idea | Already exists? | Partially exists? | Truly missing? | Duplicates another proposal? | Value /10 | Complexity /10 |
|---|---|---|---|---|---:|---:|

Pay special attention to overlap between:

- lab/workspace management
- assessment state
- leads
- methodology
- evidence
- sessions
- timeline/events
- replay
- TUI navigation
- AI recommendations

Identify proposals that are actually the same idea described using different terminology.

---

# Part 3 — Investigate the Fundamental Data Model

This is the most important part of the review.

Determine whether Cyb0x would benefit from explicitly separating:

```text
Lab Definition
      ↓
Lab Instance
      ↓
Attempt
      ↓
Assessment State
      ↓
Facts / Observations
      ↓
Actions
      ↓
Results
      ↓
Evidence / Findings
```

Do NOT assume this is correct.

Try to disprove it first.

Answer:

1. What does `Lab` mean in the current code?
2. What does `Workspace` mean?
3. What should persist across attempts?
4. What should reset between attempts?
5. Is an attempt actually a useful abstraction?
6. Are facts/observations currently represented somewhere already?
7. Are commands, results and findings improperly mixed?
8. Would this model simplify or complicate the current architecture?
9. Can it be introduced incrementally?

Give a clear verdict:

```text
KEEP / MODIFY / REJECT
```

---

# Part 4 — Investigate Capability-Based Methodology

Review the proposal to move from tool-specific methodology toward capabilities.

Concept to evaluate:

```text
Fact
 ↓
Rule / Knowledge
 ↓
Capability
 ↓
Available implementation
 ↓
Action
 ↓
Observation
```

Example:

```yaml
capability: HTTP_CONTENT_DISCOVERY
requires:
  - service.http
produces:
  - http.paths
implementations:
  - ffuf
  - gobuster
```

Determine whether this would:

- simplify existing methodology code
- improve eJPTv2 profiles
- allow multiple tool implementations
- improve portability
- reduce hard-coded assumptions
- or simply duplicate the existing methodology architecture

Do not recommend a complex rule engine unless the current project actually needs one.

Give a verdict and a minimal viable architecture if justified.

---

# Part 5 — Training / Scenario Architecture

Investigate whether Cyb0x should have a scenario model independent from the TUI.

Potential structure:

```text
Scenario
├── initial state
├── scope
├── objectives
├── environment metadata
├── expected capabilities
└── evaluation conditions
```

Then:

```text
Scenario
 ↓
Attempt
 ↓
Student actions
 ↓
Observed state
 ↓
Deterministic evaluator
```

Determine whether this is genuinely valuable for eJPTv2 training or whether it would push Cyb0x unnecessarily toward becoming a cyber-range platform.

Explicitly distinguish:

- assessment workspace
- lab scenario engine
- infrastructure provisioning

Cyb0x does NOT need to become a full infrastructure provisioning platform unless the evidence strongly supports it.

---

# Part 6 — Evaluate the TUI Proposals Against the Core Model

Do not review the TUI in isolation.

Ask:

> If the underlying assessment model were improved, which TUI features become natural and which become unnecessary?

Evaluate:

- lab switcher
- resume
- command palette
- breadcrumbs
- global search
- target 360°
- contextual history
- scratchpad
- stuck analysis
- next actions
- blind attempts
- replay
- timeline
- evidence navigation

Separate:

```text
FOUNDATIONAL
HIGH-VALUE UX
NICE POLISH
OVERENGINEERING
```

---

# Part 7 — Security and Safety Architecture

Review whether scope enforcement exists at the correct layer.

Important invariant:

> Discovered does not mean authorized.

Determine whether execution can accidentally bypass scope through another interface, automation path, or AI feature.

Also inspect:

- command execution boundaries
- shell handling
- credential storage
- secrets in logs
- exported data
- path traversal risks
- workspace permissions
- dangerous defaults
- AI-generated commands

This is an authorized security-training/pentesting tool. Do not weaken safety boundaries for convenience.

---

# Part 8 — Data Integrity and Portability

Determine whether Cyb0x can safely support:

```text
Create lab
→ work
→ quit unexpectedly
→ reopen
→ resume
```

and:

```text
Export
→ copy to another machine
→ import
→ resume
```

Inspect database migrations, persistence guarantees, relationships, evidence storage and import/export.

Identify actual failure modes rather than hypothetical ones.

---

# Part 9 — End-to-End Golden Journey

Design one realistic synthetic eJPTv2-style journey using only the current application capabilities.

For example:

```text
Create lab
→ define scope
→ add target
→ discovery
→ service enumeration
→ web investigation
→ credential discovery
→ credential testing
→ access
→ post-exploitation
→ pivot
→ internal target
→ evidence
→ finding
→ report
→ export
→ quit
→ resume
```

For every transition identify:

- current implementation
- missing piece
- awkward UX
- data-model problem
- proposal that would solve it

This is the most important practical validation of the proposals.

---

# Part 10 — Architecture Alternatives

Do NOT assume the proposed architecture is correct.

Compare at least three alternatives:

### A. Current architecture + incremental UX

### B. Stateful assessment engine

```text
State + facts + actions + observations
```

### C. Full scenario/capability architecture

```text
Scenario
 +
Assessment engine
 +
Capabilities
 +
Evaluator
```

Score each on:

| Dimension | A | B | C |
|---|---:|---:|---:|
| Practical value | | | |
| eJPTv2 usefulness | | | |
| Architectural clarity | | | |
| Implementation risk | | | |
| Long-term extensibility | | | |
| Complexity | | | |
| Migration difficulty | | | |

Recommend one.

---

# Part 11 — Be Aggressively Skeptical

For every major proposal ask:

```text
What problem does this solve?
Can the current system already solve it?
How often will a user encounter the problem?
Does it improve the pentest loop?
Does it improve learning?
Does it simplify architecture?
What new state does it introduce?
What can become inconsistent?
What is the migration cost?
Can we test it?
Can we remove it later?
```

Reject impressive-sounding architecture if it doesn't materially improve the product.

Especially challenge:

- graph databases
- event sourcing
- autonomous AI
- giant rule engines
- excessive abstractions
- huge analytics systems
- plugin ecosystems
- web frontends
- infrastructure provisioning

---

# Part 12 — Final Recommendation

Produce four categories:

## BUILD NOW
Only things with clear, demonstrated value and manageable risk.

## INVESTIGATE FIRST
Architectural questions that need experiments before implementation.

## KEEP AS FUTURE
Good ideas that should wait.

## REJECT
Ideas that add more complexity than value.

For every BUILD NOW item provide:

```text
Problem
Why current system is insufficient
Minimal change
Dependencies
Acceptance test
Risk
```

---

# Final Deliverable

End with a concise architecture recommendation:

```text
CYB0X SHOULD BE:

[one paragraph]

CORE MODEL:
[diagram]

TOP 5 CHANGES:
1.
2.
3.
4.
5.

DO NOT BUILD:
...
```

Then provide a proposed implementation sequence in phases.

## Important constraints

- Do not implement code during this review.
- Do not blindly follow proposal documents.
- Do not rewrite working systems without evidence.
- Prefer incremental migration.
- Reuse existing models where possible.
- Keep the deterministic core useful without AI.
- Keep the TUI as an interface, not the source of business logic.
- Optimize for real pentesting/training workflow rather than feature count.
- Every architectural recommendation must be justified by actual repository evidence.
