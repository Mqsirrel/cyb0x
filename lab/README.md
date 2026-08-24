# Lavoisier Synthetic Pentest Lab

A self-contained, deterministic, resettable Docker Compose lab for validating
**cyb0x/Synapse** (`Recon → Enumeration → Vulnerability Assessment →
Exploitation → Foothold → Privilege Escalation → Completion`) without any
external targets (no HTB/THM/INE access required).

```
cyb0x (this repo)
   ↓
localhost (127.0.0.1) / private Docker network 172.29.0.0/24
   ↓
┌────────────────────────────────────────────┐
│ lavoisier-target          172.29.0.10      │
│  • HTTP    :8080  enumeration target       │
│  • SSH     :22    (published :2222)        │
│  • FTP     :21    (published :2121)  decoy │
│  • VAULT-SYNC :31337 custom decoy          │
└────────────────────────────────────────────┘
```

> ⚠️ Authorized synthetic environment only. Everything here is intentionally
> insecure by design and bound to `127.0.0.1`.

---

## 1. Quickstart

```bash
cd lab
docker compose up -d --build        # start (idempotent)
docker compose down -v              # full reset (state lives only in the image)

# Optional black-box integrity verification of the running lab
./verify_lab.sh
```

Ingest the canonical recon artifact into cyb0x:

```bash
uv run synapse --workspace lavoisier ingest lab/scans/nmap_initial.xml
uv run synapse --workspace lavoisier            # launch TUI
```

The published port numbers (2121/2222/8080/31337) deliberately match the
methodology knowledge-base rules (`ftp`, `ssh`, `http` port lists), so
ingestion auto-attaches full checklists exactly as it would on a real box.

## 2. Attack path (intended solution)

| Step | Action | Result |
|------|--------|--------|
| 1 | Port scan the target | 2121/ftp (vsftpd), 2222/ssh (OpenSSH), 8080/http (nginx), 31337/vault-sync |
| 2 | `robots.txt` discloses `/admin/` and `/backups/` (**branch**) | two follow-up paths |
| 3a | `/admin/` — mock creds `admin:LavoisierAdmin2024!` accepted… | **dead end**: "MFA enrollment required" wall |
| 3b | `/backups/` — directory listing exposes `site-backup.tar.gz` (**misconfiguration**) | archive contains `config/db_credentials.txt` |
| 4 | Harvest credentials from the backup (**evidence that changes state**) | `developer:s3cr3t_dev`, plus red herrings |
| 5a | Try harvested creds against vault-sync :31337 | **dead end**: token-only auth, accounts locked |
| 5b | Spray `developer:s3cr3t_dev` against SSH :2222 | valid → **foothold**, read `/home/developer/user.txt` |
| 6 | Post-exploit: `sudo -l` shows NOPASSWD `/usr/local/bin/vault-report.sh`; the script is root-owned but **group-writable by `devops`** (developer is a member) | overwrite script → `sudo` runs it → root shell |
| 7 | Read `/root/proof.txt` | **completion** |

Flags are fixed constants (deterministic across resets):

* `user.txt` → `5f1ec9bb31ae4c7db02a7fa4e91d33c8` (`/home/developer/user.txt`)
* `proof.txt` → `9c2d44af71e05b83ac6d94f20b1e77aa` (`/root/proof.txt`, root-only)

### Credential matrix (mock)

| Username | Password | Where found | Valid on | Outcome |
|----------|----------|-------------|----------|---------|
| `admin` | `LavoisierAdmin2024!` | HTML comment in `/admin/` source | HTTP panel | MFA wall — **dead end** |
| `portal_db` | `Ch3m1st_2024!` | backup archive | nothing exposed | red herring |
| `developer` | `s3cr3t_dev` | backup archive `config/db_credentials.txt` | **SSH :2222** | **foothold** |
| `svc_archive` | `Arch1ve_R3ader!` | backup archive | vault-sync :31337 | locked — **dead end** |

### Intentional dead ends

1. **Anonymous FTP (2121)** — readable, contains only a "share retired" memo.
2. **VAULT-SYNC (31337)** — banner advertises token-only auth; harvested DB
   credentials return "account locked".
3. **`/admin/` MFA wall** — correct default credentials still grant nothing.
4. **HTTP auth-form vuln scanning** — no injection possible; pure rabbit hole.

### Branch points (multiple valid actions)

1. **Post-robots/dirb:** chase `/admin/` (trap) or `/backups/` (solution) —
   both are legitimate next moves; only one pays off.
2. **Post-credential-harvest:** spray at SSH (wins) or vault-sync (loses);
   triage legitimately ranks both surfaces while they are untested.
3. **Post-foothold (guided workflow):** the eJPTv2 profile's prerequisite jump
   unlocks *Privilege Escalation* as soon as foothold + `user_flag` exist,
   before every exploit-phase check is formally closed (non-linear branch).

## 3. Expected assessment state after each stage

These are the exact expectations asserted by
`tests/test_lab_scenario.py` (engine: `get_next_actions`,
`detect_rabbit_holes`, `evaluate_phase_progress` under the default `ejptv2`
profile). Run stages top-to-bottom; each row assumes prior rows completed.

| Stage | Operator actions (as recorded in cyb0x) | Target status | Top next-action (`kind`) | Guided phases (ejptv2) | Notes |
|-------|------------------------------------------|---------------|--------------------------|------------------------|-------|
| **0 Scope** | Add `172.29.0.10 lavoisier.local`, no scans yet | `discovered` | `recon` (P0) — *"Run initial reconnaissance"* | `host_discovery not_started`; downstream `blocked`; **no proof-flag nag on a pristine target** | regression guard: evidence gates stay dormant until surface exists |
| **1 Recon** | Ingest `lab/scans/nmap_initial.xml` | `discovered` | `enum` (P2) covering 2121,2222,8080,31337; 16 recipe checks attached | `host_discovery not_started` (16 pending recipes), rest `blocked` | recon recommendation retires itself |
| **2 Enumeration** | FTP: all 4 checks `dead_end` → service `dead_end`. Vault-sync: banner `checked`, probes `dead_end`. HTTP: stack+robots+dirb `checked`, vhosts `dead_end`. SSH: banner+auth-methods `checked` | mixed | `enum` shrinks as ports close; dead-ended ports never resurface | `host_discovery completed` → `service_enumeration completed` once last enum check closes | dead ends tracked, never re-suggested; stuck report lists them but `is_stuck=False` (surface remains) |
| **3 Vuln assessment** | Add finding *"Exposed backup archive leaks plaintext credentials"* (`vuln_check`, FINDING) on :8080; mark nikto/LFI/auth-form probes `dead_end`; save `developer:s3cr3t_dev` to the vault | http service `vulnerable` | `exploit` (P1) — *"Exploit confirmed finding … :8080"* ranked **above** remaining `enum` (branch #2) | `vulnerability_assessment completed`; `exploitation_foothold` unblocked (gate live, awaits proof) | finding-driven exploit nag is the pivot into stage 4 |
| **4 Exploitation → Foothold** | Mark SSH credential-reuse check `running` (resume hint fires), then `finding` after successful login; record credential test valid; capture `user_flag` evidence; set status `foothold`; close the finding as `checked` | `foothold` | pre-foothold: `resume` then `exploit`; post-foothold with zero open work: **`privesc` nudge** — exactly one action, nothing else | `exploitation_foothold completed` (evidence gate satisfied); `local_privesc` unlocked early via prerequisite jump (branch #3) | evidence changes machine state: flag unlocks the next phase |
| **5 Privilege escalation** | Add `sudo -l` check (`running` → resume hint → `checked`); add *"vault-report.sh group-writable by devops"* `finding` → exploit vector confirmed → `checked`; capture `root_flag`; set status `pwned` | `pwned` | while privesc items are open: global triage stays quiet for owned hosts (pinned semantics) — the **guided workflow** drives via phase-local resume/exploit actions | `local_privesc completed`; `proof_flag in_progress` until root flag captured | foothold hosts must never go fully silent |
| **6 Completion** | Nothing left in scope | `pwned` | **none** — `get_next_actions() == []` | **all six phases `completed`** | `detect_rabbit_holes().is_stuck == False`: completion ≠ rabbit hole (regression fix) |

## 4. What validates what

* `tests/test_lab_scenario.py` — always-on deterministic integration test:
  drives the repository, parsers, methodology engine and assessment engine
  through all seven stages above and asserts every documented state.
* `tests/test_live_lab.py` — opt-in live harness (`SYNAPSE_LIVE_LAB=1` +
  Docker present): boots the compose stack, runs `lab/verify_lab.sh`
  (black-box probes of every weakness/flag/privesc vector), tears it down.
  Skipped automatically elsewhere, so the suite stays green on machines
  without Docker.

## 5. Determinism & observability notes

* All content (pages, banners, flags, credentials, tarball) is static; no
  timestamps leak into responses; logs are silenced.
* Flags and the password hash are hard-coded constants — rebuilds produce a
  byte-equivalent engagement.
* `docker compose down -v && docker compose up -d --build` returns the lab to
  its pristine state (SSH host keys are the only regenerated material).
* Every weakness is observable: HTTP responses carry fixed headers, the
  vault-sync banner names its policy, FTP content explains its own retirement,
  and `verify_lab.sh` prints a pass/fail line per property.
