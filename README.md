# 🧠 SYNAPSE: Terminal Pentest State Machine & Methodology Copilot

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TUI Framework: Textual](https://img.shields.io/badge/TUI-Textual-teal.svg)](https://textual.textualize.io/)
[![Built For: eJPTv2 • OSCP • CTFs](https://img.shields.io/badge/Certifications-eJPTv2%20%7C%20OSCP%20%7C%20CPTS-red.svg)](#)

> **The keyboard-driven assessment state machine, methodology copilot, and evidence engine built for penetration testers, certification candidates (eJPTv2, OSCP, CPTS, PNPT), and CTF players.**

```
┌── SYNAPSE v1.0 [Workspace: oscp-ad-set] ────────────────────────────────────────────────────────┐
│ 🎯 Targets: 4 (Pwned: 1 | Foothold: 1) │ ⚡ Services: 14 │ ✔ Checks: 12/56 │ 🔑 Creds: 5 │ 🚩 Flags: 2 │
├────────────────────────────────────────┬────────────────────────────────────────────────────────┤
│ Targets & Attack Surface               │ Service: 445/tcp — SMB on 10.10.11.15 (DC01)           │
│  ▼ [green]✔ PWNED[/green] 10.10.11.10 (web01)   │ Product: Windows Server 2019 Standard 17763            │
│     ● 22/tcp  ssh (OpenSSH 8.2p1)      │                                                        │
│     ● 80/tcp  http (Apache 2.4.41)     │ Action Items & Command Recipes:                        │
│     ● 8080/tcp http (Tomcat 9.0)       │  [green]✔ CHECKED [/green] Anonymous / Guest Share Access              │
│  ▶▼ [magenta]★ FOOTHOLD[/magenta] 10.10.11.15 (DC01)  │    Recipe: `netexec smb 10.10.11.15 -u '' -p '' --shares`│
│     ● 88/tcp  kerberos                 │  [yellow]⟳ RUNNING [/yellow] RID Cycling & User Enum                   │
│     ● 389/tcp ldap                     │    Recipe: `netexec smb 10.10.11.15 -u 'guest' -p '' --rid`│
│    ▶● 445/tcp smb                      │  [bold red]★ FINDING [/bold red] AD CS Certificate Template Audit (ESC1) │
│     ● 5985/tcp winrm                   │    Recipe: `certipy find -u 'jsmith@CORP.LOCAL' -p 'Pass'`│
│   ○ 10.10.11.20 (sql01)                │  [white]  [ ] TODO  [/white] Password Spray Discovered Credentials     │
├────────────────────────────────────────┴────────────────────────────────────────────────────────┤
│ [1] Workbench  [2] Cred Vault  [3] Leads Board  [4] Evidence Ledger  [5] Pivot Routes  [x] Export│
│ [a] Add Target │ [c] Add Cred │ [l] Add Lead │ [e] Proof Flag │ [r] Run Recipe │ [Space] Cycle │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 💡 The Problem Synapse Solves

During high-stress timed exams (eJPTv2, OSCP, CPTS) and real assessments, testers struggle with:
1. **Methodology Amnesia & Blind Spots:** Forgetting to check low-hanging fruit on open ports (e.g. anonymous FTP, NFS exports, SNMP community strings, Tomcat manager defaults, SMB RID cycling).
2. **Rabbit-Hole Paralysis:** Spending 3 hours fuzzing complex Web SQLi while overlooking an exposed backup file or weak password on port 445.
3. **Credential & Lateral Movement Sprawl:** Discovered passwords, hashes, and Kerberos tickets scattered across terminal tabs without tracking which targets they've been tested against.
4. **Hour-23 Reporting Panic:** Frantically scrolling through terminal history trying to locate required command proofs (`whoami && ip a && type proof.txt`) and uncropped flag screenshots.
5. **Tool Bloat:** Existing tools (Faraday, Dradis) require Docker, PostgreSQL, and heavy web dashboards, while AutoRecon dumps hundreds of flat text files with zero interactive state.

**Synapse eliminates this friction entirely.** It is a single-binary/pipx-installable terminal workbench that bridges scanner ingestion, interactive methodology checklists, lateral movement tracking, and automated exam reporting.

---

## 🚀 Core Capabilities

### 1. Multi-Source Scan Ingestor
Ingests scan outputs directly into an indexed SQLite workspace:
- **Nmap XML (`-oX`) & Grepable (`-oG`)**: Extracts hosts, hostnames, OS detections, open ports, versions, and NSE script banners.
- **NetExec (nxc) / CrackMapExec**: Automatically extracts discovered domain credentials, NTLM hashes, SMB/WinRM services, and marks administrative compromise (`Pwn3d!`).
- **Rustscan & Masscan**: Ingests fast port scan JSON/list outputs.
- **Plain Text Nmap (`-oN`)**: Robust regex fallback for pasted scan summaries.

### 2. Built-in Methodology Copilot (45+ Services)
Contains an offline, battle-tested knowledge base covering 45+ network services (FTP, SSH, Telnet, SMTP, DNS, TFTP, HTTP, Kerberos, NFS, MSRPC, SMB, SNMP, LDAP, MSSQL, Oracle, MySQL, RDP, WinRM, Redis, MongoDB, AJP Ghostcat, Docker, etc.):
- Automatically attaches prioritized checks (`Recon` → `Enumeration` → `Vulnerability Check` → `Exploitation` → `Privilege Escalation`).
- Generates ready-to-run command recipes with variables auto-substituted (`{IP}`, `{PORT}`, `{HOST}`, `{USER}`, `{PASS}`, `{DOMAIN}`, `{WORDLIST}`).
- Status cycle on every item: `[TODO] ➔ [RUNNING] ➔ [CHECKED] ➔ [FINDING] ➔ [DEAD-END]`.

### 3. Lateral Movement & Credential Vault Matrix
- Centralizes plain-text passwords, NTLM hashes (`LM:NTLM` and `NTLM`), Kerberos tickets, and SSH private keys.
- Maintains a live cross-host testing matrix showing which credentials have been tested against which target IP and protocol, with visual indicators (`✔ Pwn3d`, `✔ Valid`, `✖ Invalid`, `Untested`).

### 4. Hypotheses & Leads Board (Anti-Rabbit Hole Engine)
- Prioritized Kanban-style queue (`Critical`, `High`, `Medium`, `Low`) for tracking attack hypotheses.
- When an action item is marked as `[FINDING]`, Synapse automatically spawns a high-priority follow-up lead.

### 5. Exam Evidence Ledger & Flag Validator
- Validates 32-character MD5 hashes (standard OffSec `user.txt` and `proof.txt` flags) and CTF flag formats (`flag{...}`, `HTB{...}`, `THM{...}`, `EJPT{...}`).
- Logs exact execution commands, raw terminal stdout/stderr, and timestamps.

### 6. Network Pivoting & Route Sentinel
- Visualizes multi-hop lab topology (Ligolo-ng, Chisel reverse SOCKS, SSH dynamic forwarding).
- Displays active local bindings and generates dynamic `proxychains` command prefixes.

### 7. Instant Report & Obsidian Vault Exporter
- **Single Markdown Report (`assessment_report.md`)**: Formatted to OffSec / INE submission guidelines (Executive summary, Credential matrix, Target machine breakdown, Port tables, Findings, and Proof logs).
- **Obsidian Vault (`obsidian_vault/`)**: Generates linked Markdown notes (`[[10.10.11.10]]`, `[[Credentials]]`, `[[Leads]]`) ready to open directly in Obsidian.
- **Full JSON Backup**: 100% lossless state export and import.

### 8. 100% Offline-First + Pluggable AI Advisor
- Functions completely offline without internet or API keys.
- Optionally connects to OpenAI, OpenCode, Anthropic, or local Ollama instances to provide automated banner triage and attack vector recommendations.

---

## 📦 Installation

### Using `uv` (Recommended):
```bash
# Clone the repository
git clone https://github.com/albraa/synapse.git
cd synapse

# Run directly
uv run synapse
```

### Using `pip` or `pipx`:
```bash
pip install -e .
# or
pipx install .
```

---

## ⚡ Quickstart Walkthrough

### 1. Ingest Sample or Real Scans
```bash
# Ingest an Nmap XML scan into a dedicated workspace
synapse --workspace exam ingest sample_scans/oscp_ad_lab.xml

# Ingest NetExec credential spray logs
synapse --workspace exam ingest sample_scans/netexec_ad_spray.log

# Check assessment metrics
synapse --workspace exam status
```

### 2. Launch the Interactive TUI
```bash
synapse --workspace exam
```

### 3. Keybindings in TUI
| Key | Action |
| :--- | :--- |
| **`1` - `5`** | Switch tabs (Workbench, Cred Vault, Leads, Evidence, Pivoting) |
| **`Space`** | Cycle status of selected checklist item or lead (`[TODO]` $\to$ `[CHECKED]` $\to$ `[FINDING]`) |
| **`r`** | Launch Command Runner modal for selected recipe (Edit, execute, capture evidence) |
| **`a`** | Add target host / ports manually |
| **`c`** | Save discovered credential to vault |
| **`l`** | Record new attack lead / hypothesis |
| **`e`** | Capture proof flag / evidence with OffSec validation |
| **`x`** | Export assessment report (Markdown, Obsidian vault, JSON) |
| **`q`** | Quit application |

### 4. CLI Headless Mode (Pipelines & Scripts)
```bash
# Add a target manually
synapse add-target 10.10.11.50 --os Linux -p 22,80,3306

# List scope and open services
synapse list-targets

# Add discovered credentials
synapse add-cred administrator "Winter2024!" --type password --domain CORP.LOCAL --target-ip 10.10.11.50

# List credentials matrix
synapse list-creds

# Export publication-ready report
synapse export --format markdown --output ./final_report.md
```

---

## 🛠️ Custom Methodology Configuration

You can easily extend the built-in methodology by creating `~/.config/synapse/custom_methodology.yaml`:

```yaml
services:
  custom_api:
    ports: [9090, 9443]
    name_patterns: ["custom-api", "microservice"]
    checklists:
      - category: "enum"
        title: "Check Swagger UI & GraphQL endpoint"
        description: "Probe for exposed documentation and schema dumps"
        command_template: "curl -s -i http://{IP}:{PORT}/docs"
```

---

## 🧪 Testing

Synapse includes a comprehensive automated test suite:
```bash
uv run pytest -v
```

---

## 📄 License
MIT License. Built for authorized security testing and education.
