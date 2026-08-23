# SYNAPSE TUI Design Refresh — TODO

> Agreed design plan (parked for later implementation). Full scope: theme + all modals + widgets.
> Direction: **"Claudish" palette** — warm dark charcoal, terracotta/coral accent, cream text,
> sage/kraft secondary tones. No changes to executor, parsers, DB, or export logic — presentation + keybindings only.

## 1. New: `src/synapse/tui/theme.py` (single source of truth)

- Register a Textual `Theme` as `"synapse"`:
  - Background: warm dark charcoal (`#211E1B`), surfaces `#2A2622` (never pure black)
  - Primary/accent: terracotta `#D97757`
  - Text: cream `#EDE6DA`, muted `#A8A099`
  - Warning: kraft `#D4A27F` · Success: sage `#8FA876` · Error: muted red `#C4553B`
- Centralize status-chip style maps currently duplicated as hardcoded hex across
  `service_detail.py`, `lead_board.py`, `triage_modal.py`:
  - Checklist status (TODO / RUNNING / CHECKED / FINDING / DEAD-END)
  - Lead priority + status, target/service status icons
- Shared modal CSS constants (border, header, action bar, key hints).

## 2. New: `src/synapse/tui/modals/base.py` — `SynapseModal(ModalScreen)` base class

- Standard dialog anatomy:
  - `border-title` header (glyph-prefixed, e.g. `▸ EXECUTE — <recipe>`)
  - Optional context/subtitle line (target IP, port, etc.)
  - Content region
  - Bottom action bar: buttons right-aligned, key-hints left-aligned
- Consistent round border, padding, and button variants (Cancel=default, primary action=primary, save=success).

## 3. RunnerModal redesign (centerpiece — see current screenshot problem)

- Border title + target context line (passed in from `app.py` call site).
- Output `TextArea` expands to fill (`height: 1fr`, min-height 10); dialog ~80% height — kills dead space.
- While running: `LoadingIndicator` spinner + buttons disabled.
- Result chips after completion: `✔ EXIT 0 · 27.0s · 2 flags` (sage/red).
- Flag hits rendered as a highlighted strip below output.
- "Save to Evidence" disabled until output exists.
- Keyboard flow: `^R` run, `^S` save, `Esc` cancel, visible key-hint bar.
- Lightweight output highlighting: subprocess pipes strip ANSI, so nmap output is colorless —
  add a small custom `TextArea` highlighter colorizing `open`/`filtered` states, port-table lines,
  STDERR blocks, and summary lines.

## 4. Migrate all 9 other modals onto the base class

`initial_recon`, `triage`, `stuck`, `help`, `export`, `add_target`, `add_cred`, `add_lead`, `add_evidence` —
same header/footer/border pattern, consistent button variants.

## 5. `app.py` + widgets polish

- Register + activate `synapse` theme; replace hardcoded hexes with theme vars.
- Stats banner: replace emojis (🎯⚡✔★🔑🚩) with terminal glyphs, e.g.
  `TGT 3 ▸ SVC 12 · CHK 8/24 · FND 2 · FLAGS 1` + terracotta `NEXT:` chip.
- Widgets (`target_tree`, `service_detail`, `lead_board`, `cred_matrix`) consume centralized
  chips/glyphs from `theme.py`. Zero logic changes.

## 6. Verification

- `uv run pytest -v`
- `uv run synapse --workspace <tmp> ingest sample_scans/*` then launch TUI; smoke-test RunnerModal.
- Screenshot new RunnerModal and compare against the old one before/after.

## Design critique this fixes (from the `r` RunnerModal screenshot)

1. No hierarchy — small cyan title floating in a box; no header bar or target context.
2. Dead space — large gap between output and floating buttons.
3. Default-looking widgets — stock buttons/input, clashing `thick $primary` border, monochrome output.
4. Mouse-only flow in a keyboard-driven tool; no `^R`/`^S` hints.
5. Weak run feedback — plain status label; no spinner, exit-code badge, or flag highlight.
