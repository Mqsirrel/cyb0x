# Contributing to Synapse

Thank you for contributing to **Synapse**! Whether you are a human security engineer, a CTF player, or an autonomous AI agent building on this codebase, please follow these guidelines to keep the codebase robust, well-tested, and reliable.

---

## 🎯 Development Principles

1. **Keep it Lean & Fast:** Avoid adding heavy external database daemons (Postgres, MongoDB) or Docker dependencies. Synapse must run anywhere Python 3.10+ and SQLite exist.
2. **Deterministic Offline Capability:** Always ensure core features (ingestion, methodology matching, credential tracking, export) work completely without internet access.
3. **Safety & Process Control:** When adding command runners, always manage subprocess trees cleanly without leaving orphan processes.
4. **Test-Driven Changes:** Every new feature, parser, or methodology rule must be accompanied by unit tests in `tests/`.

---

## 🛠️ Environment Setup

We recommend using `uv` for fast dependency management:

```bash
# Clone the repository
git clone https://github.com/Mqsirrel/cyb0x.git
cd cyb0x

# Install dependencies and setup virtual environment
uv sync

# Run the test suite
uv run pytest -v
```

---

## 🧪 Testing Guidelines

Run tests with verbose output:
```bash
uv run pytest -v
```

When contributing new parsers or features:
1. Place mock scan data in `sample_scans/` or inline in `tests/test_parsers.py`.
2. Ensure both valid and malformed inputs are tested.
3. Test TUI components asynchronously using Textual's `App.run_test()` pilot harness in `tests/test_tui.py`.

---

## 📝 Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat: ...` for new features (e.g. `feat: add Jenkins script console methodology`)
- `fix: ...` for bug fixes (e.g. `fix: handle blank passwords in NetExec logs`)
- `docs: ...` for documentation changes
- `refactor: ...` for code restructuring without behavior changes
- `test: ...` for adding or updating unit tests

---

## 📄 License
By contributing to Synapse, you agree that your contributions will be licensed under the MIT License.
