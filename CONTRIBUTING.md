# Contributing to NanoSIEM

Thank you for considering a contribution. NanoSIEM is a learning-oriented
open-source project and all contributions are welcome — from fixing a typo
to adding a new Sigma rule to building an entirely new detection component.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Submitting a Sigma Rule](#submitting-a-sigma-rule)
- [Submitting a Correlation Chain](#submitting-a-correlation-chain)
- [Reporting a Bug](#reporting-a-bug)

---

## Code of Conduct

Be respectful. This is a security-focused project — no discussion of
using NanoSIEM for unauthorized access, attacking systems you don't own,
or any other illegal activity.

---

## Ways to Contribute

| Contribution type | Effort | Where to start |
|---|---|---|
| Fix a bug | Low | Open an issue first, then PR |
| Add a Sigma rule | Low | See [Submitting a Sigma Rule](#submitting-a-sigma-rule) |
| Add a correlation chain | Medium | See [Submitting a Correlation Chain](#submitting-a-correlation-chain) |
| Add a log format parser | Medium | `nano_siem/ingestion/parser.py` |
| Add ML features | Medium | `nano_siem/ml/features.py` |
| Improve test coverage | Low–Medium | `tests/` |
| Fix documentation | Low | Edit `.md` files directly |
| Report a bug | Low | Use the bug report template |

---

## Development Setup

```bash
# Clone
git clone https://github.com/Sudeep72/nano-siem.git
cd nano-siem

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run the demo
bash demo.sh
```

### Optional: install linting tools

```bash
pip install ruff mypy
ruff check nano_siem/
mypy nano_siem/ --ignore-missing-imports
```

---

## Code Style

NanoSIEM follows these conventions:

**Python**
- Python 3.10+ syntax (`match`, `|` union types, `dataclass`)
- `ruff` for linting — run `ruff check nano_siem/` before committing
- Type annotations on all public functions
- Docstrings on all public classes and non-trivial functions
- No line longer than 100 characters
- `from __future__ import annotations` at top of every module

**Naming**
- Classes: `PascalCase`
- Functions and variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private helpers: `_leading_underscore`

**Architecture rules (important)**
- Every component communicates through `NormalizedEvent` — never pass raw bytes or format-specific objects downstream
- Detection logic belongs in `sigma/`, `correlation/`, or `ml/` — not in `main.py` or `cli/`
- No new heavy dependencies without a discussion issue first
- New features must come with tests — no untested code merged

---

## Testing Requirements

Every pull request must:

1. Pass all existing tests: `python -m pytest tests/ -v`
2. Include tests for new functionality
3. Not decrease overall test count

Test conventions:
- Test files: `tests/test_<module>.py`
- Test classes: `class Test<Component>:`
- Test methods: `def test_<specific_behavior>(self):`
- Use `tmp_path` pytest fixture for file I/O tests
- Use `MagicMock` for external dependencies — no network calls in tests

---

## Submitting a Pull Request

1. **Fork** the repository and create a branch: `git checkout -b feature/my-feature`
2. **Make your changes** following the code style above
3. **Write tests** for any new functionality
4. **Run the full test suite**: `python -m pytest tests/ -v`
5. **Run the linter**: `ruff check nano_siem/`
6. **Commit** with a clear message:
   ```
   feat(sigma): add Windows event log field modifier support

   Adds 'EventID|' field modifier to the Sigma evaluator so rules
   targeting Windows event logs can match on numeric event IDs.
   Includes 3 new tests in test_sigma.py.
   ```
7. **Open a PR** against the `main` branch using the PR template

### Commit message format

```
<type>(<scope>): <short description>

<optional body>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`
Scopes: `ingestion`, `sigma`, `correlation`, `ml`, `alerting`, `storage`, `cli`, `docs`

---

## Submitting a Sigma Rule

Sigma rules live in `rules/sample/`. To add a new rule:

1. Create a `.yml` file in `rules/sample/` following the Sigma spec
2. Required fields: `title`, `id` (UUID v4), `status`, `level`, `logsource`, `detection`
3. The rule **must** include at least one test case — add a fixture to `tests/fixtures/`
4. The rule **must** be tested by running it against nano-siem:
   ```bash
   nano-siem parse-line '<your test log line>'
   ```
5. Include `falsepositives` to document known benign matches
6. Reference MITRE ATT&CK techniques in `tags` where applicable: `attack.t1110.001`

**Rule template:**

```yaml
title: Descriptive Rule Title
id: <uuid4>
status: experimental       # experimental | test | stable
description: >
  One paragraph describing what this rule detects and why it matters.
author: Your Name
date: 2026-06-01
tags:
  - attack.t1234           # MITRE tactic
  - attack.t1234.001       # MITRE technique
logsource:
  product: linux
  service: sshd            # or: webserver, network, syslog
level: medium              # informational | low | medium | high | critical
detection:
  keywords:
    - 'pattern to match'
  condition: keywords
falsepositives:
  - Known benign scenario that triggers this rule
```

---

## Submitting a Correlation Chain

Correlation chains live in `nano_siem/correlation/chains.py` in the
`BUILTIN_CHAINS` list.

To add a chain:

1. Define the attack scenario clearly — what is the attacker doing?
2. Each `ChainStep` should match on at least 2 different matchers (rule title + tag)
   so the step fires even if the Sigma rule didn't match
3. Choose a realistic `window_seconds` — brute force patterns are fast (60-300s),
   lateral movement can be slow (up to 3600s)
4. Add at least 2 tests in `tests/test_correlation.py`:
   - One that fires the chain (positive case)
   - One that does NOT fire (events in wrong order, or wrong source IP)
5. Document the MITRE ATT&CK tactic and techniques

**Chain template:**

```python
ChainRule(
    id="chain-NNN",
    title="Attack Pattern Title",
    description=(
        "What this chain detects. Describe the attacker behavior "
        "and why this sequence is significant."
    ),
    steps=[
        ChainStep(
            name="step_one",
            matchers=["Sigma Rule Title", "tag:value", "keyword in message"],
        ),
        ChainStep(
            name="step_two",
            matchers=["Another Rule Title", "other:tag"],
        ),
    ],
    window_seconds=300,
    severity="high",
    mitre_tactic="Tactic Name",
    mitre_techniques=["T1234", "T5678"],
),
```

---

## Reporting a Bug

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).

Please include:
- NanoSIEM version (`nano-siem --version` or the git commit hash)
- Python version (`python --version`)
- Operating system
- The log line or input that caused the issue
- The actual behavior vs. expected behavior
- Any error output or tracebacks

For security vulnerabilities, do not open a public issue.
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
