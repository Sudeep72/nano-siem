# Changelog

All notable changes to NanoSIEM are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2026-06-07

NanoSIEM v2.0 — Detection Engineering Edition.
Adds a complete detection engineering toolchain on top of the v1.0 core.

### Added

**MITRE ATT&CK Registry (`detection/mitre.py`)**
- Built-in ATT&CK Enterprise technique registry (curated subset, v14)
- `lookup(technique_id)` — case-insensitive, accepts `T1110`, `attack.t1110.001`
- `techniques_for_tags(tags)` — extract techniques from Sigma rule tag lists
- `coverage_summary(rules)` — tactic → covered techniques map

**Sigma Rule Validator (`detection/validator.py`)**
- Schema validation: required fields, valid level/status values
- AST validation: condition parses, all referenced groups exist
- Completeness checks: description, author, tags, falsepositives, id
- MITRE checks: tags follow `attack.tXXXX` format, technique IDs are known
- Test fixture check: warns if no fixture file found for the rule
- `validate_rule(path)` → `RuleValidationReport` with ERROR/WARNING/INFO results
- `validate_rules_dir(dir)` → batch validation, never crashes on bad files

**Rule Unit Tester (`detection/rule_tester.py`)**
- YAML fixture format: positive and negative test cases per rule
- `run_rule_tests(rule_path, fixture_path)` → `RuleTestReport`
- Auto-discovery of fixture files alongside rules or in `tests/fixtures/`
- Per-test elapsed time measurement
- `run_all_rule_tests(rules_dir)` → batch test runner

**ATT&CK Coverage Reporter (`detection/coverage.py`)**
- `build_coverage_report(rules, chains)` → `CoverageReport`
- Coverage by tactic, technique, and which rules/chains cover each technique
- Output formats: console table (rich), JSON, Markdown
- Coverage percentage against known technique registry

**New CLI Commands (v2.0)**
- `nano-siem validate <path>` — validate rule(s), exit 1 on errors
- `nano-siem validate <path> --strict` — treat warnings as errors
- `nano-siem test-rule <path>` — run rule unit tests against fixtures
- `nano-siem test-rule <path> --fixture <file>` — explicit fixture path
- `nano-siem coverage` — show ATT&CK coverage table
- `nano-siem coverage --format json --output coverage.json`
- `nano-siem coverage --format markdown --output coverage.md`
- `nano-siem list-rules` — list all loaded rules with level/status/tags
- `nano-siem list-rules --level high` — filter by severity level
- `nano-siem --version` — show version string

**New Detection Rules (10 additional, 17 total)**
- `rules/linux/cron_persistence.yml` — suspicious cron job (T1053.003)
- `rules/linux/ssh_key_added.yml` — SSH authorized key added (T1098)
- `rules/linux/passwd_modification.yml` — /etc/passwd modification (T1136)
- `rules/linux/reverse_shell.yml` — reverse shell patterns (T1059.004) CRITICAL
- `rules/linux/setuid_binary.yml` — setuid/setgid bit set (T1548.001)
- `rules/web/sql_injection.yml` — SQL injection attempt (T1190)
- `rules/web/directory_traversal.yml` — directory traversal (T1190)
- `rules/web/command_injection.yml` — command injection (T1190, T1059)
- `rules/network/firewall_drop_spike.yml` — firewall drop rate (T1046)
- `rules/network/dns_exfiltration.yml` — DNS exfiltration patterns (T1071)

**Test Fixtures**
- `tests/fixtures/ssh_brute_force.fixture.yml` — 4 test cases
- `tests/fixtures/privilege_escalation_sudo.fixture.yml` — 3 test cases
- `tests/fixtures/port_scan_detected.fixture.yml` — 3 test cases
- `tests/fixtures/reverse_shell.fixture.yml` — 3 test cases
- `tests/fixtures/sql_injection.fixture.yml` — 3 test cases

**Tests**
- `tests/test_detection.py` — 48 new tests covering all v2.0 components
- Total: 282 tests (was 234)

### Changed
- `pyproject.toml` version bumped to 2.0.0
- `nano_siem/cli/app.py` — expanded with v2.0 commands, `--version` flag
- Rule directory structure reorganized: `rules/linux/`, `rules/web/`, `rules/network/`

---

## [1.0.0] — 2026-06-05

Initial public release of NanoSIEM — a production-grade, minimal-dependency
SIEM engine built from scratch in Python.

### Added

**Ingestion Pipeline**
- Multi-format log parser: Syslog RFC 5424, Syslog RFC 3164, CEF, JSON, plaintext
- Auto-format detection — no configuration required
- Async UDP syslog listener (RFC 3164/5424)
- Async TCP syslog listener (RFC 6587 newline-framed)
- Async TCP JSON listener (newline-delimited JSON, filebeat/fluentd compatible)
- File tail listener for local log ingestion (`/var/log/auth.log` etc.)
- Bounded ingestion queue (10,000 events) with backpressure
- `NormalizedEvent` common schema — all downstream components speak one language
- Field extraction: source/dest IP, ports, usernames, file paths, HTTP fields
- Auth outcome tagging: `auth:failure`, `auth:success`, `category:auth`

**Sigma Rule Engine**
- Hand-rolled recursive descent Sigma condition parser
- Full operator support: `and`, `or`, `not`, `1 of <glob>`, `all of them`
- Field modifiers: `contains`, `startswith`, `endswith`, `re`, exact
- YAML rule loader with validation and graceful skip on bad files
- Hot-reload support: rules reloaded when files change on disk
- 7 built-in Sigma rules
- Event enrichment: `sigma_matches` list and tags populated on match

**Attack Chain Correlation**
- Per-source-IP sliding time-window event buffer
- LRU eviction at 10,000 tracked sources
- Greedy forward sequence finder — handles noise between steps
- 6 built-in kill-chain patterns covering the MITRE ATT&CK kill chain
- Alert deduplication: same (chain, source) within 5 min = one alert

**ML Anomaly Detection**
- Isolation Forest trained on 2000-event synthetic clean baseline
- 31-dimensional feature extractor
- Percentile-calibrated score normalization
- XAI attribution: top-5 features by deviation from baseline

**Alert Manager + STIX 2.1 Export**
- Unified alert object: sigma, correlation, ml source types
- SHA-256 fingerprint deduplication
- Valid STIX 2.1 bundles: Indicator + Sighting + ObservedData
- Deterministic STIX IDs
- NDJSON alert log

**CLI + Storage**
- `nano-siem run`, `tail`, `parse-line`, `stats`
- SQLite ring buffer (WAL mode, 100k event cap)

**Tests**
- 234 tests across 6 modules
