# Changelog

All notable changes to NanoSIEM are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

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
- 7 built-in Sigma rules: SSH brute force, login, sudo escalation, port scan, web admin probe, CEF severity, root process execution
- Event enrichment: `sigma_matches` list and tags populated on match

**Attack Chain Correlation**
- Per-source-IP sliding time-window event buffer
- LRU eviction at 10,000 tracked sources
- Greedy forward sequence finder — handles noise between steps
- 6 built-in kill-chain patterns covering the MITRE ATT&CK kill chain
- Alert deduplication: same (chain, source) within 5 min = one alert
- `CorrelationAlert` with step-by-step event attribution

**ML Anomaly Detection**
- Isolation Forest trained on 2000-event synthetic clean baseline
- 31-dimensional feature extractor covering temporal, network, program, message, severity signals
- Percentile-calibrated score normalization (1st/99th percentile of training scores)
- XAI attribution: top-5 features by deviation from baseline on every scored event
- Async load-or-train on startup, model serialized with joblib
- Graceful neutral-score fallback before model loads

**Alert Manager**
- Unified alert object: `sigma`, `correlation`, `ml` source types
- SHA-256 fingerprint deduplication — same alert within window increments `hit_count`
- Severity filtering (`min_severity` config)
- MITRE ATT&CK technique extraction from Sigma rule tags

**STIX 2.1 Export**
- Valid STIX 2.1 bundles: `Indicator` + `Sighting` + `ObservedData`
- Deterministic STIX IDs — same alert always generates same ID
- MITRE ATT&CK external references on indicators
- Custom `x_nano_siem_*` properties: severity, anomaly score, XAI features, chain steps
- NDJSON alert log for downstream tool integration
- Date-organized output: `alerts/YYYY-MM-DD/alert-<id>-<type>.json`

**Storage**
- SQLite ring buffer with WAL mode and 8MB cache
- Bounded to 100,000 events (configurable) with automatic oldest-first eviction
- Async-safe via thread pool executor
- Indexed on timestamp, host, and has_alert

**CLI**
- `nano-siem run` — start network listeners
- `nano-siem tail <file>` — tail a local log file
- `nano-siem parse-line '<log>'` — debug single log line
- `nano-siem stats` — show ring buffer event count

**Tests**
- 234 tests across 6 modules
- `test_parser.py` — 27 tests (all 5 formats)
- `test_normalizer.py` — 26 tests (field mapping, extraction, tagging)
- `test_sigma.py` — 47 tests (loader, AST, evaluator, engine)
- `test_correlation.py` — 42 tests (window, step matching, chains)
- `test_ml.py` — 50 tests (features, training, scoring, XAI)
- `test_alerting.py` — 42 tests (alert construction, dedup, STIX)

**Documentation and Developer Experience**
- `README.md` — full architecture diagram, feature matrix, quickstart
- `ROADMAP.md` — versioned capability plan through v4.0
- `CONTRIBUTING.md` — contribution guide, code style, PR process
- `SECURITY.md` — vulnerability reporting policy
- `config.yaml` — fully documented configuration
- `demo.sh` — end-to-end 5-phase demonstration
- `examples/` — runnable usage scripts
- GitHub Actions CI/CD workflows
- Issue templates: bug report, feature request, Sigma rule submission
- Pull request template

### Performance

- Ingestion throughput: ~55,000 events/sec
- Parse + normalize: 0.018 ms/event
- End-to-end pipeline: < 0.5 ms/event

---

## [Unreleased]

Changes planned for the next release will be listed here.
See [ROADMAP.md](ROADMAP.md) for the full version plan.
