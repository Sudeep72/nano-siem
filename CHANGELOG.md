## [4.1.0] — 2026-06-13

Patch release adding 5 missing roadmap features across v2/v3/v4.
Tests: 428 (was 332). No breaking changes.

### Added

**Rule Quality Metrics (v2.1) — `detection/quality.py`**
- `assess_rule_quality(rule)` — composite 0-100 maintenance score
- Complexity score: AST depth + node count + field modifier count
- Specificity score: field-match ratio, keyword length, not-filter bonus
- FP risk estimate: low/medium/high with human-readable reasons
- Overlap detection: Jaccard similarity across all rule keyword sets
- `assess_all_rules(rules)` — batch assessment with shared overlap map
- CLI: `nano-siem quality` (sortable table with FP-risk reasons for high-risk rules)
- API: `GET /api/quality`

**Rule Hot Reload (v2.1) — `detection/hot_reload.py`**
- `HotReloadManager` — file-watch loop with configurable check interval
- Validates before swap: broken rules never replace a working rule set
- `ReloadEvent` history with changed_files, errors, and timestamp
- `set_on_reload(callback)` — hook for live rule set updates
- `check_once()` for CLI/manual use, `start()/stop()` for async loop
- Wired into `api/pipeline.py` via `_on_rules_reloaded` → `SigmaEngine.set_rules()`
- `SigmaEngine.set_rules(rules)` — new method for live rule set replacement
- CLI: `nano-siem watch-rules` (--once / --interval flags)
- API: `GET /api/reload/status`

**Threat Intelligence Enrichment (v3.1) — `enrichment/threat_intel.py`**
- `ThreatIntelEnricher` — async IP enrichment with in-memory cache (1hr TTL)
- Geolocation via ip-api.com (free, no key, 45 req/min rate-limited)
- IP reputation via AbuseIPDB free tier (optional `ABUSEIPDB_API_KEY`)
- Private/RFC1918/loopback IPs tagged locally, no external call
- `EnrichmentResult.risk_level` property: internal/unknown/low/medium/high
- AbuseIPDB category code mapping for human-readable abuse type labels
- CLI: `nano-siem enrich <ip>`
- API: `GET /api/enrich/{ip}`

**Knowledge Graph (v4.1) — `reasoning/knowledge_graph.py`**
- `build_knowledge_graph(alerts)` — entity relationship graph from alert list
- Node types: source_ip, host, alert, technique, tactic, chain
- Edge relations: fired, affects, maps_to, belongs_to, part_of
- `describe_entity(graph, entity_id)` — plain-English summary with
  technique/tactic aggregation across connected alerts (2-hop traversal)
- `subgraph_for(node_id, depth)` — bounded subgraph extraction
- Add-node merging with deduplication; no-duplicate edge enforcement
- API: `GET /api/graph`, `GET /api/graph/{entity_id}?depth=`

**Attack Replay Engine (v4.1) — `reasoning/replay.py`**
- `build_replay(alert)` — converts correlation alert chain_steps into
  `ReplaySession`/`ReplayStep` with distributed timestamps
- `build_replay_with_commentary(alert, engine)` — per-step Gemini commentary
  + overall threat narrative via ReasoningEngine
- Raises `ValueError` for non-correlation alerts or empty chain_steps
- CLI: `nano-siem replay <alert_file> [--ai]`
- API: `POST /api/replay`

### New CLI commands
- `nano-siem quality` — rule quality report
- `nano-siem watch-rules` — hot reload watcher
- `nano-siem enrich <ip>` — IP enrichment panel
- `nano-siem replay <file> [--ai]` — step-through attack replay

### New API endpoints
- `GET  /api/quality` — rule quality metrics
- `GET  /api/reload/status` — hot reload status and history
- `GET  /api/enrich/{ip}` — IP geolocation + reputation
- `GET  /api/graph` — full knowledge graph from recent alerts
- `GET  /api/graph/{entity_id}?depth=` — entity subgraph + description
- `POST /api/replay` — attack replay session

### Tests (96 new, 428 total)
- `tests/test_quality.py` — 26 tests
- `tests/test_hot_reload.py` — 14 tests
- `tests/test_enrichment.py` — 26 tests
- `tests/test_knowledge_graph.py` — 24 tests
- `tests/test_replay.py` — 21 tests (with mocked Gemini)


---

## [4.0.0] — 2026-06-07

NanoSIEM v4.0 — AI Reasoning Edition.
Adds Gemini-powered incident explanation, summaries, MITRE context,
executive reports, and threat narratives — all operating exclusively
on already-generated alerts. Detection remains entirely in the engine.

### Added

**AI Reasoning Engine (`reasoning/`)**
- `reasoning/gemini.py` — async Gemini 1.5 Flash client with sliding-window
  rate limiting (free tier: 14 req/min), response caching, and clean error handling
- `reasoning/prompts.py` — 6 prompt templates, all enforcing the core constraint:
  Gemini never performs detection, only explains confirmed alerts
  - `analyst_explanation_prompt` — L1/L2 SOC analyst explanation
  - `incident_summary_prompt` — structured incident report across multiple alerts
  - `mitre_explanation_prompt` — ATT&CK technique context tied to specific alert evidence
  - `recommended_actions_prompt` — prioritized action plan (immediate/investigate/remediate)
  - `executive_report_prompt` — non-technical CISO/leadership report
  - `threat_narrative_prompt` — attack story from attacker + defender perspectives
- `reasoning/engine.py` — `ReasoningEngine` orchestrating all 6 tasks,
  with stats tracking and graceful error handling

**6 New API Endpoints**
- `POST /api/ai/explain` — analyst explanation for a single alert
- `POST /api/ai/summary` — incident summary across multiple alerts
- `POST /api/ai/mitre` — MITRE ATT&CK context for an alert
- `POST /api/ai/recommend` — prioritized action plan for an alert
- `POST /api/ai/report` — executive security report
- `POST /api/ai/narrative` — threat narrative (attacker + defender story)
- `GET  /api/ai/status` — AI configuration status and usage stats

**Dashboard Updates**
- New `AI Analyst` tab — 6 reasoning tasks, multi and single-alert modes,
  alert selector dropdown, live Markdown rendering, token/latency display
- Inline AI panel in every alert card — `Explain`, `Actions`, `ATT&CK` buttons
  that expand inline without leaving the alert feed
- Version banner updated to `v4.0 · AI Reasoning Edition`

**Tests**
- `tests/test_reasoning.py` — 50 new tests covering GeminiClient,
  all 6 prompt builders, system instruction constraints, ReasoningEngine
  with mocked API, error handling, and edge cases
- Total: 332 tests (was 282)

### Design Constraint (enforced in code and tests)
Gemini NEVER performs detection. It only receives Alert objects that were
already generated by Sigma rules, the correlation engine, or the ML scorer.
The system instruction explicitly prohibits detection decisions.
Tests verify this constraint is present in every prompt.

### Configuration
```bash
# Set your free Gemini API key (https://aistudio.google.com/app/apikey)
export GEMINI_API_KEY=your_key_here
nano-siem api
```


---

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
