<div align="center">

# NanoSIEM

**A production-grade, minimal-dependency SIEM engine built from scratch in Python.**

[![CI](https://github.com/Sudeep72/nano-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/Sudeep72/nano-siem/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-234%20passing-brightgreen.svg)](tests/)
[![STIX 2.1](https://img.shields.io/badge/output-STIX%202.1-orange.svg)](https://oasis-open.github.io/cti-documentation/stix/intro)

*Sigma detection · Attack chain correlation · ML anomaly scoring · STIX 2.1 export*

</div>

---

## What is NanoSIEM?

NanoSIEM is a fully functional SIEM engine written in ~4,500 lines of pure Python.
It implements the same detection pipeline used by enterprise security platforms — but
without the abstraction fog. Every component is readable, testable, and documented.

Built as a learning-by-doing alternative to studying SIEM theory. If you want to
understand how detection engineering actually works at the code level, read this codebase.

```
Log sources → Parse → Normalize → Sigma Eval → Correlate → ML Score → Alert → STIX 2.1
```

---

## Feature Matrix

| Capability | Detail |
|---|---|
| **Log Ingestion** | Syslog RFC 5424, Syslog RFC 3164, CEF, JSON, plaintext — auto-detected |
| **Transport** | UDP syslog, TCP syslog (RFC 6587), TCP JSON, local file tail |
| **Sigma Engine** | Custom AST parser — `and`/`or`/`not`/`1 of`/`all of`, field modifiers (`contains`, `startswith`, `endswith`, `re`) |
| **Correlation** | 6 built-in attack chains, sliding time-window, source-IP grouped, deduplication |
| **ML Detection** | Isolation Forest, 31-feature extractor, percentile-calibrated scoring, XAI attribution |
| **Alerting** | Unified alert manager, severity filtering, dedup by fingerprint |
| **Output** | STIX 2.1 JSON bundles, NDJSON alert log, SQLite ring buffer |
| **CLI** | `run`, `tail`, `parse-line`, `stats` commands via Typer |
| **Tests** | 234 passing, 6 test modules covering all components |
| **Dependencies** | `pyyaml`, `stix2`, `scikit-learn`, `typer`, `rich`, `joblib` — nothing else |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Log Sources                              │
│   UDP Syslog · TCP Syslog · TCP JSON · File Tail                │
└────────────────────────────┬────────────────────────────────────┘
                             │  RawMessage queue (asyncio, bounded 10k)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Ingestion Pipeline                           │
│                                                                 │
│   parser.py          normalizer.py          schema.py           │
│   ┌──────────┐       ┌────────────┐        ┌──────────────┐    │
│   │RFC 5424  │       │ IP extract │        │NormalizedEvent│    │
│   │RFC 3164  │──────▶│ Username   │───────▶│  (common     │    │
│   │CEF       │       │ Auth tags  │        │   schema)    │    │
│   │JSON      │       │ Port parse │        └──────┬───────┘    │
│   │Plaintext │       └────────────┘               │            │
│   └──────────┘                                    │            │
└───────────────────────────────────────────────────┼────────────┘
                                                    │
              ┌─────────────────────────────────────┤
              │                                     │
              ▼                                     ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│   Sigma Rule Engine     │           │  Correlation Engine      │
│                         │           │                         │
│  loader.py              │           │  window.py              │
│  ┌─────────────────┐   │           │  ┌─────────────────┐    │
│  │ YAML → SigmaRule│   │           │  │ Per-source deque │    │
│  └────────┬────────┘   │           │  │ Sliding window   │    │
│           │            │           │  │ LRU eviction     │    │
│  ast.py   │            │           │  └────────┬────────┘    │
│  ┌────────▼────────┐   │           │           │             │
│  │ Condition → AST │   │           │  chainer.py             │
│  │ and/or/not/1of  │   │           │  ┌────────▼────────┐    │
│  └────────┬────────┘   │           │  │ Sequence finder  │    │
│           │            │           │  │ 6 built-in chains│    │
│  evaluator.py          │           │  │ Alert callbacks  │    │
│  ┌────────▼────────┐   │           │  └─────────────────┘    │
│  │ Walk AST vs     │   │           └─────────────────────────┘
│  │ NormalizedEvent │   │
│  └─────────────────┘   │           ┌─────────────────────────┐
└─────────────────────────┘           │   ML Anomaly Scorer     │
                                      │                         │
                                      │  features.py            │
                                      │  ┌─────────────────┐    │
                                      │  │ 31-dim extractor │    │
                                      │  │ temporal/network │    │
                                      │  │ program/message  │    │
                                      │  └────────┬────────┘    │
                                      │           │             │
                                      │  baseline.py            │
                                      │  ┌────────▼────────┐    │
                                      │  │ IsolationForest  │    │
                                      │  │ Calibrated score │    │
                                      │  │ XAI attribution  │    │
                                      │  └─────────────────┘    │
                                      └─────────────────────────┘
                                                    │
                                                    ▼
                              ┌─────────────────────────────────┐
                              │        Alert Manager            │
                              │                                 │
                              │  Sigma + Correlation + ML       │
                              │  Fingerprint deduplication      │
                              │  Severity routing               │
                              └──────────┬──────────────────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                    ▼
             ┌──────────┐       ┌──────────────┐      ┌──────────┐
             │STIX 2.1  │       │ NDJSON alert │      │  SQLite  │
             │ Bundles  │       │    log       │      │  Ring    │
             └──────────┘       └──────────────┘      │  Buffer  │
                                                      └──────────┘
```

---

## Quickstart

### Install

```bash
git clone https://github.com/Sudeep72/nano-siem.git
cd nano-siem
pip install -e .
```

### Run the demo (no setup required)

```bash
bash demo.sh
```

This runs all 5 detection phases against synthetic log data and shows real detections.

### Start the live pipeline

```bash
# Terminal 1 — start nano-siem
nano-siem run

# Terminal 2 — send a simulated attack kill chain
bash examples/send_kill_chain.sh
```

### Tail a local log file

```bash
nano-siem tail /var/log/auth.log
```

### Parse and inspect a single log line

```bash
nano-siem parse-line '<34>1 2026-06-02T03:00:01Z web-01 sshd 1234 - - Failed password for root from 203.0.113.5 port 22'
```

---

## Detection Layers

### Layer 1 — Sigma Rule Evaluation

NanoSIEM ships with 7 built-in Sigma rules and supports loading any Sigma-compatible YAML:

| Rule | Level | MITRE Technique |
|---|---|---|
| SSH Brute Force Attempt | HIGH | T1110.001 |
| SSH Successful Login | LOW | T1021.004 |
| Privilege Escalation via Sudo | MEDIUM | T1548.003 |
| Port Scan Detected | MEDIUM | T1046 |
| Web Admin Panel Access Attempt | MEDIUM | T1190 |
| High Severity CEF Event | HIGH | — |
| Suspicious Root Process Execution | HIGH | T1059 |

Add your own rules in `rules/` — any `.yml` file is auto-loaded.

### Layer 2 — Attack Chain Correlation

6 built-in kill-chain patterns, source-IP grouped across a sliding time window:

| Chain | Steps | Window | Severity |
|---|---|---|---|
| Brute Force → Successful Login | 2 | 10 min | CRITICAL |
| Port Scan → Brute Force | 2 | 5 min | HIGH |
| Login → Privilege Escalation | 2 | 15 min | CRITICAL |
| Port Scan → Web Admin Probe | 2 | 3 min | HIGH |
| Full Intrusion Kill Chain | 4 | 30 min | CRITICAL |
| Repeated Auth Failures (×3) | 3 | 2 min | MEDIUM |

### Layer 3 — ML Anomaly Detection

Isolation Forest trained on a 2000-event synthetic baseline of normal Linux traffic.
31-dimensional feature vector covering temporal, network, program, message, and severity signals.
Detects threats with no rule coverage — including novel attack patterns.

**XAI attribution** explains every anomaly score with the top features driving it:
```
🤖 ML [ANOMALOUS] score=0.987 | drivers: is_error_severity=1.00, is_off_hours=0.84, dest_port_norm=0.67
```

---

## Output

### STIX 2.1 Bundles

Every alert produces a valid STIX 2.1 bundle in `alerts/YYYY-MM-DD/`:

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [
    { "type": "indicator", "name": "SSH Brute Force Attempt", "confidence": 80 },
    { "type": "sighting",  "count": 3, "first_seen": "2026-06-02T03:00:01Z" },
    { "type": "observed-data", "custom_properties": {
        "x_nano_siem_severity": "high",
        "x_nano_siem_anomaly_score": 0.691,
        "x_nano_siem_xai_features": [{"feature": "has_failure_keyword", "deviation": 1.0}]
    }}
  ]
}
```

### NDJSON Alert Log

`alerts/alerts-YYYY-MM-DD.ndjson` — one JSON object per line, easy to pipe to any downstream tool.

---

## Configuration

All settings in `config.yaml`:

```yaml
ingestion:
  syslog_host: "0.0.0.0"
  syslog_port: 5140
  syslog_protocol: "tcp"     # tcp | udp
  json_port: 5141

ml:
  train_on_startup: true
  anomaly_threshold: 0.62    # 0.0–1.0, higher = stricter

alerting:
  dedup_window_seconds: 300
  min_severity: "low"        # low | medium | high | critical
  stix_output: true
```

---

## Sending Logs to NanoSIEM

```bash
# TCP Syslog (RFC 5424)
echo '<34>1 2026-06-02T03:00:01Z web-01 sshd - - - Failed password for root from 1.2.3.4' \
  | nc -q1 localhost 5140

# TCP JSON
echo '{"host":"web-01","process":"nginx","message":"GET /admin HTTP/1.1 403","level":"warn"}' \
  | nc -q1 localhost 5141

# CEF (via TCP syslog port)
echo 'CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=192.168.1.5 dst=10.0.0.1' \
  | nc -q1 localhost 5140
```

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

```
234 passed in 3.13s
```

Test coverage spans all 5 detection layers:

| Module | Tests |
|---|---|
| `test_parser.py` | 27 — RFC5424, RFC3164, CEF, JSON, plaintext |
| `test_normalizer.py` | 26 — field mapping, IP/port/user extraction, auth tagging |
| `test_sigma.py` | 47 — loader, AST builder, evaluator, engine integration |
| `test_correlation.py` | 42 — window buffer, step matching, chain detection |
| `test_ml.py` | 50 — feature extraction, training, scoring, XAI |
| `test_alerting.py` | 42 — alert construction, dedup, STIX output |

---

## Project Structure

```
nano-siem/
├── nano_siem/
│   ├── schema.py              # NormalizedEvent — the pipeline's common language
│   ├── main.py                # Async pipeline orchestrator
│   ├── ingestion/
│   │   ├── parser.py          # RFC5424 / RFC3164 / CEF / JSON / plaintext
│   │   ├── normalizer.py      # ParsedLog → NormalizedEvent + field extraction
│   │   └── listener.py        # UDP, TCP syslog, TCP JSON, file tail listeners
│   ├── sigma/
│   │   ├── loader.py          # Sigma YAML → SigmaRule dataclass
│   │   ├── ast.py             # Detection block → evaluable AST
│   │   └── evaluator.py       # AST evaluation + SigmaEngine
│   ├── correlation/
│   │   ├── chains.py          # 6 built-in ChainRule definitions
│   │   ├── window.py          # Per-source sliding time-window buffer
│   │   └── chainer.py         # Sequence detection + Correlator
│   ├── ml/
│   │   ├── features.py        # 31-dimensional feature extractor
│   │   ├── baseline.py        # IsolationForest trainer + corpus generator
│   │   └── scorer.py          # Per-event anomaly scoring + XAI
│   ├── storage/
│   │   └── ringbuffer.py      # SQLite-backed event ring buffer
│   ├── alerting/
│   │   ├── manager.py         # Alert dedup, severity routing
│   │   └── stix_output.py     # STIX 2.1 bundle serializer
│   └── cli/
│       └── app.py             # Typer CLI
├── rules/sample/              # 7 built-in Sigma rules
├── tests/                     # 234 tests across 6 modules
├── examples/                  # Runnable usage examples
├── config.yaml                # All configuration
└── demo.sh                    # End-to-end 5-phase demo
```

---

## Performance

Benchmarked on a standard laptop (Python 3.13, single core):

| Metric | Value |
|---|---|
| Ingestion throughput | ~55,000 events/sec |
| Parse + normalize latency | 0.018 ms/event |
| Sigma evaluation (7 rules) | ~0.05 ms/event |
| ML scoring (IsolationForest) | ~0.1 ms/event |
| End-to-end pipeline latency | < 0.5 ms/event |
| Memory (1000 sources, 500 events each) | ~100 MB |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full version plan.

| Version | Focus | Status |
|---|---|---|
| v1.0 | Core detection platform | ✅ Released |
| v2.0 | Detection Engineering Edition | 🔜 Planned |
| v3.0 | SOC Operations Edition | 🔜 Planned |
| v4.0 | AI Reasoning Edition | 🔜 Planned |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome — especially new Sigma rules, correlation chain patterns, and additional log format parsers.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
Built by <a href="https://github.com/Sudeep72">Sudeep Ravichandran</a> · Indiana University Bloomington, MS Cybersecurity Risk Management
</div>
