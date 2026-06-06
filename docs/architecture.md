# NanoSIEM Architecture

## Pipeline Overview

Every log that enters NanoSIEM travels through a single straight pipeline.
Each stage communicates through one shared object: `NormalizedEvent`.

```
                        ┌─────────────────────────────────────┐
                        │           Log Sources               │
                        │                                     │
                        │  /var/log/auth.log (file tail)      │
                        │  UDP :5140 (syslog RFC 5424/3164)   │
                        │  TCP :5140 (syslog RFC 6587)        │
                        │  TCP :5141 (JSON / filebeat)        │
                        └──────────────┬──────────────────────┘
                                       │  raw bytes
                                       ▼
                        ┌─────────────────────────────────────┐
                        │      asyncio.Queue (max 10,000)     │
                        │      Backpressure buffer            │
                        └──────────────┬──────────────────────┘
                                       │  RawMessage
                                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        INGESTION LAYER                               │
│                                                                      │
│   parser.py                        normalizer.py                     │
│   ┌────────────────────────┐       ┌───────────────────────────┐    │
│   │ Format auto-detection  │       │ IP, port, username extract │    │
│   │ RFC 5424 │ RFC 3164    │──────▶│ Auth outcome tagging      │    │
│   │ CEF      │ JSON        │       │ Program category tagging  │    │
│   │ Plaintext (fallback)   │       │ Fields dict population    │    │
│   └────────────────────────┘       └───────────────┬───────────┘    │
│                                                    │                 │
│                                          NormalizedEvent             │
└────────────────────────────────────────────────────┼─────────────────┘
                                                     │
                         ┌───────────────────────────┼──────────────────────┐
                         │                           │                      │
                         ▼                           ▼                      ▼
        ┌────────────────────────┐  ┌────────────────────────┐  ┌──────────────────────┐
        │   SIGMA LAYER          │  │  CORRELATION LAYER     │  │   ML LAYER           │
        │                        │  │                        │  │                      │
        │  loader.py             │  │  window.py             │  │  features.py         │
        │  YAML → SigmaRule      │  │  Per-source deque      │  │  31-dim extractor    │
        │                        │  │  Sliding window        │  │  Temporal/network/   │
        │  ast.py                │  │  LRU source eviction   │  │  program/message/    │
        │  Condition → AST tree  │  │                        │  │  severity signals    │
        │  and/or/not/1of/allof  │  │  chainer.py            │  │                      │
        │                        │  │  Sequence finder       │  │  baseline.py         │
        │  evaluator.py          │  │  6 built-in chains     │  │  IsolationForest     │
        │  AST walk vs event     │  │  Source-IP grouped     │  │  2000 clean events   │
        │  Field modifier eval   │  │  Alert deduplication   │  │  Calibrated scoring  │
        │  Event enrichment      │  │  Callback system       │  │                      │
        │                        │  │                        │  │  scorer.py           │
        │  7 built-in rules      │  │                        │  │  Score + XAI         │
        └───────────┬────────────┘  └───────────┬────────────┘  └──────────┬───────────┘
                    │                           │                           │
                    │  RuleMatch[]              │  CorrelationAlert[]       │  ScoredEvent
                    └───────────────────────────┼───────────────────────────┘
                                                │
                                                ▼
                        ┌─────────────────────────────────────────┐
                        │           ALERT LAYER                   │
                        │                                         │
                        │  manager.py                             │
                        │  ┌─────────────────────────────────┐   │
                        │  │ Sigma + Correlation + ML → Alert │   │
                        │  │ SHA-256 fingerprint dedup        │   │
                        │  │ Severity filtering               │   │
                        │  │ hit_count increment on repeat    │   │
                        │  └─────────────────────────────────┘   │
                        │                                         │
                        │  stix_output.py                         │
                        │  ┌─────────────────────────────────┐   │
                        │  │ Indicator + Sighting + ObsData   │   │
                        │  │ Deterministic STIX IDs           │   │
                        │  │ MITRE ATT&CK external references │   │
                        │  │ x_nano_siem_* custom properties  │   │
                        │  └─────────────────────────────────┘   │
                        └───────────────┬─────────────────────────┘
                                        │
              ┌─────────────────────────┼──────────────────────────┐
              ▼                         ▼                          ▼
   ┌─────────────────┐       ┌──────────────────┐       ┌──────────────────┐
   │ STIX 2.1 Bundle │       │  NDJSON Alert Log │       │  SQLite Ring     │
   │ alerts/YYYY-MM- │       │  alerts/alerts-   │       │  Buffer          │
   │ DD/alert-*.json │       │  YYYY-MM-DD.ndjson│       │  data/events.db  │
   └─────────────────┘       └──────────────────┘       └──────────────────┘
```

## Key Design Decisions

### 1. NormalizedEvent as the universal interface

Every component reads and writes `NormalizedEvent`. No component ever sees
raw bytes or format-specific objects after the normalizer runs.
This makes every layer independently testable and swappable.

### 2. Bounded async queue for backpressure

The ingestion queue has a hard cap of 10,000 events. When the pipeline is
slow (heavy ruleset, disk writes), listeners drop packets rather than
exhausting memory. Dropping logs is safer than crashing.

### 3. Source-IP grouped correlation

The correlation window groups events by source IP, not by session or timestamp.
This means an attacker who pauses between steps (or uses different source ports)
is still tracked as one sequence. It's attacker-centric, not connection-centric.

### 4. Calibrated ML scoring

The IsolationForest score is normalized using the 1st/99th percentile of training
scores — not a hardcoded `[-0.5, 0.5]` range. This means the threshold is
relative to your actual baseline, not a theoretical distribution.

### 5. Deterministic STIX IDs

STIX object IDs are SHA-256 hashes of `(type, local_id)`. The same alert always
produces the same STIX ID. This enables safe re-ingestion into threat intelligence
platforms without creating duplicate objects.

## Data Flow Example — Brute Force Attack

```
Raw syslog arrives:
  <34>1 2026-06-02T03:00:01Z web-01 sshd 1234 - - Failed password for root from 203.0.113.5

parser.py:
  format = "syslog_rfc5424"
  facility = "auth" (PRI 34 >> 3 = 4)
  severity = "crit" (PRI 34 & 7 = 2)
  host = "web-01", program = "sshd", pid = 1234

normalizer.py:
  source_ip = "203.0.113.5" (regex extracted from message)
  dest_port = 22 (regex extracted "port 22")
  fields.username = "root"
  tags = ["category:auth", "auth:failure"]

sigma/evaluator.py:
  Rule "SSH Brute Force Attempt" → keywords match "Failed password" ✓
  event.sigma_matches = ["SSH Brute Force Attempt"]
  event.tags += ["sigma:ssh_brute_force_attempt", "level:high"]

correlation/chainer.py:
  Source "203.0.113.5" window: [this event]
  Chain "Brute Force → Login": step 1 (brute_force) ✓, step 2 pending...
  No chain fires yet (only 1 step matched)

ml/scorer.py:
  features[3] = 1.0  (is_off_hours = 3am)
  features[7] = 0.0  (source_ip_is_rfc1918 = False, 203.0.113.5 is public)
  features[22] = 1.0 (has_failure_keyword = "Failed")
  score = 0.691 → ANOMALOUS

alerting/manager.py:
  Sigma alert: fingerprint = sha256("sigma:203.0.113.5:SSH Brute Force Attempt")[:16]
  New alert → write STIX bundle + NDJSON entry

[...3 more brute force events arrive, chain step 1 accumulates...]

[Accepted password event arrives from 203.0.113.5]
  Chain "Brute Force → Login": step 1 ✓, step 2 ✓ → CHAIN FIRES
  CorrelationAlert severity=CRITICAL, duration=60s
  STIX bundle written with chain_steps, mitre_tactic, mitre_techniques
```
