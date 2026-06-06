# NanoSIEM Roadmap

NanoSIEM is built in four major versions, each adding a complete capability layer
on top of the previous one. Every version is independently useful — v1 is a
fully functional SIEM, v2 adds detection engineering tooling, v3 adds a SOC
operations interface, and v4 adds AI-assisted investigation.

> **Core detection philosophy:**
> Detection in NanoSIEM is performed exclusively by Sigma rules, the correlation
> engine, and the ML anomaly scorer. AI/LLM assistance (v4) operates only
> *after* an alert has been generated — never as a detection mechanism itself.

---

## v1.0 — Core Detection Platform ✅ Released

The foundation: a complete SIEM detection pipeline built from scratch.

| Feature | Status |
|---|---|
| RFC 5424 / RFC 3164 / CEF / JSON / plaintext ingestion | ✅ |
| UDP + TCP syslog, TCP JSON, file tail listeners | ✅ |
| Custom Sigma AST parser and rule evaluator | ✅ |
| `and` / `or` / `not` / `1 of` / `all of` condition support | ✅ |
| Field modifiers: `contains`, `startswith`, `endswith`, `re` | ✅ |
| 7 built-in Sigma detection rules | ✅ |
| Sliding time-window attack chain correlation | ✅ |
| 6 built-in kill-chain detection patterns | ✅ |
| Isolation Forest anomaly detection | ✅ |
| 31-feature extractor with XAI attribution | ✅ |
| Unified alert manager with fingerprint deduplication | ✅ |
| STIX 2.1 bundle export | ✅ |
| SQLite ring buffer storage | ✅ |
| CLI interface (`run`, `tail`, `parse-line`, `stats`) | ✅ |
| 234-test suite across all components | ✅ |
| GitHub Actions CI | ✅ |

---

## v2.0 — Detection Engineering Edition 🔜 Planned

Make NanoSIEM a first-class environment for writing, testing, and shipping
detection rules — the toolchain a detection engineer actually uses daily.

| Feature | Description |
|---|---|
| **MITRE ATT&CK Mapping** | Full technique/tactic taxonomy mapped to all built-in rules and chains; ATT&CK coverage matrix output |
| **Detection-as-Code** | Rules stored as code with version control integration; diff-friendly YAML format |
| **Rule Validation** | Schema validation, condition syntax checking, test fixture requirement enforcement |
| **Rule Unit Testing** | Per-rule test fixtures (positive + negative examples); `nano-siem test-rule <file>` command |
| **Rule Hot Reload** | File watcher; rules reload without restarting the pipeline |
| **Rule Quality Metrics** | False positive rate estimation, coverage overlap detection, rule complexity scoring |
| **Extended Sigma Support** | `near` aggregation, `count` aggregation, timeframe conditions |
| **Sigma Rule Linter** | CLI command to lint rule files before committing |
| **More Built-in Rules** | 50+ rules covering OWASP Top 10, Linux persistence, lateral movement |

---

## v3.0 — SOC Operations Edition 🔜 Planned

Add a real-time SOC operations layer: a web dashboard for alert triage,
threat intelligence enrichment, and ATT&CK coverage visualization.

| Feature | Description |
|---|---|
| **FastAPI Backend** | REST API over the NanoSIEM pipeline; WebSocket stream for live events |
| **React Dashboard** | Real-time alert feed, event timeline, source IP heatmap |
| **Alert Explorer** | Filter/sort/search alerts by severity, type, source, time range |
| **ATT&CK Coverage View** | Interactive MITRE ATT&CK matrix showing which techniques NanoSIEM currently covers |
| **Threat Intelligence Enrichment** | IP reputation lookup (AbuseIPDB, VirusTotal), ASN/geolocation tagging |
| **Alert Case Management** | Assign, acknowledge, escalate, and close alerts from the UI |
| **Saved Searches** | Named queries over the alert log and event ring buffer |
| **Export** | Alert export to CSV, PDF, and STIX bundle ZIP |
| **Multi-source Ingestion** | Elastic Beats, Syslog-ng, rsyslog, Splunk forwarder compatibility |

---

## v4.0 — AI Reasoning Edition 🔜 Planned

Add AI-assisted investigation to the SOC layer. The AI operates exclusively
*after* detection — it reads alerts and explains them. It never performs detection.

> **Design constraint (non-negotiable):**
> Gemini will NEVER be used for detection. Detection remains exclusively:
> Sigma rules, correlation engine, ML anomaly scoring, and threat intelligence.
> Gemini operates only on already-generated alerts.

| Feature | Description |
|---|---|
| **Incident Summaries** | Plain-English summary of an alert or alert cluster for L1 analysts |
| **Analyst Explanations** | "Why did this alert fire?" — maps Sigma condition to the specific matched fields |
| **Executive Reports** | Non-technical incident summaries for CISO/management |
| **MITRE ATT&CK Explanations** | "What does T1110.001 mean, and how does this alert relate to it?" |
| **Threat Narratives** | Multi-alert correlation narrative: "Here is the full story of what the attacker did" |
| **Recommended Actions** | Suggested containment, investigation, and remediation steps per alert type |
| **Knowledge Graph** | Entity relationships: source IPs → alerts → techniques → assets |
| **Attack Replay Engine** | Replay a correlated kill chain event-by-event with analyst commentary |
| **AI Investigation Reports** | Full incident report generated from alert + event data, ready to file |

---

## Contributing to the Roadmap

If you have ideas for features in any version, open an issue with the label
`roadmap` and describe the use case. Sigma rules for v2.0 are especially welcome
— see [CONTRIBUTING.md](CONTRIBUTING.md) for the rule submission process.
