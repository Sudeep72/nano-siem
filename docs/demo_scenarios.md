# NanoSIEM Demo Scenarios

Three demo scenarios for different audiences.
All run against the live pipeline (`nano-siem run` in Terminal 1).

---

## Scenario 1 — "Show me the detection pipeline" (Technical Recruiter / Hiring Manager)

**Time: ~3 minutes**
**Goal:** Show all three detection layers firing simultaneously

```bash
# Terminal 1
nano-siem run

# Terminal 2
bash examples/send_kill_chain.sh
```

**What to narrate:**

Point to each line as it appears in Terminal 1:

1. `⚡ SIGMA [HIGH] SSH Brute Force Attempt` — "This is the Sigma engine. I built a custom recursive descent parser for Sigma's condition language — and/or/not operators, glob patterns, field modifiers like `contains` and `startswith`. It evaluates in under 0.05ms per event."

2. `🔗 CHAIN [CRITICAL] Brute Force Followed by Successful Login | src=203.0.113.5 | 60s` — "This is the correlation engine. It tracks every source IP's event history in a sliding time window. When the attacker goes from failed logins to a successful one, the chain fires — regardless of noise in between."

3. `🤖 ML [ANOMALOUS] score=0.987 | drivers: is_off_hours=0.84, source_ip_is_rfc1918=0.00` — "This is Isolation Forest trained on a synthetic baseline of normal Linux traffic. 3am logins from public IPs score high even with no matching rules."

4. The last event (reverse shell JSON): "Notice — no `⚡ SIGMA` here. No rule matches a `/bin/bash -i >& /dev/tcp/...` command. Only the ML layer caught it. That's the value of layered detection."

5. `📄 STIX [CRITICAL] CORRELATION alert written → alerts/xxxxxxxx` — "Every alert writes a valid STIX 2.1 bundle. These are immediately ingestible by any threat intelligence platform — MITRE ATT&CK references, sighting counts, XAI feature attribution all included."

---

## Scenario 2 — "Show me the code" (Security Engineer Interview)

**Time: ~10 minutes**
**Goal:** Walk through the Sigma AST parser — the most technically interesting component

Open `nano_siem/sigma/ast.py` and walk through:

```python
# This is how Sigma conditions become evaluable trees
def _parse_or(tok, groups):
    left = _parse_and(tok, groups)
    while tok.peek() and tok.peek().lower() == "or":
        tok.consume()
        right = _parse_and(tok, groups)
        left = OrNode(left, right)
    return left
```

**Talk track:**

"The Sigma condition language is like a mini programming language —
`keywords and filter`, `1 of group_*`, `all of them`. I wrote a
recursive descent parser for it from scratch. The precedence is handled
by the nesting order: `_parse_or` calls `_parse_and`, which calls
`_parse_not`, which calls `_parse_atom`. So `A or B and C` naturally
becomes `Or(A, And(B, C))` without any precedence tables."

Then show a rule firing live:

```bash
nano-siem parse-line '<34>1 2026-06-02T03:00:01Z web-01 sshd 1234 - - Failed password for root from 203.0.113.5 port 22'
```

"Every field you see in the output — source IP, username, facility, severity —
was extracted by the normalizer using a combination of format-specific field
mapping and fallback regex extraction. The same interface works whether the
log came from syslog, CEF, or JSON."

---

## Scenario 3 — "Show me the ML" (Data Science / ML-aware Interviewer)

**Time: ~5 minutes**
**Goal:** Explain the Isolation Forest approach and XAI

```bash
python examples/score_events.py
```

**Talk track:**

"The feature extractor produces a 31-dimensional vector for each event.
Every feature is normalized to [0,1]. The features fall into five categories:
temporal — what time of day, is it a weekend; network — source IP, is it
RFC1918, dest port; program — is it an auth program, stable hash of
program name; message content — failure/success keywords, file paths;
and severity/facility from syslog."

"The IsolationForest scores by measuring how many random cuts it takes to
isolate a point. Anomalous points get isolated in fewer cuts because they're
far from the training distribution. I calibrate the score using the 1st/99th
percentile of scores on the training data itself — so the threshold is
relative to your actual baseline, not a hardcoded range."

"The XAI output tells you which features drove the score. When the reverse
shell scored 0.987, the top drivers were `is_off_hours=1.0` (3am),
`source_ip_is_rfc1918=0.0` (public IP), and `dest_port_norm=0.99` (port 4444).
That's directly actionable for an analyst — they know exactly why the model
flagged it."

---

## Quick Reference — Key Numbers to Cite

| Metric | Value |
|---|---|
| Total source code | ~4,500 lines of Python |
| Test count | 234 passing |
| Ingestion throughput | ~55,000 events/sec |
| End-to-end latency | < 0.5 ms/event |
| Sigma rules | 7 built-in, unlimited custom |
| Chain patterns | 6 built-in kill-chain patterns |
| ML features | 31-dimensional feature vector |
| ML training | 2,000 synthetic clean events |
| STIX output | Valid 2.1 bundles, deterministic IDs |
| Dependencies | 6 packages (pyyaml, stix2, scikit-learn, typer, rich, joblib) |

---

## What Makes This Different From "I Used Splunk"

| Splunk / ELK | NanoSIEM |
|---|---|
| Black-box platform | Every component is readable |
| Sigma rules via plugins | Custom Sigma AST parser from scratch |
| Correlation via SPL/KQL | Custom sliding-window correlator |
| ML via add-on products | Isolation Forest built in |
| STIX via integrations | Native STIX 2.1 output |
| Thousands of lines of config | 6 dependencies, `pip install -e .` |
| Can't explain the internals | Can explain every design decision |
