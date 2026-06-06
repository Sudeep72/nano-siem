#!/usr/bin/env python3
"""
parse_single_log.py — Parse and inspect a single log line through the full pipeline.

Usage:
    python examples/parse_single_log.py
    python examples/parse_single_log.py '<34>1 2026-06-02T10:00:00Z web-01 sshd - - - Failed password'
"""

import sys
import json
import asyncio
from nano_siem.ingestion.parser import parse
from nano_siem.ingestion.normalizer import normalize
from nano_siem.sigma.evaluator import SigmaEngine
from nano_siem.ml.scorer import AnomalyScorer

LINE = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "<34>1 2026-06-02T03:00:01Z web-01 sshd 1234 - - Failed password for root from 203.0.113.5 port 22"
)

# Parse and normalize
parsed = parse(LINE)
event  = normalize(parsed)

print("\n=== Parsed Log ===")
print(f"  Format   : {event.log_source}")
print(f"  Host     : {event.host}")
print(f"  Program  : {event.program}")
print(f"  Source IP: {event.source_ip}")
print(f"  Dest Port: {event.dest_port}")
print(f"  Severity : {event.severity}")
print(f"  Facility : {event.facility}")
print(f"  Tags     : {event.tags}")
print(f"  Message  : {event.message}")

# Sigma evaluation
print("\n=== Sigma Evaluation ===")
engine = SigmaEngine("rules/")
engine.load()
matches = engine.evaluate(event)
if matches:
    for m in matches:
        print(f"  ⚡ FIRED  [{m.rule.level.upper()}] {m.rule.title}")
        print(f"           Tags: {m.rule.tags}")
else:
    print("  ✓ No rules fired")

# ML scoring
print("\n=== ML Anomaly Score ===")
scorer = AnomalyScorer(model_path="data/baseline.joblib", threshold=0.62)
asyncio.run(scorer.load_or_train())
result = scorer.score(event)
status = "ANOMALOUS" if result.is_anomalous else "NORMAL"
print(f"  Score  : {result.anomaly_score:.3f} → {status}")
print(f"  Top drivers:")
for feat, dev in result.top_features[:3]:
    print(f"    {feat:<30} deviation={dev:.3f}")

print()
