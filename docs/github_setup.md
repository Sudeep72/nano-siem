# GitHub Repository Setup

## Repository Description (140 chars max)

```
Production-grade SIEM engine built from scratch — Sigma detection, attack chain correlation, ML anomaly scoring, and STIX 2.1 export.
```

## Topics / Tags

Add these in the GitHub repository settings under "Topics":

```
siem
sigma
detection-engineering
cybersecurity
anomaly-detection
machine-learning
stix
threat-detection
soc
python
isolation-forest
attack-chain
mitre-attack
log-analysis
security-tools
```

## Social Preview Image

Create a 1280×640 PNG for the GitHub social preview.
Suggested content: NanoSIEM logo + pipeline diagram + key stats
  ("234 tests · 55k events/sec · Sigma + ML + STIX 2.1")

## Repository Settings Checklist

- [ ] Description set (above)
- [ ] Topics added (above)
- [ ] Website set: (your portfolio or LinkedIn)
- [ ] Social preview image uploaded
- [ ] Issues enabled
- [ ] Discussions enabled (for community Q&A)
- [ ] Wikis disabled (use docs/ folder instead)
- [ ] Branch protection on `main`:
      - Require PR reviews: 1
      - Require status checks: CI (test), lint
      - Dismiss stale reviews on new push
- [ ] GitHub Actions enabled

## First Release

```bash
git tag -a v1.0.0 -m "NanoSIEM v1.0.0 — Core Detection Platform

A production-grade, minimal-dependency SIEM engine.

- Sigma rule evaluation with custom AST parser
- Attack chain correlation (6 built-in kill-chain patterns)
- Isolation Forest ML anomaly detection with XAI
- STIX 2.1 alert export
- 234 tests, ~55k events/sec throughput"

git push origin v1.0.0
```

## Pinned Repositories

If pinning on your GitHub profile, use this description:
> NanoSIEM — Built a complete SIEM engine from scratch: Sigma AST parser, sliding-window attack chain correlation, ML anomaly scoring, and STIX 2.1 export. 4,500 lines · 234 tests.
