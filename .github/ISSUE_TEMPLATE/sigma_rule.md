---
name: Sigma Rule Submission
about: Submit a new Sigma detection rule for inclusion
title: '[RULE] '
labels: sigma-rule
assignees: Sudeep72
---

## Rule Summary

**Title:** <!-- e.g. "Suspicious Base64 Encoded Command in Shell" -->
**MITRE Technique:** <!-- e.g. T1059.004 -->
**Severity:** <!-- informational | low | medium | high | critical -->
**Log source:** <!-- linux/sshd, webserver, network, syslog, etc. -->

## Rule YAML

```yaml
title:
id:
status: experimental
description: |

author:
date:
tags:
  - attack.t
logsource:
  product:
  service:
level:
detection:
  keywords:
    -
  condition: keywords
falsepositives:
  -
```

## Test Log Line

Paste a raw log line that this rule should fire on:

```
<paste here>
```

Paste a raw log line that this rule should NOT fire on (to verify no false positive):

```
<paste here>
```

## Why This Rule Matters

Brief justification — what attack does this detect, and why is it valuable?
