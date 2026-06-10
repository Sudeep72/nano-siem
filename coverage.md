# NanoSIEM ATT&CK Coverage Report

**Rules loaded:** 17  
**Chains loaded:** 6  
**Techniques covered:** 14 / 25  
**Coverage:** 56.0%

---

## Initial Access

| Technique | ID | Covered By |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Rule: Web Command Injection Attempt, Rule: Directory Traversal Attempt, Rule: SQL Injection Attempt, Chain: Port Scan → Web Admin Probe |

## Execution

| Technique | ID | Covered By |
|---|---|---|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | Rule: Suspicious Root Process Execution, Rule: Web Command Injection Attempt |
| Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Rule: Reverse Shell Attempt |

## Persistence

| Technique | ID | Covered By |
|---|---|---|
| Cron | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Rule: Suspicious Cron Job Added |

## Privilege Escalation

| Technique | ID | Covered By |
|---|---|---|
| Abuse Elevation Control Mechanism | [T1548](https://attack.mitre.org/techniques/T1548/) | Chain: Full Intrusion Kill Chain |
| Setuid and Setgid | [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Rule: Setuid/Setgid Bit Set on File |
| Sudo and Sudo Caching | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Rule: Privilege Escalation via Sudo, Chain: Successful Login Followed by Privilege Escalation |

## Defense Evasion

| Technique | ID | Covered By |
|---|---|---|
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Chain: Brute Force Followed by Successful Login, Chain: Successful Login Followed by Privilege Escalation, Chain: Full Intrusion Kill Chain |

## Credential Access

| Technique | ID | Covered By |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Chain: Port Scan Followed by Brute Force, Chain: Full Intrusion Kill Chain, Chain: Repeated Auth Failures from Single Source |
| Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Rule: SSH Brute Force Attempt, Chain: Brute Force Followed by Successful Login |

## Discovery

| Technique | ID | Covered By |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Rule: Firewall Drop Rate Spike, Rule: Port Scan Detected, Chain: Port Scan Followed by Brute Force, Chain: Port Scan → Web Admin Probe, Chain: Full Intrusion Kill Chain |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Rule: Web Admin Panel Access Attempt |

## Lateral Movement

| Technique | ID | Covered By |
|---|---|---|
| SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Rule: SSH Successful Login |

## Command and Control

| Technique | ID | Covered By |
|---|---|---|
| Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) | Rule: Potential DNS Exfiltration |
