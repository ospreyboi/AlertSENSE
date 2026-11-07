#!/usr/bin/env bash
# Starts the Lab site lab and waits until the website really answers.
# If Docker's container state is broken (common after a codespace restart), it rebuilds the lab.
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f lab/docker-compose.yml"

mkdir -p lab/blocklist
[ -s lab/blocklist/blocklist.conf ] || echo "# Managed by AlertSense enforcer" > lab/blocklist/blocklist.conf

if ! $COMPOSE up -d; then
  echo "⚠️  Docker could not start the lab; rebuilding containers..."
  $COMPOSE down --remove-orphans || true
  docker rm -f lab-app-1 lab-proxy-1 2>/dev/null || true
  $COMPOSE up -d || { echo "❌ Docker failed again"; exit 1; }
fi

echo "Waiting for Lab site to be ready..."
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null --max-time 3 -w "%{http_code}" http://localhost:8080/)
  if [ "$code" = "302" ] || [ "$code" = "200" ]; then
    echo "✅ Lab site ready (HTTP $code) after ~$((i*3))s"
    exit 0
  fi
  sleep 3
done
echo "❌ Lab site not ready after 90s (last code: $code)."
$COMPOSE ps -a
$COMPOSE logs proxy --tail 10
exit 1
