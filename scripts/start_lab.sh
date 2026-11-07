#!/usr/bin/env bash
# Starts the DVWA lab and waits until the website really answers.
cd "$(dirname "$0")/.."
docker compose -f lab/docker-compose.yml up -d
echo "Waiting for DVWA to be ready..."
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null --max-time 3 -w "%{http_code}" http://localhost:8080/)
  if [ "$code" = "302" ] || [ "$code" = "200" ]; then
    echo "✅ DVWA ready (HTTP $code) after ~$((i*3))s"
    exit 0
  fi
  sleep 3
done
echo "❌ DVWA not ready after 90s (last code: $code). Recent logs:"
docker compose -f lab/docker-compose.yml ps -a
docker compose -f lab/docker-compose.yml logs dvwa --tail 15
exit 1
