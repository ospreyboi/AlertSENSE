#!/usr/bin/env bash
# Stop the background AlertSense processes (the lab containers keep running).
cd "$(dirname "$0")/.."
for name in enforcer sensor api; do
  if [ -f "run/$name.pid" ]; then
    kill "$(cat "run/$name.pid")" 2>/dev/null && echo "• stopped $name"
    rm -f "run/$name.pid"
  fi
done
echo "Lab containers are still up. To stop them too: docker compose -f lab/docker-compose.yml down"
