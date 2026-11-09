#!/usr/bin/env bash
# Start the whole AlertSense demo in the background: lab website, API, sensor, enforcer.
cd "$(dirname "$0")/.."
mkdir -p run
./scripts/start_lab.sh || exit 1

start() {  # start <name> <command...>
  local name=$1; shift
  if [ -f "run/$name.pid" ] && kill -0 "$(cat "run/$name.pid")" 2>/dev/null; then
    echo "• $name already running"; return
  fi
  nohup "$@" > "run/$name.log" 2>&1 &
  echo $! > "run/$name.pid"
  echo "• started $name   (log: run/$name.log)"
}

start api uvicorn app.main:app --host 127.0.0.1 --port 8000
for i in $(seq 1 20); do curl -s -o /dev/null http://127.0.0.1:8000/health && break; sleep 1; done
start sensor python -m sensors.web_sensor
start enforcer python -m sensors.enforcer

echo
echo "✅ AlertSense is running."
echo "   Dashboard : Ports tab -> port 8000 -> open in browser"
echo "   API key   : grep ALERTSENSE_API_KEY .env"
echo "   Logs      : tail -f run/*.log"
echo "   Attack    : ./lab/attack_demo.sh"
echo "   Stop      : ./scripts/stop_all.sh"
