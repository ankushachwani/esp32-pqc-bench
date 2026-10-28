#!/usr/bin/env bash
# Run on the Mac. Builds on the Pi, then takes the shared board lock only for flash + measurement, then copies results back.
# Extra args go to host/run_bench.py (e.g. --quick --out /tmp/q).
set -euo pipefail
cd "$(dirname "$0")"
PI="${PI:?set PI=user@host of the machine the ESP32 is plugged into}"
SSH="ssh -o BatchMode=yes ${SSH_OPTS:-}"
./sync_build.sh
$SSH "$PI" "cd pqc_bench && mkdir -p results/raw logs && flock -w 3600 /usr/local/share/esp32.lock bash -c '
  (cd firmware && ~/.platformio/penv/bin/pio run -t upload --upload-port /dev/ttyUSB0 2>&1 | tail -2) &&
  python3 host/run_bench.py $* 2>&1 | tee logs/run_bench.log'"
if [ -z "${NO_COPY:-}" ]; then
  rsync -a -e "$SSH" "$PI:pqc_bench/results/raw/" results/raw/
  rsync -a -e "$SSH" "$PI:pqc_bench/logs/run_bench.log" results/raw/run_bench.log
fi
