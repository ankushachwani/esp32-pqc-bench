#!/usr/bin/env bash
# Run on the Mac: copy what the build needs to the Pi and compile there. No board access, so no lock.
set -euo pipefail
cd "$(dirname "$0")"
PI="${PI:-ankushachwani@10.0.0.201}"
SSH="ssh -o BatchMode=yes -o HostKeyAlias=pi.local"
rsync -a --delete -e "$SSH" --exclude .pio --exclude .git \
    --include 'firmware/***' --include 'host/***' --include 'common/***' \
    --include 'crypto_kem/' --include 'crypto_kem/ml-kem-*/***' \
    --include 'crypto_sign/' --include 'crypto_sign/ml-dsa-*/***' --include 'crypto_sign/falcon-512/***' \
    --include 'crypto_sign/sphincs-sha2-128?-simple/***' \
    --exclude '*' ./ "$PI:pqc_bench/"
$SSH "$PI" 'cd pqc_bench/firmware && ~/.platformio/penv/bin/pio run 2>&1 | grep -E "error|warning: |RAM:|Flash:|SUCCESS|FAILED"'
# sizes from the linker map, and the versions the numbers belong to
$SSH "$PI" 'cd pqc_bench && mkdir -p results/raw &&
  python3 analysis/code_size.py firmware/.pio/build/esp32dev/firmware.map results/raw/code_size_members.csv &&
  { echo "pio $(~/.platformio/penv/bin/pio --version)";
    echo "platform espressif32 $(python3 -c "import json;print(json.load(open(\"$HOME/.platformio/platforms/espressif32/platform.json\"))[\"version\"])")";
    echo "framework-arduinoespressif32 $(python3 -c "import json;print(json.load(open(\"$HOME/.platformio/packages/framework-arduinoespressif32/package.json\"))[\"version\"])")";
    ~/.platformio/packages/toolchain-xtensa-esp32/bin/xtensa-esp32-elf-size firmware/.pio/build/esp32dev/firmware.elf; } > results/raw/build_info.txt'
