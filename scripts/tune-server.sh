#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-$HOME/.config/maniac-killer/config.toml}"
mkdir -p "$(dirname "$CONFIG_PATH")"

echo "🔍 [Maniac Killer] Detecting hardware capacity..."

# 1. Detect CPU Cores
if command -v nproc >/dev/null 2>&1; then
    CPUS=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
    CPUS=$(sysctl -n hw.ncpu)
else
    CPUS=4
fi

# 2. Detect Total RAM in MB
if [ -f /proc/meminfo ]; then
    TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_RAM_MB=$(( TOTAL_RAM_KB / 1024 ))
elif command -v sysctl >/dev/null 2>&1; then
    TOTAL_RAM_BYTES=$(sysctl -n hw.memsize)
    TOTAL_RAM_MB=$(( TOTAL_RAM_BYTES / 1024 / 1024 ))
else
    TOTAL_RAM_MB=8192
fi

TOTAL_RAM_GB=$(( TOTAL_RAM_MB / 1024 ))

echo "   ↳ Detected: ${CPUS} CPU Cores, ${TOTAL_RAM_GB} GB RAM"

# 3. Calculate Adaptive CPU Threshold:
# - <=4 cores: 50% capacity (min 150%)
# - 5-16 cores: 25% capacity (min 250%)
# - >16 cores: 15% capacity (min 400%, max 800%)
if [ "$CPUS" -le 4 ]; then
    CALC_CPU=$(( CPUS * 50 ))
    if [ "$CALC_CPU" -lt 150 ]; then CALC_CPU=150; fi
elif [ "$CPUS" -le 16 ]; then
    CALC_CPU=$(( CPUS * 25 ))
    if [ "$CALC_CPU" -lt 250 ]; then CALC_CPU=250; fi
else
    CALC_CPU=$(( CPUS * 15 ))
    if [ "$CALC_CPU" -lt 400 ]; then CALC_CPU=400; fi
    if [ "$CALC_CPU" -gt 800 ]; then CALC_CPU=800; fi
fi

# 4. Calculate Adaptive Memory Threshold:
# 25% of total physical RAM, clamped to [4096MB, 65536MB]
CALC_MEM=$(( TOTAL_RAM_MB / 4 ))
if [ "$CALC_MEM" -lt 4096 ]; then CALC_MEM=4096; fi
if [ "$CALC_MEM" -gt 65536 ]; then CALC_MEM=65536; fi
CALC_MEM_GB=$(( CALC_MEM / 1024 ))

echo "   ↳ Calculated Sizing:"
echo "     • CPU Threshold:     ${CALC_CPU}.0% (sustained across ${CPUS} cores)"
echo "     • Memory Threshold:  ${CALC_MEM} MB (${CALC_MEM_GB} GB, 25% of total RAM)"
echo "     • CPU Streak:        30 checks (5 mins; compilers/SSR: 10 mins)"
echo "     • Alert Cooldown:    120 mins (2 hours)"

# 5. Apply or Update Configuration File
if [ -f "$CONFIG_PATH" ]; then
    echo "📝 Updating existing configuration at: $CONFIG_PATH"
    python3 - << EOF
import re

path = "$CONFIG_PATH"
with open(path, "r") as f:
    content = f.read()

content = re.sub(r'cpu_threshold\s*=\s*[0-9\.]+', f'cpu_threshold = {float("$CALC_CPU")}', content)
content = re.sub(r'cpu_streak\s*=\s*[0-9]+', 'cpu_streak = 30', content)
content = re.sub(r'mem_threshold_mb\s*=\s*[0-9]+', f'mem_threshold_mb = $CALC_MEM', content)

if 'alert_cooldown_mins' in content:
    content = re.sub(r'alert_cooldown_mins\s*=\s*[0-9]+', 'alert_cooldown_mins = 120', content)
else:
    content = content.replace(f'mem_threshold_mb = $CALC_MEM', f'mem_threshold_mb = $CALC_MEM\nalert_cooldown_mins = 120')

with open(path, "w") as f:
    f.write(content)
print("✅ Successfully updated thresholds in", path)
EOF
else
    echo "✨ Generating new configuration at: $CONFIG_PATH"
    RAND_TOKEN="maniac-$(openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(16))')"
    cat << EOF > "$CONFIG_PATH"
# Maniac Killer Hardware-Tuned Configuration
server_name = "$(hostname)"
check_interval_secs = 10
cpu_threshold = ${CALC_CPU}.0
cpu_streak = 30
mem_threshold_mb = ${CALC_MEM}
alert_cooldown_mins = 120
http_port = 19999
http_host = "0.0.0.0"
auth_token = "${RAND_TOKEN}"

custom_whitelist = [
    "claude",
    "serena",
    "orbstack",
    "docker",
    "rybbit",
    "clickhouse",
    "pm2"
]
EOF
fi

echo "🎯 Auto-tuning complete!"
