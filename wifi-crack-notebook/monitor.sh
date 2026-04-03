#!/bin/bash
# ============================================================================
# WiFi 破解实时监控 (本地用)
# 所有路径基于脚本所在目录，支持任意位置运行
# 用法: bash monitor.sh
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${SCRIPT_DIR}/work"
POTFILE="${WORK}/hashcat.potfile"
HASHES="${WORK}/hashes_deduped.22000"
LAST_CNT=0

echo "════════════════════════════════════"
echo "  WiFi 破解实时监控 (每5秒刷新)"
echo "════════════════════════════════════"

while true; do
    [ -f "${POTFILE}" ] || { sleep 5; continue; }
    CNT=$(wc -l < "${POTFILE}" | tr -d ' ')
    if [ "$CNT" -gt "$LAST_CNT" ]; then
        clear
        echo "════════════════════════════════════"
        echo "  已破解: ${CNT} 个 WiFi  $(date '+%H:%M:%S')"
        echo "════════════════════════════════════"
        # potfile 格式: hash_hex*ssid_hex:password
        while IFS= read -r line; do
            pw="${line##*:}"
            tmp="${line%:*}"
            ssid_hex="${tmp##*\*}"
            ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
            [ -z "$ssid" ] && ssid="unknown"
            echo ""
            echo "  WiFi: ${ssid}"
            echo "  密码: ${pw}"
        done < "${POTFILE}"
        echo ""
        echo "════════════════════════════════════"
        LAST_CNT=$CNT
    fi
    sleep 5
done
