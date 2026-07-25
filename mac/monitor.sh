#!/bin/bash
# macOS 本地进度监控（读取 mac/work 或 notebook/work）
MAC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${MAC_DIR}/.." && pwd)"
WORK="${WIFI_WORK_DIR:-${MAC_DIR}/work}"
[ -f "${WORK}/hashcat.potfile" ] || WORK="${REPO_ROOT}/wifi-crack-notebook/work"
POTFILE="${WORK}/hashcat.potfile"
LAST_CNT=0

echo "Mac 破解监控 · potfile=${POTFILE}"
while true; do
    [ -f "${POTFILE}" ] || { sleep 5; continue; }
    CNT=$(wc -l < "${POTFILE}" | tr -d ' ')
    if [ "$CNT" -gt "$LAST_CNT" ]; then
        clear
        echo "已破解: ${CNT}  $(date '+%H:%M:%S')"
        while IFS= read -r line; do
            pw="${line##*:}"
            tmp="${line%:*}"
            ssid_hex="${tmp##*\*}"
            ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
            echo "  WiFi: ${ssid}  密码: ${pw}"
        done < "${POTFILE}"
        LAST_CNT=$CNT
    fi
    sleep 5
done
