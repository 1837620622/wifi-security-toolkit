#!/bin/bash
# 实时监控 WiFi 破解结果
WORK="/Users/chuankangkk/Downloads/Wi-Fi破解/wifi-crack-notebook/work"
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
        hashcat -m 22000 "${HASHES}" --potfile-path "${POTFILE}" --show 2>/dev/null | while IFS=: read hash pw; do
            ssid_hex=$(echo "$hash" | cut -d'*' -f6)
            ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
            bssid=$(echo "$hash" | cut -d'*' -f4)
            mac=$(echo "$bssid" | sed 's/\(..\)/\1:/g; s/:$//')
            echo ""
            echo "  WiFi: ${ssid}"
            echo "  密码: ${pw}"
            echo "  MAC:  ${mac}"
        done
        echo ""
        echo "════════════════════════════════════"
        LAST_CNT=$CNT
    fi
    sleep 5
done
