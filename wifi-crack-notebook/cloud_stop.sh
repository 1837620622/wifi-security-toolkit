#!/bin/bash
# ============================================================================
# AutoDL算力云 (www.autodl.com) - 停止破解任务
# 自动检测环境: 云端本地直接执行 / Mac通过SSH远程执行
# 用法: bash cloud_stop.sh
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"

# ── AutoDL SSH 配置 (从环境变量读取或手动填写) ──
CLOUD_HOST="${CLOUD_HOST:-connect.westc.seetacloud.com}"
CLOUD_PORT="${CLOUD_PORT:-22}"
CLOUD_PASS="${CLOUD_PASS:-}"

# ── 自动检测运行环境 ──
run_cmd() {
    if [ -f /root/wifi-crack/crack_cloud.sh ] || [ "$(whoami)" = "root" ]; then
        eval "$1"
    else
        if [ -n "$CLOUD_PASS" ]; then
            SSHPASS="$CLOUD_PASS" sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                -p "$CLOUD_PORT" "root@${CLOUD_HOST}" "$1"
        else
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                -p "$CLOUD_PORT" "root@${CLOUD_HOST}" "$1"
        fi
    fi
}

echo "── 停止AutoDL算力云 (www.autodl.com)破解任务 ──"

# 先显示当前破解结果
run_cmd '
POTFILE="/root/wifi-crack/work/hashcat.potfile"
HASHES="/root/wifi-crack/work/hashes_deduped.22000"
if [ -f "$POTFILE" ] && [ -s "$POTFILE" ]; then
    CNT=$(wc -l < "$POTFILE" | tr -d " ")
    echo "  当前破解结果 (${CNT} 条):"
    hashcat -m 22000 "$HASHES" --potfile-path "$POTFILE" --show 2>/dev/null | while IFS= read -r line; do
        pw="${line##*:}"
        hash="${line%:*}"
        ssid_hex=$(echo "$hash" | awk -F"*" "{print \$6}")
        ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
        echo "  * ${ssid}: ${pw}"
    done
else
    echo "  暂无破解结果"
fi
'

# 停止 hashcat
run_cmd "killall -9 hashcat 2>/dev/null; echo '  hashcat 已停止'"

# 停止 crack_cloud 脚本
run_cmd "pkill -9 -f 'bash crack_cloud' 2>/dev/null; pkill -9 -f 'bash ./crack_cloud' 2>/dev/null; echo '  脚本已停止'" 2>/dev/null

# 验证
echo ""
run_cmd "ps aux | grep -E 'hashcat|crack_cloud' | grep -v grep || echo '✅ 所有任务已停止'"
echo ""
