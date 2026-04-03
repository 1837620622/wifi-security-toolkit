#!/bin/bash
# ============================================================================
# AutoDL算力云 (www.autodl.com) - 监控破解进度
# 自动检测环境: 云端本地直接执行 / Mac通过SSH远程执行
# 用法: bash cloud_monitor.sh          (查看一次)
#       bash cloud_monitor.sh -f       (持续监控，每30秒刷新)
# ============================================================================

# ── 监控逻辑 (本地执行) ──
do_monitor() {
echo "============================================"
echo "  AutoDL算力云 (www.autodl.com) WiFi破解 - 实时监控"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

# 检查进程状态
PROCS=$(ps aux | grep -E 'hashcat|crack_cloud' | grep -v grep)
if [ -z "$PROCS" ]; then
    echo "  ⚠  没有运行中的破解任务"
else
    echo "── 运行中的进程 ──"
    echo "$PROCS" | awk '{printf "  PID=%s CPU=%s%% MEM=%s%% TIME=%s CMD=%s\n", $2, $3, $4, $10, $11}'
fi
echo ""

# GPU 状态
echo "── GPU 状态 ──"
nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw --format=csv,noheader 2>/dev/null | \
    awk -F', ' '{printf "  %s | 温度:%s | 利用率:%s | 显存:%s/%s | 功耗:%s\n", $1, $2, $3, $4, $5, $6}'
echo ""

# 已破解结果
POTFILE="/root/wifi-crack/work/hashcat.potfile"
HASHES="/root/wifi-crack/work/hashes_deduped.22000"
if [ -f "$POTFILE" ] && [ -s "$POTFILE" ]; then
    CNT=$(wc -l < "$POTFILE" | tr -d ' ')
    echo "── 已破解: ${CNT} 条 ──"
    # potfile 格式: hash_hex*ssid_hex:password
    while IFS= read -r line; do
        pw="${line##*:}"
        # ssid_hex 在最后一个 * 和最后一个 : 之间
        tmp="${line%:*}"
        ssid_hex="${tmp##*\*}"
        ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
        [ -z "$ssid" ] && ssid="unknown"
        echo "  * ${ssid} -> ${pw}"
    done < "$POTFILE"
else
    echo "── 尚未破解任何密码 ──"
fi
echo ""

# 最新日志 (最后30行)
echo "── 最新日志 ──"
tail -30 /root/wifi-crack/crack.log 2>/dev/null || echo "  无日志"
echo ""
}

# ── AutoDL SSH 配置 (从环境变量读取或手动填写) ──
CLOUD_HOST="${CLOUD_HOST:-connect.westc.seetacloud.com}"
CLOUD_PORT="${CLOUD_PORT:-22}"
CLOUD_PASS="${CLOUD_PASS:-}"

# ── 自动检测运行环境 ──
check_once() {
    if [ -f /root/wifi-crack/crack_cloud.sh ] || [ "$(whoami)" = "root" ]; then
        do_monitor
    else
        if [ -n "$CLOUD_PASS" ]; then
            SSHPASS="$CLOUD_PASS" sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                -p "$CLOUD_PORT" "root@${CLOUD_HOST}" "bash /root/wifi-crack/cloud_monitor.sh"
        else
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                -p "$CLOUD_PORT" "root@${CLOUD_HOST}" "bash /root/wifi-crack/cloud_monitor.sh"
        fi
    fi
}

# 主逻辑
if [ "$1" = "-f" ] || [ "$1" = "--follow" ]; then
    echo "持续监控模式 (Ctrl+C 退出, 每30秒刷新)"
    echo ""
    while true; do
        clear
        check_once
        sleep 30
    done
else
    check_once
fi
