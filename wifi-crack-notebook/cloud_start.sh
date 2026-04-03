#!/bin/bash
# ============================================================================
# AutoDL算力云 (www.autodl.com) - 启动破解任务
# 自动检测环境: 云端本地直接执行 / Mac通过SSH远程执行
# 用法: bash cloud_start.sh
# ============================================================================

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

echo "── 启动破解任务 ──"

# 先停掉旧任务
run_cmd "killall -9 hashcat 2>/dev/null; sleep 1; echo '  旧 hashcat 已清理'"
run_cmd "pkill -9 -f 'bash crack_cloud' 2>/dev/null; pkill -9 -f 'bash ./crack_cloud' 2>/dev/null; sleep 1; echo '  旧脚本已清理'" 2>/dev/null

# 启动新任务 (nohup后台运行)
run_cmd "cd /root/wifi-crack && nohup bash crack_cloud.sh > crack.log 2>&1 & sleep 3 && ps aux | grep -E 'hashcat|crack_cloud' | grep -v grep && echo '' && echo 'OK 破解任务已启动' || echo 'FAIL 启动失败'"
