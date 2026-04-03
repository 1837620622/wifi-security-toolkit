#!/bin/bash
# ============================================================
# 终端1: 扫描周围 WiFi + 设置监管域 + 启用监听模式
#
# 用法: sudo bash 1_scan.sh
# 作者: 传康Kk (微信:1837620622)
# ============================================================

# ---- 颜色 ----
R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; E='\033[0m'
info()  { echo -e "  ${C}[*]${E} $1"; }
ok()    { echo -e "  ${G}[✓]${E} $1"; }
warn()  { echo -e "  ${Y}[!]${E} $1"; }
err()   { echo -e "  ${R}[✗]${E} $1"; }

# ---- 检查 root ----
[ "$(id -u)" -ne 0 ] && { err "需要 root: sudo bash 1_scan.sh"; exit 1; }

echo ""
echo -e "  ${C}╔════════════════════════════════════════════╗${E}"
echo -e "  ${C}║   终端1: 扫描 WiFi + 设置环境             ║${E}"
echo -e "  ${C}╚════════════════════════════════════════════╝${E}"
echo ""

# ---- 恢复网卡 ----
info "恢复网卡..."
for mon in $(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i}'); do
    airmon-ng stop "$mon" >/dev/null 2>&1
done
sleep 1

# ---- 获取网卡 ----
IFACE=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type managed/{print i}' | head -1)
if [ -z "$IFACE" ]; then
    IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
    [ -n "$IFACE" ] && {
        ip link set "$IFACE" down 2>/dev/null
        iw dev "$IFACE" set type managed 2>/dev/null
        ip link set "$IFACE" up 2>/dev/null
        sleep 1
    }
fi
[ -z "$IFACE" ] && { err "未找到无线网卡"; exit 1; }
ok "网卡: $IFACE"

# ---- 设置监管域（必须在 managed 模式下！）----
info "设置监管域为 IN（解锁最大发射功率）..."
iw reg set IN 2>/dev/null
sleep 0.5
ok "监管域: $(iw reg get 2>/dev/null | grep 'country' | head -1)"

# ---- 启用监听模式 ----
info "启用监听模式..."
airmon-ng check kill >/dev/null 2>&1
sleep 1
airmon-ng start "$IFACE" >/dev/null 2>&1
sleep 2

MON=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i}')
[ -z "$MON" ] && { err "启用监听模式失败"; exit 1; }
ok "监听接口: $MON"

echo ""
echo -e "  ${Y}列说明:${E}"
echo -e "  ${Y}  BSSID = 路由器MAC    PWR = 信号（越接近0越好）${E}"
echo -e "  ${Y}  CH = 频道            ENC = 加密方式${E}"
echo -e "  ${Y}  ESSID = WiFi名称${E}"
echo -e "  ${Y}  下半部分 STATION = 已连接的客户端MAC${E}"
echo ""
echo -e "  ${G}看够了按 Ctrl+C 停止扫描${E}"
echo ""

# ---- 扫描 ----
airodump-ng "$MON"

# ---- 扫描结束，显示下一步 ----
echo ""
echo -e "  ${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
echo -e "  ${G}扫描完成！记下目标的 BSSID、频道、客户端MAC${E}"
echo -e "  ${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
echo ""
echo -e "  ${Y}下一步 → 打开第2个终端运行:${E}"
echo -e "  ${G}sudo bash 2_capture.sh <BSSID> <频道>${E}"
echo -e "  ${G}例: sudo bash 2_capture.sh A4:BA:70:04:1A:7E 9${E}"
echo ""
echo -e "  ${Y}同时打开第3个终端运行:${E}"
echo -e "  ${G}sudo bash 3_deauth.sh <BSSID> [客户端MAC]${E}"
echo -e "  ${G}例: sudo bash 3_deauth.sh A4:BA:70:04:1A:7E${E}"
echo -e "  ${G}例: sudo bash 3_deauth.sh A4:BA:70:04:1A:7E 14:D8:81:A0:DC:3D${E}"
echo -e "  ${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
