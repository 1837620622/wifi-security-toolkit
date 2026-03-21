#!/bin/bash
# ============================================================
# WiFi频道扫描工具 — 告诉你Sniffer该选哪个频道
# 用法: bash scan_channels.sh
# 作者：传康Kk (微信:1837620622)
# ============================================================

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/opt/miniconda3/bin:$PATH"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${GREEN}  ╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}  ║   WiFi 频道扫描 — Sniffer 选频道参考          ║${NC}"
echo -e "${GREEN}  ╚════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}  扫描中...${NC}"
echo ""

# 找到有pyobjc的python3
PYTHON3=""
for p in /opt/miniconda3/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
    if "$p" -c "import objc" 2>/dev/null; then
        PYTHON3="$p"
        break
    fi
done
if [ -z "$PYTHON3" ]; then
    echo -e "${YELLOW}  [!] 未找到带pyobjc的python3，请安装: pip install pyobjc${NC}"
    exit 1
fi

"$PYTHON3" -c "
import objc, sys
objc.loadBundle('CoreWLAN', globals(), bundle_path='/System/Library/Frameworks/CoreWLAN.framework')
client = CWWiFiClient.sharedWiFiClient()
iface = client.interface()
nets, err = iface.scanForNetworksWithName_error_(None, None)
if not nets:
    print('  [!] 未扫描到WiFi')
    sys.exit(1)

from collections import defaultdict
by_ch = defaultdict(list)
for n in nets:
    ssid = n.ssid() or '(hidden)'
    bssid = n.bssid() or ''
    rssi = int(n.rssiValue())
    ch = int(n.wlanChannel().channelNumber())
    by_ch[ch].append((rssi, ssid, bssid))

# 按频道中最强信号排序
ch_sorted = sorted(by_ch.keys(), key=lambda c: max(r for r,_,_ in by_ch[c]), reverse=True)

print('  频道  │ WiFi数 │ 最强信号 │ 包含的WiFi网络')
print('  ──────┼────────┼──────────┼─────────────────────────────────')
recommend = []
for ch in ch_sorted:
    items = sorted(by_ch[ch], key=lambda x: x[0], reverse=True)
    best_rssi = items[0][0]
    names = ', '.join(f'{s}({r}dBm)' for r,s,_ in items[:4])
    if len(items) > 4:
        names += f' +{len(items)-4}个'
    flag = ' ★' if best_rssi > -75 else ''
    print(f'  CH{ch:>3d} │  {len(items):>3d}   │  {best_rssi:>4d}dBm │ {names}{flag}')
    if best_rssi > -75:
        recommend.append((ch, len(items), best_rssi, items[0][1]))

print()
if recommend:
    print('  ★ 推荐频道（信号 > -75dBm）:')
    for ch, cnt, rssi, ssid in recommend:
        print(f'    → CH{ch} ({ssid} {rssi}dBm, 共{cnt}个WiFi)')
    best = recommend[0]
    print()
    print(f'  Sniffer设置: 频道={best[0]}  宽度=20MHz')
" 2>&1

echo ""
