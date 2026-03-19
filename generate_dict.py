#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi密码字典生成器
生成目标：50万条以上去重密码，按优先级排序（高频在前）
WiFi密码最少8位（WPA/WPA2要求）
"""

import os
import sys
import time
import itertools

# 脚本所在目录即项目根目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "wifi_dict.txt")


def log(msg):
    """输出带时间戳的日志"""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ============================================================
# 全局去重集合和结果列表
# ============================================================
_seen = set()
_results = []


def add(s):
    """添加密码（自动去重，跳过不足8位的）"""
    if len(s) >= 8 and s not in _seen:
        _seen.add(s)
        _results.append(s)


# ============================================================
# 第1梯队：纯数字8位高频模式（最重要，命中率最高）
# ============================================================
def gen_pure_digit_patterns():
    """生成纯数字8位高频模式密码"""
    start_count = len(_results)

    # 1. 所有8位重复数字：11111111, 22222222 等
    for d in "0123456789":
        add(d * 8)

    # 2. 所有8位递增/递减序列
    for start in range(10):
        # 递增（循环）
        add("".join(str((start + i) % 10) for i in range(8)))
        # 递减（循环）
        add("".join(str((start - i) % 10) for i in range(8)))

    # 3. AABBCCDD 格式（遍历所有10^4种组合）
    for a in range(10):
        for b in range(10):
            for c in range(10):
                for d in range(10):
                    add(f"{a}{a}{b}{b}{c}{c}{d}{d}")

    # 4. AAAABBBB 格式（10^2 = 100种）
    for a in range(10):
        for b in range(10):
            add(f"{a}{a}{a}{a}{b}{b}{b}{b}")

    # 5. ABCDABCD 格式（4位重复2次，10^4 = 10000种）
    for n in range(10000):
        s = f"{n:04d}"
        add(s + s)

    # 6. ABABABAB 格式（2位重复4次，100种）
    for n in range(100):
        s = f"{n:02d}"
        add(s + s + s + s)

    # 7. 生日格式：YYYYMMDD（1960-2010年）
    for year in range(1960, 2011):
        for month in range(1, 13):
            for day in range(1, 32):
                # 简单月份日期验证
                if month in (4, 6, 9, 11) and day > 30:
                    continue
                if month == 2 and day > 29:
                    continue
                add(f"{year:04d}{month:02d}{day:02d}")

    # 8. 反向生日：MMDDYYYY
    for year in range(1960, 2011):
        for month in range(1, 13):
            for day in range(1, 32):
                if month in (4, 6, 9, 11) and day > 30:
                    continue
                if month == 2 and day > 29:
                    continue
                add(f"{month:02d}{day:02d}{year:04d}")

    # 9. 6位生日(YYMMDD) + 单字符前/后缀
    hot_years = list(range(1980, 2005))
    hot_months = list(range(1, 13))
    hot_days = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28]
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    for year in hot_years:
        yy = f"{year % 100:02d}"
        for month in hot_months:
            for day in hot_days:
                yymmdd = f"{yy}{month:02d}{day:02d}"
                for c in chars:
                    add(c + yymmdd)
                    add(yymmdd + c)

    log(f"  纯数字8位高频模式: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 第2梯队：中国手机号（11位）
# ============================================================
def gen_phone_numbers():
    """生成中国手机号相关密码"""
    start_count = len(_results)

    # 中国手机号段前缀
    prefixes = [
        "130", "131", "132", "133", "134", "135", "136", "137",
        "138", "139", "147", "149", "150", "151", "152", "153",
        "155", "156", "157", "158", "159", "162", "165", "166",
        "167", "170", "171", "172", "173", "175", "176", "177",
        "178", "180", "181", "182", "183", "184", "185", "186",
        "187", "188", "189", "190", "191", "192", "193", "195",
        "196", "197", "198", "199",
    ]

    # 后8位常见模式（重复/递增等）
    hot_tails = [
        "00000000", "11111111", "22222222", "33333333",
        "44444444", "55555555", "66666666", "77777777",
        "88888888", "99999999", "12345678", "87654321",
        "11223344", "12341234", "00001234", "11110000",
        "88886666", "66668888", "88880000", "00008888",
        "13141314", "52015201", "00001111", "99998888",
        "12120000", "00001212",
    ]

    for prefix in prefixes:
        for tail in hot_tails:
            # 完整11位手机号
            add(prefix + tail[:8])  # 3+8=11位
            # 后8位单独作为密码
            add(tail)

    # 前缀+中间4位+尾4位 → 11位手机号
    mid_patterns = ["0000", "1111", "1234", "5678", "8888", "6666", "9999"]
    for prefix in prefixes:
        for mid in mid_patterns:
            for end in mid_patterns:
                phone = prefix + mid + end
                if len(phone) == 11:
                    add(phone)

    log(f"  手机号密码: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 第3梯队：情感数字系列
# ============================================================
def gen_emotion_numbers():
    """生成情感/爱情数字密码"""
    start_count = len(_results)

    # 5201314 系列变体（各种组合）
    bases = [
        "52013140", "52013141", "52013142", "52013143", "52013144",
        "52013145", "52013146", "52013147", "52013148", "52013149",
        "520131400", "5201314520", "13145200", "13145201", "13145202",
        "52005200", "13141314", "52025202", "52145214", "52013520",
        "52101314", "05200520", "13140520", "15201314", "52001314",
        "13145201", "01314520", "51413141", "520520520",
        "1314520", "5201314", "5200520", "13201314",
        "52013888", "88885200",
    ]
    for s in bases:
        add(s)

    # 520xxxxx / xxxxx520（8位）
    for i in range(100000):
        add(f"520{i:05d}")
        add(f"{i:05d}520")
        if i >= 100000:
            break

    # 1314xxxx / xxxx1314
    for i in range(10000):
        add(f"1314{i:04d}")
        add(f"{i:04d}1314")

    # 爱情数字组合
    love_nums = ["520", "1314", "521", "5201314", "1314520",
                 "5200", "13140", "1111", "8888", "9999", "6666"]
    for a in love_nums:
        for b in love_nums:
            s = a + b
            add(s)

    # 吉利数字
    lucky = [
        "16881688", "18881888", "68886888", "11118888",
        "88881111", "66668888", "88886666", "11116666",
        "95279527", "88668866", "66886688", "18881314",
        "13881388", "13881314", "16161616", "18181818",
        "88188818", "86868686", "66886688", "18861886",
    ]
    for s in lucky:
        add(s)

    log(f"  情感数字密码: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 第4梯队：常见弱口令
# ============================================================
def gen_weak_passwords():
    """生成常见弱口令及变体"""
    start_count = len(_results)

    # 基础弱口令
    bases = [
        "password", "password1", "password123", "password!",
        "admin123", "admin1234", "admin12345", "admin888",
        "123456789", "1234567890", "12345678", "87654321",
        "qwerty123", "qwerty12", "qwerty1234", "qwerty12345",
        "iloveyou", "iloveyou1", "iloveyou!",
        "abc12345", "abc123456", "abc1234567",
        "a1234567", "a12345678",
        "aa123456", "aaa12345",
        "1q2w3e4r", "2w3e4r5t", "q1w2e3r4", "1qaz2wsx",
        "letmein1", "welcome1", "sunshine",
        "monkey123", "dragon123", "master123",
        "superman", "batman123",
        "football", "baseball", "basketball",
        "michael1", "shadow123",
        "internet", "computer", "windows1",
        "passw0rd", "p@ssw0rd", "p@$$w0rd",
        "test1234", "test12345",
        "root12345", "toor12345",
        "linux1234", "ubuntu123",
        "wifi1234", "wifi12345", "wifi123456",
        "wlan1234", "wlan12345",
        "router12", "router123",
        "net12345", "network1",
        "home1234", "home12345",
        "tp-link1", "tplink12", "tplink123",
        "dlink123", "asus1234", "netgear1",
        "wireless", "internet",
        "88888888", "66666666", "12341234",
    ]
    for s in bases:
        add(s)

    # 字母双写+常见数字后缀
    double_letters = [a+a for a in "abcdefghijklmnopqrstuvwxyz"]
    suffixes = ["123456", "1234567", "12345678", "123456789",
                "111111", "888888", "666666", "000000",
                "112233", "123123", "654321"]
    for p in double_letters:
        for s in suffixes:
            add(p + s)

    # 单字母+数字
    for letter in "abcdefghijklmnopqrstuvwxyz":
        for num in ["1234567", "12345678", "123456789", "1234567890",
                    "11111111", "88888888", "00000000", "66666666",
                    "12341234", "23456789", "87654321"]:
            add(letter + num)
            add(num + letter)

    log(f"  弱口令密码: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 第5梯队：键盘模式
# ============================================================
def gen_keyboard_patterns():
    """生成键盘走位密码"""
    start_count = len(_results)

    keyboard_bases = [
        "qwertyui", "qwertyuiop", "asdfghjk", "asdfghjkl",
        "zxcvbnm1", "qweasdzx",
        "poiuytre", "lkjhgfds", "mnbvcxza",
        "qazwsxed", "rfvtgbyh",
        "1qaz2wsx", "3edc4rfv", "5tgb6yhn",
        "2wsxzaq1",
        "qwerty12", "qwerty123", "asdfgh12",
        "zxcvbn12", "qwertyu1", "asdfghj1",
        "1234qwer", "qwer1234", "asdf1234",
        "zxcv1234", "q1w2e3r4", "1q2w3e4r",
        "a1s2d3f4", "z1x2c3v4",
        "qazwsx12", "!QAZ@WSX",
        "1234!@#$", "abcd1234",
        "qwertyui", "asdfghjk", "zxcvbnm1",
        "1qazxsw2", "2wsxzaq1",
    ]

    for s in keyboard_bases:
        if len(s) >= 8:
            add(s)
        if len(s) > 8:
            add(s[:8])

    # 键盘前缀+数字
    for prefix in ["q", "a", "z", "w", "s", "x", "e", "d", "c", "qw", "as", "zx"]:
        for nums in ["12345678", "1234567", "123456", "12341234",
                     "11111111", "88888888", "00000000", "87654321"]:
            add(prefix + nums)
            add(nums + prefix)

    log(f"  键盘模式密码: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 第6梯队：拼音组合
# ============================================================
def gen_pinyin_passwords():
    """生成拼音组合密码"""
    start_count = len(_results)

    pinyins = [
        "woaini", "woshishui", "nihao", "zaijian", "xiexie",
        "wodemima", "mima", "mimamima", "zhangsan", "lisi",
        "wangwu", "zhaoliu", "sunqi",
        "baobei", "laogong", "laopo", "meimei", "gege",
        "didi", "jiejie", "mama", "baba",
        "qinai", "xingan", "baobao", "aixin",
        "kuaile", "youxi", "diannao",
        "shouji", "wangzhan", "wangluo",
        "taobao", "wechat", "weixin",
        "jiayou", "shengri", "xingfu",
        "aiqing", "youqing", "pengyou", "tongxue",
        "xiaoming", "xiaohong", "xiaohua", "xiaoli",
        "wangjun", "zhangwei", "liming", "zhangli",
    ]

    num_suffixes = [
        "123", "1234", "12345", "123456", "1234567", "12345678",
        "111", "888", "666", "520", "1314", "0000", "9999",
        "1988", "1989", "1990", "1991", "1992", "1993", "1994",
        "1995", "1996", "1997", "1998", "1999", "2000", "2001",
        "2002", "2003", "00", "01", "02", "11", "12", "88", "99",
    ]

    for py in pinyins:
        for suffix in num_suffixes:
            add(py + suffix)
            add(py.capitalize() + suffix)
        if len(py) >= 8:
            add(py)
        # 两个拼音拼接
        for py2 in pinyins[:10]:
            s = py + py2
            if len(s) >= 8:
                add(s[:12])  # 限制长度

    log(f"  拼音组合密码: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 第7梯队：纯数字有规律子集（高效版）
# ============================================================
def gen_digit_subsets():
    """
    高效生成纯数字有规律子集，无需遍历1亿个数字
    通过直接构造有规律的数字来生成
    """
    start_count = len(_results)

    # 常见子串（将直接构造包含这些的8位数字）
    common_substrs = [
        "1234", "2345", "3456", "4567", "5678", "6789",
        "9876", "8765", "7654", "6543", "5432", "4321",
        "0000", "1111", "2222", "3333", "4444", "5555",
        "6666", "7777", "8888", "9999",
        "1314", "0520", "5201", "3141",
    ]

    # 方法1：包含特定4位子串的8位数字（枚举前4位或后4位）
    for sub in common_substrs:
        for prefix in range(10000):
            # sub在后4位
            add(f"{prefix:04d}{sub}")
            # sub在前4位
            add(f"{sub}{prefix:04d}")
            # sub在中间（位置1-4）
            for i in range(1, 5):
                n = prefix
                digits = list(f"{n:08d}")
                for j, c in enumerate(sub):
                    if i + j < 8:
                        digits[i + j] = c
                add("".join(digits))

    # 方法2：回文数字
    # 8位回文：ABCDDCBA
    for n in range(10000):
        s = f"{n:04d}"
        add(s + s[::-1])  # ABCDDCBA
    # 8位回文：ABCDDDCBA（9位，不需要）

    # 方法3：前4后4相同（已在gen_pure_digit_patterns中覆盖ABCDABCD）
    # 补充：前4后4互为反转
    for n in range(10000):
        s = f"{n:04d}"
        add(s + s[::-1])

    # 方法4：包含连续3位递增/递减
    for start in range(10):
        for pos in range(6):  # 3位子串的起始位置0-5
            for prefix_n in range(1000):
                # 前缀填充
                prefix = f"{prefix_n:0{pos}d}" if pos > 0 else ""
                seq_up = "".join(str((start + i) % 10) for i in range(3))
                seq_dn = "".join(str((start - i) % 10) for i in range(3))
                remaining = 8 - pos - 3
                for suffix_n in range(10 ** remaining):
                    suffix = f"{suffix_n:0{remaining}d}" if remaining > 0 else ""
                    add(prefix + seq_up + suffix)
                    add(prefix + seq_dn + suffix)

    # 方法5：包含重复字符3位以上（AAAxxx 格式）
    for d in range(10):
        triple = str(d) * 3
        for n in range(100000):
            # 三连在前
            add(f"{triple}{n:05d}")
            # 三连在后
            add(f"{n:05d}{triple}")
            # 三连在中间
            for pos in range(1, 6):
                pre_len = pos
                suf_len = 8 - pos - 3
                if suf_len < 0:
                    continue
                pre = f"{n // (10 ** suf_len if suf_len > 0 else 1):0{pre_len}d}"[:pre_len]
                suf = f"{n % (10 ** suf_len if suf_len > 0 else 1):0{suf_len}d}" if suf_len > 0 else ""
                add(pre + triple + suf)

    log(f"  有规律数字子集: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 第8梯队：9-11位扩展
# ============================================================
def gen_extended_passwords(top_n=20000):
    """对高频8位密码加前缀/后缀生成9-11位密码"""
    start_count = len(_results)

    # 取当前前 top_n 条高频密码做扩展
    top_base = list(_results[:top_n])

    chars = list("0123456789abcdefghijklmnopqrstuvwxyz")
    num2 = ["00", "01", "11", "12", "88", "99", "23", "24", "66", "88"]

    for pwd in top_base:
        for c in chars:
            add(c + pwd)
            add(pwd + c)
        for num in num2:
            add(pwd + num)
            add(num + pwd)

    log(f"  9-11位扩展密码: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 补充：直接枚举有规律的8位纯数字（快速版）
# ============================================================
def gen_structured_8digit():
    """
    直接生成8位有规律纯数字：
    - 包含"0000/1111/..."这类4位重复的
    - 包含"1234/5678/..."这类4位递增的
    - 前4和后4相关的（镜像、反转等）
    """
    start_count = len(_results)

    # 生成包含常见4字符组合的8位数
    patterns_4 = []
    # 4位全相同：0000-9999
    for d in range(10):
        patterns_4.append(str(d) * 4)
    # 4位递增：0123, 1234, ..., 6789
    for s in range(7):
        patterns_4.append("".join(str((s+i) % 10) for i in range(4)))
    # 4位递减：9876, 8765, ...
    for s in range(9, 2, -1):
        patterns_4.append("".join(str((s-i) % 10) for i in range(4)))
    # 特殊4位
    patterns_4 += ["1314", "5201", "0520", "5200", "8888", "6666",
                   "1234", "5678", "9012", "0000", "1111", "2345"]

    for p4 in patterns_4:
        # 此4位模式放在前/后，其余4位枚举
        for n in range(10000):
            n4 = f"{n:04d}"
            add(p4 + n4)
            add(n4 + p4)

    log(f"  结构化8位数字: 新增 {len(_results) - start_count} 条，总 {len(_results)} 条")


# ============================================================
# 主函数
# ============================================================
def main():
    log("=== WiFi密码字典生成器开始 ===")
    log(f"输出文件: {OUTPUT_FILE}")

    # === 按优先级生成各类密码 ===
    log("\n[第1梯队] 纯数字8位高频模式...")
    gen_pure_digit_patterns()

    log("\n[第2梯队] 手机号密码...")
    gen_phone_numbers()

    log("\n[第3梯队] 情感数字...")
    gen_emotion_numbers()

    log("\n[第4梯队] 常见弱口令...")
    gen_weak_passwords()

    log("\n[第5梯队] 键盘模式...")
    gen_keyboard_patterns()

    log("\n[第6梯队] 拼音组合...")
    gen_pinyin_passwords()

    log(f"\n当前已有 {len(_results)} 条密码")

    # 如果不到50万，追加结构化8位数字
    if len(_results) < 500000:
        log("\n[第7梯队] 结构化8位数字子集...")
        gen_structured_8digit()

    log(f"\n当前已有 {len(_results)} 条密码")

    # 如果仍不到50万，追加有规律子集
    if len(_results) < 500000:
        log("\n[第7b梯队] 有规律数字进一步扩展...")
        gen_digit_subsets()

    log(f"\n当前已有 {len(_results)} 条密码")

    # 在当前基础上生成9-11位扩展（截止到50万后即可）
    log("\n[第8梯队] 9-11位扩展（基于当前高频列表）...")
    gen_extended_passwords(top_n=15000)

    total = len(_results)
    log(f"\n总计生成 {total} 条密码")

    if total < 500000:
        log(f"警告：仅生成了 {total} 条，未达到50万目标")
    else:
        log(f"达到目标：{total} 条 >= 500000 条")

    # 写入文件
    log(f"\n正在写入 {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(_results) + "\n")

    # 验证
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        line_count = sum(1 for line in f if line.strip())

    log(f"\n=== 完成 ===")
    log(f"文件: {OUTPUT_FILE}")
    log(f"行数: {line_count} 条密码")
    log(f"大小: {os.path.getsize(OUTPUT_FILE) / 1024 / 1024:.1f} MB")

    return line_count


if __name__ == "__main__":
    count = main()
    sys.exit(0 if count >= 500000 else 1)
