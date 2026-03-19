#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中国定制WiFi密码字典生成器
按命中率从高到低分层，用于在线爆破和hashcat字典攻击
"""

import os
from typing import List


# ============================================================
# TOP高频密码（静态，命中率最高的前100条）
# ============================================================
TOP_PASSWORDS = [
    # 第1梯队：超高频纯数字
    "12345678", "88888888", "00000000", "11111111", "66666666",
    "123456789", "1234567890", "0123456789", "87654321", "12341234",
    "11112222", "12121212", "99999999", "22222222", "33333333",
    "44444444", "55555555", "77777777", "98765432", "11223344",
    "13579246", "24681357", "01234567", "10203040", "56785678",
    "78907890", "43214321", "32103210", "11235813",
    # 第2梯队：情感/吉利数字
    "52013141", "13145200", "52005200", "13141314", "52025202",
    "52145214", "52013520", "52101314", "05200520", "13140520",
    "15201314", "52001314", "13145201", "01314520", "51413141",
    "14725836", "15935728", "13572468", "15975328", "52052052",
    "13131313", "14141414", "10101010", "16881688", "18881888",
    "68886888", "11118888", "88881111", "66668888", "88886666",
    "11116666", "95279527", "95889588", "10086100", "10010100",
    "520131400", "131452000", "520520520",
    # 第3梯队：年份数字
    "19881988", "19891989", "19901990", "19911991", "19921992",
    "19931993", "19941994", "19951995", "19961996", "19971997",
    "19981998", "19991999", "20002000", "20012001", "20022002",
    "20102010", "20202020", "20242024", "20252025", "20262026",
    # 第4梯队：字母+数字
    "password", "admin123", "admin888", "password1", "abc12345",
    "abc123456", "a1234567", "a12345678", "aa123456", "asd12345",
    "qwer1234", "asdf1234", "zxcv1234", "1q2w3e4r", "q1w2e3r4",
    "1qaz2wsx", "qwerty12", "iloveyou", "football", "baseball",
    # 第5梯队：拼音
    "woaini520", "woaini1314", "wodemima", "mima1234",
    "wifi1234", "wifi12345", "wlan1234",
]


def _extract_suffix(ssid: str, n: int) -> str:
    """从SSID末尾提取N个十六进制/数字字符（原版Go逻辑）"""
    if len(ssid) < n:
        return ""
    suffix = ssid[-n:]
    clean = ''.join(c for c in suffix if c.isalnum() and
                    (c.isdigit() or c.lower() in 'abcdef'))
    if len(clean) >= n:
        return clean[:n].lower()
    return ""


def generate_router_defaults(ssid: str) -> List[str]:
    """根据SSID前缀生成路由器默认密码（对齐原版Go代码）"""
    passwords = []
    ssid_upper = ssid.upper()

    # TP-LINK: 后4位/后6位作为默认密码一部分
    if "TP-LINK" in ssid_upper or "TP_LINK" in ssid_upper:
        suffix4 = _extract_suffix(ssid, 4)
        if suffix4:
            passwords.extend([
                "1234567890",
                suffix4 + suffix4,           # 4位重复
                "TP" + suffix4 + "TP",     # TP包裹
                "admin" + suffix4,           # admin前缀
                "tp" + suffix4,              # tp前缀
            ])
        # 提取SSID中的全部字母数字后缀
        full_suffix = ''.join(c for c in ssid if c.isalnum())[-8:]
        if full_suffix:
            passwords.extend([full_suffix, full_suffix.lower(), full_suffix.upper()])
        passwords.extend([
            "12345678", "88888888", "admin123",
            "tplink12", "tplink123", "tp-link1",
        ])

    # CMCC（移动）: 后3-4位数字组合
    if "CMCC" in ssid_upper:
        suffix3 = _extract_suffix(ssid, 3)
        if suffix3:
            passwords.extend([
                suffix3 + suffix3 + suffix3[:2],  # 3位重复到≥ 8位
                "1" + suffix3 + suffix3 + "1",  # 1xxx1格式
                "cmcc" + suffix3 + suffix3[:1],
            ])
        parts = ssid.split('_')
        for p in parts:
            if len(p) >= 8 and p.isalnum():
                passwords.append(p)
        passwords.extend(["12345678", "1234567890"])

    # Tenda/腾达
    if "TENDA" in ssid_upper:
        suffix4 = _extract_suffix(ssid, 4)
        if suffix4:
            passwords.extend([suffix4 + suffix4, "tenda" + suffix4])
        passwords.extend(["12345678", "tenda123"])

    # FAST/迅捷
    if "FAST" in ssid_upper:
        suffix4 = _extract_suffix(ssid, 4)
        if suffix4:
            passwords.extend([suffix4 + suffix4, "fast" + suffix4])
        passwords.extend(["12345678", "fast1234"])

    # MERCURY/水星
    if "MERCURY" in ssid_upper or "MERC" in ssid_upper:
        suffix4 = _extract_suffix(ssid, 4)
        if suffix4:
            passwords.extend([suffix4 + suffix4, "merc" + suffix4])
        passwords.extend(["12345678", "mercury1", "merc1234"])

    # D-LINK
    if "DLINK" in ssid_upper or "D-LINK" in ssid_upper:
        passwords.extend(["12345678", "dlink123"])

    # HUAWEI/华为
    if "HUAWEI" in ssid_upper or "HONOR" in ssid_upper:
        full_suffix = ''.join(c for c in ssid if c.isalnum())[-8:]
        if full_suffix:
            passwords.extend([full_suffix, full_suffix.lower()])
        passwords.extend(["12345678", "huawei12"])

    # Xiaomi/小米
    if "XIAOMI" in ssid_upper or "REDMI" in ssid_upper or "MI-" in ssid_upper:
        passwords.extend(["12345678", "xiaomi12"])

    # ZTE/中兴
    if "ZTE" in ssid_upper or "中兴" in ssid:
        suffix4 = _extract_suffix(ssid, 4)
        if suffix4:
            passwords.extend([suffix4 + suffix4, "zte" + suffix4])
        passwords.extend(["12345678"])

    # ChinaNet/中国电信
    if "CHINANET" in ssid_upper or "CHINA-NET" in ssid_upper:
        passwords.extend(["12345678", "1234567890"])

    # 通用默认密码（所有品牌都追加）
    passwords.extend([
        "12345678", "88888888", "00000000", "11111111", "66666666",
        "123456789", "1234567890", "0123456789", "87654321",
        "password", "admin123", "admin888", "12341234", "11112222",
    ])

    return list(dict.fromkeys(passwords))  # 去重保序


def generate_ssid_smart(ssid: str, full: bool = False) -> List[str]:
    """
    根据SSID中的数字/字母模式生成针对性密码
    full=False: 轻量版（约20-50条，用于Phase 2 TOP密码）
    full=True:  完整版（含门牌号扩展，可达万级，用于Phase 5）
    """
    passwords = []

    digits = ''.join(c for c in ssid if c.isdigit())
    letters = ''.join(c for c in ssid if c.isalpha())

    if len(digits) >= 3:
        # 数字本身如果>=8位
        if len(digits) >= 8:
            passwords.append(digits)

        # 数字重复補到8位
        d = digits
        while len(d) < 8:
            d += digits
        passwords.append(d[:8])
        if len(d) >= 9:
            passwords.append(d[:9])

        # 数字+常见后缀 / 前缀+数字
        for s in ["0000", "1234", "8888", "6666", "0123", "abcd", "wifi"]:
            combo = digits + s
            if len(combo) >= 8:
                passwords.append(combo[:min(len(combo), 11)])
            combo2 = s + digits
            if len(combo2) >= 8:
                passwords.append(combo2[:min(len(combo2), 11)])

        # 门牌号/宿舍号模式（完整版才启用，数量大）
        if full and 3 <= len(digits) <= 5:
            need = 8 - len(digits)
            if need <= 3:
                for n in range(10**3):
                    extra = f"{n:03d}"
                    p1 = digits + extra
                    if 8 <= len(p1) <= 11:
                        passwords.append(p1)
                    p2 = extra + digits
                    if 8 <= len(p2) <= 11:
                        passwords.append(p2)
            elif need <= 5:
                cap = min(10**need, 100000)
                for n in range(cap):
                    extra = f"{n:0{need}d}"
                    p1 = digits + extra
                    if 8 <= len(p1) <= 11:
                        passwords.append(p1)
                    p2 = extra + digits
                    if 8 <= len(p2) <= 11:
                        passwords.append(p2)

    if letters:
        lower = letters.lower()
        for suffix in ["123", "1234", "12345", "123456", "12345678",
                       "888", "666", "520", "1314"]:
            pwd = lower + suffix
            if len(pwd) >= 8:
                passwords.append(pwd)

    # SSID本身作为密码的变体
    lower_ssid = ssid.lower()
    if len(lower_ssid) >= 8:
        passwords.append(lower_ssid)
    for suffix in ["123", "1234", "12345", "666", "888", "000", "111"]:
        combo = lower_ssid + suffix
        if len(combo) >= 8:
            passwords.append(combo)

    return list(dict.fromkeys(passwords))


def generate_chinese_passwords() -> List[str]:
    """生成中国特色高频密码（约5000条）"""
    passwords = []
    seen = set()

    def add(s):
        if len(s) >= 8 and s not in seen:
            seen.add(s)
            passwords.append(s)

    # 1. 8位重复数字
    for d in "0123456789":
        add(d * 8)

    # 2. 递增/递减序列
    for start in range(10):
        add("".join(str((start + i) % 10) for i in range(8)))
        add("".join(str((start - i) % 10) for i in range(8)))

    # 3. AABBCCDD格式（常见的）
    for a in range(10):
        for b in range(10):
            add(f"{a}{a}{b}{b}{a}{a}{b}{b}")
            add(f"{a}{a}{a}{a}{b}{b}{b}{b}")

    # 4. ABCDABCD格式
    for n in range(10000):
        s = f"{n:04d}"
        add(s + s)

    # 5. 生日格式 YYYYMMDD（1975-2010）
    for year in range(1975, 2011):
        for month in range(1, 13):
            max_day = 31
            if month in (4, 6, 9, 11):
                max_day = 30
            elif month == 2:
                max_day = 29
            for day in range(1, max_day + 1):
                add(f"{year:04d}{month:02d}{day:02d}")

    # 6. 520/1314系列
    love_bases = [
        "52013140", "52013141", "13145200", "52005200", "13141314",
        "52025202", "52013520", "05200520", "15201314", "52001314",
    ]
    for s in love_bases:
        add(s)

    for i in range(100000):
        add(f"520{i:05d}")
    for i in range(10000):
        add(f"1314{i:04d}")
        add(f"{i:04d}1314")

    # 7. 吉利数字
    lucky = [
        "16881688", "18881888", "68886888", "11118888",
        "88881111", "66668888", "88886666", "11116666",
        "95279527", "88668866", "66886688", "18181818",
        "86868686", "13881388", "16161616",
    ]
    for s in lucky:
        add(s)

    # 8. 常见弱口令
    weak = [
        "password", "password1", "password123",
        "admin123", "admin1234", "admin12345", "admin888",
        "qwerty123", "qwerty12", "qwerty1234",
        "abc12345", "abc123456", "abc1234567",
        "a1234567", "a12345678", "aa123456",
        "1q2w3e4r", "q1w2e3r4", "1qaz2wsx",
        "iloveyou", "iloveyou1",
        "wifi1234", "wifi12345", "wifi123456",
        "wlan1234", "wlan12345",
        "test1234", "test12345",
    ]
    for s in weak:
        add(s)

    # 9. 键盘模式
    keyboard = [
        "qwertyui", "qwertyuiop", "asdfghjk", "asdfghjkl",
        "zxcvbnm1", "1234qwer", "qwer1234", "asdf1234",
        "qazwsx12", "1qazxsw2",
    ]
    for s in keyboard:
        if len(s) >= 8:
            add(s)

    # 10. 拼音+数字
    pinyins = [
        "woaini", "nihao", "baobei", "laogong", "laopo",
        "xiexie", "kuaile", "xingfu", "aiqing", "pengyou",
        "wangzi", "gongzhu", "xiaoming", "zhangwei", "liming",
    ]
    num_suffixes = [
        "123", "1234", "12345", "123456", "520", "1314",
        "888", "666", "0000", "111", "000",
    ]
    for py in pinyins:
        for suffix in num_suffixes:
            add(py + suffix)

    # 11. 单字母+数字
    for letter in "abcdefghijklmnopqrstuvwxyz":
        for num in ["1234567", "12345678", "123456789",
                    "11111111", "88888888", "00000000", "66666666"]:
            add(letter + num)

    return passwords


def build_top_passwords(ssid: str) -> List[str]:
    """构建快速验证用的TOP密码列表（约60-150条，10秒内可完成）"""
    all_pwds = []
    seen = set()

    def add_unique(lst):
        for p in lst:
            if p not in seen and len(p) >= 8:
                seen.add(p)
                all_pwds.append(p)

    # 第1层：路由器默认密码
    add_unique(generate_router_defaults(ssid))
    # 第2层：SSID智能推测（轻量版，不含门牌号扩展）
    add_unique(generate_ssid_smart(ssid, full=False))
    # 第3层：TOP高频密码（前50个）
    add_unique(TOP_PASSWORDS[:50])

    return all_pwds


def build_full_passwords(ssid: str, extra_dict_path: str = "",
                         wpa_sec_path: str = "") -> List[str]:
    """构建完整密码列表（用于Phase 5兜底爆破）"""
    all_pwds = []
    seen = set()

    def add_unique(lst):
        for p in lst:
            if p not in seen and len(p) >= 8:
                seen.add(p)
                all_pwds.append(p)

    # SSID智能推测（完整版，含门牌号扩展）
    add_unique(generate_ssid_smart(ssid, full=True))

    # 中国定制字典
    add_unique(generate_chinese_passwords())

    # TOP密码
    add_unique(TOP_PASSWORDS)

    # 外部字典
    if extra_dict_path and os.path.exists(extra_dict_path):
        try:
            with open(extra_dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if pwd and len(pwd) >= 8 and pwd not in seen:
                        seen.add(pwd)
                        all_pwds.append(pwd)
        except:
            pass

    # wpa-sec字典
    if wpa_sec_path and os.path.exists(wpa_sec_path):
        try:
            with open(wpa_sec_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    if pwd and len(pwd) >= 8 and pwd not in seen:
                        seen.add(pwd)
                        all_pwds.append(pwd)
        except:
            pass

    return all_pwds


def save_wordlist(passwords: List[str], output_path: str) -> str:
    """保存密码列表到文件（用于hashcat字典攻击）"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(passwords) + '\n')
    return output_path
