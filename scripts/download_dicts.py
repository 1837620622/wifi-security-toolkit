#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在线密码字典下载器
功能：从 GitHub 开源项目下载高质量 WiFi 密码字典
数据源：SecLists、NihaoKangkang、pydictor 等
"""

import os
import sys
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
ONLINE_DIR = PROJECT_DIR / "wordlists" / "online"

DICT_SOURCES = [
    {
        "name": "SecLists WPA Top4800",
        "desc": "全球最常见 4800 个 WiFi 密码",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
        "filename": "seclists_wpa_top4800.txt",
    },
    {
        "name": "SecLists WPA Top447",
        "desc": "全球 Top447 WiFi 高频密码",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top447.txt",
        "filename": "seclists_wpa_top447.txt",
    },
    {
        "name": "中国常用密码 Top10000",
        "desc": "中国互联网用户最常用的 10000 个密码",
        "url": "https://raw.githubusercontent.com/NihaoKangkang/Chinese-Common-Password-List/main/Chinese-common-password-list-top-10000.txt",
        "filename": "chinese_top10000.txt",
    },
    {
        "name": "中国常用密码 Top1000",
        "desc": "中国用户 Top1000 高频密码",
        "url": "https://raw.githubusercontent.com/NihaoKangkang/Chinese-Common-Password-List/main/Chinese-common-password-list-top-1000.txt",
        "filename": "chinese_top1000.txt",
    },
    {
        "name": "中国弱密码 Top1000",
        "desc": "pydictor 收集的中国弱密码",
        "url": "https://raw.githubusercontent.com/LandGrey/pydictor/master/wordlist/SEDB/ChineseWeakPass1000.txt",
        "filename": "chinese_weak1000.txt",
    },
    {
        "name": "中国常用密码 Top100000",
        "desc": "中国用户 Top10万 密码（大字典）",
        "url": "https://raw.githubusercontent.com/NihaoKangkang/Chinese-Common-Password-List/main/Chinese-common-password-list-top-100000.txt",
        "filename": "chinese_top100000.txt",
    },
]


def download_file(url, dest_path, desc=""):
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        print(f"  下载中: {desc or url}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        with open(dest_path, "wb") as f:
            f.write(data)
        size_kb = len(data) / 1024
        text = data.decode("utf-8", errors="ignore")
        line_count = text.count(chr(10))
        print(f"  完成: {size_kb:.0f} KB, {line_count} 行")
        return True
    except Exception as e:
        print(f"  失败: {e}")
        return False


def filter_wifi_passwords(filepath):
    path = Path(filepath)
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    original = len(lines)
    seen = set()
    unique = []
    for line in lines:
        pwd = line.strip()
        if pwd and not pwd.startswith("#") and len(pwd) >= 8 and pwd not in seen:
            seen.add(pwd)
            unique.append(pwd)
    with open(path, "w", encoding="utf-8") as f:
        for pwd in unique:
            f.write(pwd + chr(10))
    print(f"  过滤: {original} -> {len(unique)} 条")


def main():
    ONLINE_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 55)
    print("  WiFi 密码字典在线下载器")
    print("=" * 55)
    print(f"  保存目录: {ONLINE_DIR}")
    print()

    success = 0
    for src in DICT_SOURCES:
        dest = ONLINE_DIR / src["filename"]
        print(f"[{src['name']}]")
        print(f"  说明: {src['desc']}")
        if dest.exists():
            size = dest.stat().st_size / 1024
            print(f"  已存在 ({size:.0f} KB)，跳过")
            success += 1
            continue
        ok = download_file(src["url"], dest, src["name"])
        if ok:
            filter_wifi_passwords(dest)
            success += 1
        print()

    print(f"完成: {success}/{len(DICT_SOURCES)} 个字典")


if __name__ == "__main__":
    main()
