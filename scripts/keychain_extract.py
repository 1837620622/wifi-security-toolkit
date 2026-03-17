#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
macOS 钥匙串 WiFi 密码提取器
功能：从系统钥匙串中提取已保存的 WiFi 名称和密码
用途：已知密码分析 -> 推断目标密码模式 -> 优化字典
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
OUTPUT_FILE = PROJECT_DIR / "captures" / "keychain_passwords.json"

# 企业WiFi关键词
ENT_KW = ["eduroam", "1X", "802.1x", "enterprise", "campus", "office", "corp"]


def list_saved_wifi():
    """从钥匙串列出所有已保存的WiFi SSID"""
    try:
        r = subprocess.run(
            ["security", "dump-keychain", "/Library/Keychains/System.keychain"],
            capture_output=True, text=True, timeout=10
        )
        # 解析 desc="AirPort network password" 的条目
        entries = r.stdout.split("keychain:")
        ssids = []
        for entry in entries:
            if "AirPort network password" in entry:
                # 提取 acct 字段
                m = re.search(r'"acct"<blob>="([^"]+)"', entry)
                if m:
                    ssids.append(m.group(1))
                else:
                    # 尝试hex编码的SSID
                    m2 = re.search(r'"acct"<blob>=0x([0-9A-Fa-f]+)\s+"([^"]*)"?', entry)
                    if m2:
                        try:
                            name = bytes.fromhex(m2.group(1)).decode("utf-8")
                            ssids.append(name)
                        except Exception:
                            ssids.append(m2.group(2) if m2.group(2) else "(hex)")
        return ssids
    except Exception as e:
        print(f"[!] 读取钥匙串失败: {e}")
        return []


def classify_ssids(ssids):
    """分类SSID为家庭WiFi和企业WiFi"""
    home = []
    enterprise = []
    for s in ssids:
        is_ent = False
        for kw in ENT_KW:
            if kw.lower() in s.lower():
                is_ent = True
                break
        if is_ent:
            enterprise.append(s)
        else:
            home.append(s)
    return home, enterprise


def extract_password(ssid):
    """提取指定SSID的密码（需要系统弹窗确认）"""
    try:
        r = subprocess.run(
            ["security", "find-generic-password",
             "-D", "AirPort network password",
             "-ga", ssid,
             "/Library/Keychains/System.keychain"],
            capture_output=True, text=True, timeout=30
        )
        # 密码在 stderr 中，格式: password: "xxx"
        for line in r.stderr.splitlines():
            if "password:" in line:
                m = re.search(r'password:\s*"(.+)"', line)
                if m:
                    return m.group(1)
                # 无引号的情况
                m2 = re.search(r'password:\s*(\S+)', line)
                if m2:
                    return m2.group(1)
        return None
    except Exception:
        return None


def analyze_passwords(passwords):
    """分析已知密码的模式特征"""
    if not passwords:
        return {}
    stats = {
        "total": len(passwords),
        "pure_digit": 0,
        "pure_alpha": 0,
        "mixed": 0,
        "lengths": {},
        "patterns": [],
    }
    for pwd in passwords:
        l = len(pwd)
        stats["lengths"][str(l)] = stats["lengths"].get(str(l), 0) + 1
        if pwd.isdigit():
            stats["pure_digit"] += 1
        elif pwd.isalpha():
            stats["pure_alpha"] += 1
        else:
            stats["mixed"] += 1
    return stats


def main():
    parser = argparse.ArgumentParser(description="WiFi 钥匙串密码提取器")
    parser.add_argument("-e", "--extract", action="store_true", help="提取密码")
    parser.add_argument("-s", "--ssid", type=str, help="指定SSID")
    parser.add_argument("-a", "--analyze", action="store_true", help="分析密码模式")
    args = parser.parse_args()

    print("=" * 50)
    print("  macOS 钥匙串 WiFi 密码提取器")
    print("=" * 50)
    print()

    # 列出所有WiFi
    ssids = list_saved_wifi()
    if not ssids:
        print("[!] 未找到已保存的WiFi")
        # 备用方案
        try:
            r = subprocess.run(
                ["networksetup", "-listpreferredwirelessnetworks", "en0"],
                capture_output=True, text=True, timeout=5
            )
            ssids = [l.strip() for l in r.stdout.splitlines()[1:] if l.strip()]
        except Exception:
            pass

    home, ent = classify_ssids(ssids)
    print(f"[*] 找到 {len(ssids)} 个已保存WiFi ({len(home)} 家庭 / {len(ent)} 企业)")
    print()

    if home:
        print("[家庭WiFi]")
        for i, s in enumerate(home, 1):
            print(f"  {i:>3}. {s}")
    if ent:
        print()
        print("[企业/校园WiFi]")
        for s in ent[:10]:
            print(f"       {s}")

    if args.extract:
        print()
        print("[*] 提取密码（系统可能弹出授权对话框）...")
        targets = [args.ssid] if args.ssid else home
        results = {}
        for ssid in targets:
            pwd = extract_password(ssid)
            if pwd:
                results[ssid] = pwd
                print(f"  {ssid}: {pwd}")
            else:
                print(f"  {ssid}: (需要授权或无密码)")

        if results:
            OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"[+] 已保存: {OUTPUT_FILE}")

            if args.analyze:
                stats = analyze_passwords(list(results.values()))
                print()
                print("[密码模式分析]")
                print(f"  纯数字: {stats['pure_digit']}")
                print(f"  纯字母: {stats['pure_alpha']}")
                print(f"  混合:   {stats['mixed']}")
                print(f"  长度分布: {stats['lengths']}")


if __name__ == "__main__":
    main()
