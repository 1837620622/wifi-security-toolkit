#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MAC 地址管理器
功能：修改/随机化/恢复 WiFi 接口 MAC 地址，规避 AP 封禁
原理：路由器通过 MAC 地址识别设备，更换 MAC 后被视为新设备
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
MAC_BACKUP = PROJECT_DIR / "captures" / "original_mac.json"


def get_current_mac(interface="en0"):
    """获取当前 MAC 地址"""
    try:
        r = subprocess.run(["ifconfig", interface],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"ether\s+([0-9a-f:]{17})", r.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def generate_random_mac():
    """
    生成随机 MAC 地址
    规则：第一字节为偶数（单播），第二位设为1（本地管理）
    """
    first = random.randint(0, 127) * 2  # 偶数 = 单播
    first = first | 0x02  # 设置本地管理位
    octets = [first] + [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in octets)


def backup_mac(mac, interface="en0"):
    """备份原始 MAC 地址"""
    MAC_BACKUP.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if MAC_BACKUP.exists():
        with open(MAC_BACKUP, "r") as f:
            data = json.load(f)
    if interface not in data:
        data[interface] = mac
        with open(MAC_BACKUP, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] 原始MAC已备份: {mac}")


def set_mac(new_mac, interface="en0"):
    """
    修改 MAC 地址
    流程：关闭WiFi -> 修改MAC -> 开启WiFi
    """
    current = get_current_mac(interface)
    if current:
        backup_mac(current, interface)

    print(f"[*] 当前MAC: {current}")
    print(f"[*] 目标MAC: {new_mac}")
    print()

    # 关闭WiFi
    print("[1/3] 关闭WiFi...", end=" ", flush=True)
    subprocess.run(["networksetup", "-setairportpower", interface, "off"],
                   capture_output=True, timeout=5)
    time.sleep(1)
    print("OK")

    # 修改MAC（需要sudo）
    print("[2/3] 修改MAC...", end=" ", flush=True)
    r = subprocess.run(["sudo", "ifconfig", interface, "ether", new_mac],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        print(f"失败: {r.stderr.strip()}")
        # 恢复WiFi
        subprocess.run(["networksetup", "-setairportpower", interface, "on"],
                       capture_output=True)
        return False
    time.sleep(1)
    print("OK")

    # 开启WiFi
    print("[3/3] 开启WiFi...", end=" ", flush=True)
    subprocess.run(["networksetup", "-setairportpower", interface, "on"],
                   capture_output=True, timeout=5)
    time.sleep(2)
    print("OK")

    # 验证
    actual = get_current_mac(interface)
    if actual and actual.lower() == new_mac.lower():
        print(f"[+] MAC修改成功: {actual}")
        return True
    else:
        print(f"[!] MAC可能未生效 (当前: {actual})")
        print("    macOS可能已阻止修改，某些版本需要关闭SIP")
        return False


def restore_mac(interface="en0"):
    """恢复原始 MAC 地址"""
    if not MAC_BACKUP.exists():
        print("[!] 无备份记录")
        return False
    with open(MAC_BACKUP, "r") as f:
        data = json.load(f)
    original = data.get(interface)
    if not original:
        print(f"[!] 无 {interface} 的备份")
        return False
    print(f"[*] 恢复原始MAC: {original}")
    return set_mac(original, interface)


def main():
    parser = argparse.ArgumentParser(description="MAC 地址管理器")
    parser.add_argument("-r", "--random", action="store_true", help="随机化MAC")
    parser.add_argument("--restore", action="store_true", help="恢复原始MAC")
    parser.add_argument("--set", type=str, metavar="MAC", help="设置指定MAC")
    parser.add_argument("-i", "--interface", default="en0", help="网络接口")
    args = parser.parse_args()

    print("=" * 45)
    print("  MAC 地址管理器")
    print("=" * 45)
    print()

    current = get_current_mac(args.interface)
    print(f"[*] 接口: {args.interface}")
    print(f"[*] 当前MAC: {current or '未知'}")

    if args.restore:
        restore_mac(args.interface)
    elif args.random:
        new = generate_random_mac()
        set_mac(new, args.interface)
    elif args.set:
        set_mac(args.set, args.interface)
    else:
        # 仅显示信息
        if MAC_BACKUP.exists():
            with open(MAC_BACKUP, "r") as f:
                data = json.load(f)
            orig = data.get(args.interface)
            if orig:
                print(f"[*] 原始MAC: {orig}")
                if current and current.lower() != orig.lower():
                    print("[*] 状态: 已修改")
                else:
                    print("[*] 状态: 原始")


if __name__ == "__main__":
    main()
