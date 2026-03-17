#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi 安全测试工具包 v3.0 - 主控制台
功能：统一入口，菜单驱动，智能识别家庭WiFi
"""

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent

BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def banner():
    print(f"""{CYAN}{BOLD}
 ===================================================
    WiFi 安全测试工具包 v3.0
    macOS Apple Silicon | 家庭WiFi智能识别
    仅限授权网络安全测试
 ==================================================={RESET}
{YELLOW}
  [1] 扫描周围WiFi（家庭WiFi自动标注）
  [2] 下载在线密码字典
  [3] 生成智能密码字典
  [4] WiFi密码破解（家庭WiFi专用）
  [5] Hashcat离线破解
  [6] 网络分析（连接后使用）
  [7] 查看已破解的WiFi
  [8] 修复位置权限（获取SSID名称）
  [9] 环境检查
  [A] 钥匙串WiFi密码提取
  [B] 社工字典生成（目标定向）
  [C] MAC地址伪装（规避封禁）
  [0] 退出{RESET}
""")


def run_script(name, args=None):
    """运行子脚本"""
    cmd = [sys.executable, str(SCRIPT_DIR / name)]
    if args:
        cmd.extend(args)
    subprocess.run(cmd)


def menu_scan():
    print(f"{CYAN}[扫描WiFi]{RESET}")
    mode = input("  显示全部网络? (y/N): ").strip().lower()
    args = ["-s"]
    if mode == "y":
        args.append("-a")
    cont = input("  持续扫描? (y/N): ").strip().lower()
    if cont == "y":
        interval = input("  间隔秒数 (默认5): ").strip() or "5"
        args.extend(["-c", "-i", interval])
    run_script("wifi_scanner.py", args)


def menu_download():
    print(f"{CYAN}[下载在线字典]{RESET}")
    run_script("download_dicts.py")


def menu_gen():
    print(f"{CYAN}[生成智能字典]{RESET}")
    quick = input("  快速模式（仅高频）? (y/N): ").strip().lower()
    args = []
    if quick == "y":
        args.append("--quick")
    out = input("  输出路径 (回车默认): ").strip()
    if out:
        args.extend(["-o", out])
    run_script("wordlist_gen.py", args)


def menu_crack():
    print(f"{CYAN}[WiFi密码破解]{RESET}")
    print()
    ssid = input("  目标SSID (回车进入交互选择): ").strip()

    # 列出字典
    wl_dir = PROJECT_DIR / "wordlists"
    wl_files = sorted(wl_dir.rglob("*.txt"))
    if wl_files:
        print()
        print("  可用字典:")
        for i, f in enumerate(wl_files, 1):
            lines = sum(1 for _ in open(f, "r", errors="ignore"))
            rel = f.relative_to(PROJECT_DIR)
            size = f.stat().st_size / 1024
            print(f"    [{i}] {rel} ({lines:,} 条, {size:.0f}KB)")
        print()
        choice = input(f"  选择字典 (1-{len(wl_files)}): ").strip()
        try:
            wl_path = str(wl_files[int(choice) - 1])
        except (ValueError, IndexError):
            print("[!] 无效选择")
            return
    else:
        wl_path = input("  字典路径: ").strip()

    delay = input("  间隔秒数 (默认0.5): ").strip() or "0.5"

    args = ["-w", wl_path, "-d", delay]
    if ssid:
        args.extend(["-t", ssid])
    run_script("wifi_cracker.py", args)


def menu_hashcat():
    print(f"{CYAN}[Hashcat离线破解]{RESET}")
    print("  [1] 检查环境")
    print("  [2] 转换握手包")
    print("  [3] 字典攻击")
    print("  [4] 纯数字掩码攻击")
    print()
    c = input("  选择 (1-4): ").strip()
    if c == "1":
        run_script("hashcat_helper.py", ["check"])
    elif c == "2":
        f = input("  握手包路径: ").strip()
        run_script("hashcat_helper.py", ["convert", f])
    elif c == "3":
        f = input("  哈希文件: ").strip()
        run_script("hashcat_helper.py", ["crack", f, "--list-wordlists"])
        w = input("  字典路径: ").strip()
        run_script("hashcat_helper.py", ["crack", f, "-w", w])
    elif c == "4":
        f = input("  哈希文件: ").strip()
        run_script("hashcat_helper.py", ["mask", f])


def menu_network():
    print(f"{CYAN}[网络分析]{RESET}")
    run_script("network_analyzer.py")


def menu_cracked():
    if not CRACKED_FILE.exists():
        print("[*] 暂无破解记录")
        return
    with open(CRACKED_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not data:
        print("[*] 暂无破解记录")
        return
    print(f"{GREEN}[已破解的WiFi]{RESET}")
    print(f"{'SSID':<28} {'密码':<24} {'时间'}")
    print("-" * 70)
    for ssid, info in data.items():
        print(f"{ssid:<28} {info['password']:<24} {info.get('time', 'N/A')}")


CRACKED_FILE = PROJECT_DIR / "captures" / "cracked.json"


def menu_fix_location():
    print(f"{CYAN}[修复位置权限]{RESET}")
    run_script("fix_location.py")


def menu_check():
    print(f"{CYAN}[环境检查]{RESET}")
    print(f"  Python: {sys.version.split()[0]}")

    libs = {"CoreWLAN": "pyobjc-framework-CoreWLAN", "scapy": "scapy"}
    for lib, pkg in libs.items():
        try:
            __import__(lib)
            print(f"  {lib:<14} OK")
        except ImportError:
            print(f"  {lib:<14} X (pip3 install {pkg})")

    import shutil
    for tool in ["hashcat", "aircrack-ng", "hcxpcapngtool"]:
        p = shutil.which(tool)
        print(f"  {tool:<14} {'OK (' + p + ')' if p else 'X'}")

    wl_dir = PROJECT_DIR / "wordlists"
    wl_files = list(wl_dir.rglob("*.txt"))
    total_lines = 0
    for f in wl_files:
        total_lines += sum(1 for _ in open(f, "r", errors="ignore"))
    print(f"  字典: {len(wl_files)} 个, {total_lines:,} 条密码")


def menu_keychain():
    # 钥匙串 WiFi 密码提取，可选导出全部账号信息
    print(f"{CYAN}[钥匙串提取]{RESET}")
    mode = input("  提取密码? (y/N): ").strip().lower()
    args = ["-e", "-a"] if mode == "y" else []
    run_script("keychain_extract.py", args)


def menu_smart_dict():
    # 启动社工定向字典生成
    print(f"{CYAN}[社工字典]{RESET}")
    run_script("smart_dict.py")


def menu_mac_spoof():
    # MAC 地址伪装与恢复
    print(f"{CYAN}[MAC伪装]{RESET}")
    print("  [1] 查看当前MAC")
    print("  [2] 随机化MAC")
    print("  [3] 恢复原始MAC")
    c = input("  选择: ").strip()
    if c == "2":
        run_script("mac_spoof.py", ["-r"])
    elif c == "3":
        run_script("mac_spoof.py", ["--restore"])
    else:
        run_script("mac_spoof.py")


def main():
    handlers = {
        "1": menu_scan,
        "2": menu_download,
        "3": menu_gen,
        "4": menu_crack,
        "5": menu_hashcat,
        "6": menu_network,
        "7": menu_cracked,
        "8": menu_fix_location,
        "9": menu_check,
        "a": menu_keychain,
        "b": menu_smart_dict,
        "c": menu_mac_spoof,
    }

    while True:
        banner()
        choice = input(f"{BOLD}> {RESET}").strip()
        if choice == "0":
            print("bye")
            break
        elif choice in handlers:
            try:
                handlers[choice]()
            except KeyboardInterrupt:
                print()
            print()
            input(f"{YELLOW}回车返回...{RESET}")
            clear()
        else:
            print("[!] 无效")


if __name__ == "__main__":
    main()
