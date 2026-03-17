#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hashcat 离线破解辅助工具
功能：管理 .cap/.hccapx/.hc22000 握手包文件，调用 hashcat 进行 GPU 加速破解
适配：macOS + hashcat（通过 Homebrew 安装）
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

# ============================================================
# 项目路径
# ============================================================
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
CAPTURES_DIR = PROJECT_DIR / "captures"
WORDLISTS_DIR = PROJECT_DIR / "wordlists"


# ============================================================
# 检查工具是否安装
# ============================================================
def check_tool(name):
    """检查命令行工具是否可用"""
    return shutil.which(name) is not None


def check_environment():
    """检查运行环境"""
    tools = {
        "hashcat": check_tool("hashcat"),
        "hcxpcapngtool": check_tool("hcxpcapngtool"),
    }

    print("[*] 环境检查:")
    for tool, available in tools.items():
        status = "✅ 已安装" if available else "❌ 未安装"
        print(f"    {tool}: {status}")

    if not tools["hashcat"]:
        # 分开输出空行和正文，避免 \n 被误写成真实换行导致语法错误
        print()
        print("[!] hashcat 未安装，请执行: brew install hashcat")

    if not tools["hcxpcapngtool"]:
        print("[!] hcxtools 未安装，请执行: brew install hcxtools")
        print("    （用于将 .cap 文件转换为 hashcat 格式）")

    return tools


# ============================================================
# 文件格式转换
# ============================================================
def convert_cap_to_hc22000(cap_file, output=None):
    """
    将 .cap/.pcap/.pcapng 文件转换为 hashcat 22000 格式
    使用 hcxpcapngtool
    """
    cap_file = Path(cap_file)
    if output is None:
        output = cap_file.with_suffix(".hc22000")
    else:
        output = Path(output)

    if not check_tool("hcxpcapngtool"):
        print("[!] hcxpcapngtool 未安装: brew install hcxtools")
        return None

    try:
        r = subprocess.run(
            ["hcxpcapngtool", "-o", str(output), str(cap_file)],
            capture_output=True, text=True, timeout=30
        )
        if output.exists() and output.stat().st_size > 0:
            print(f"[+] 转换成功: {output}")
            return output
        else:
            print(f"[!] 转换失败（文件为空或无有效握手包）")
            print(f"    {r.stderr.strip()}")
            return None
    except Exception as e:
        print(f"[!] 转换出错: {e}")
        return None


def convert_hccapx_to_hc22000(hccapx_file, output=None):
    """将旧版 .hccapx 转换为 hc22000 格式"""
    hccapx_file = Path(hccapx_file)
    if output is None:
        output = hccapx_file.with_suffix(".hc22000")

    try:
        r = subprocess.run(
            ["hcxpcapngtool", "-o", str(output), str(hccapx_file)],
            capture_output=True, text=True, timeout=30
        )
        if output.exists():
            print(f"[+] 转换成功: {output}")
            return output
    except Exception:
        pass
    return None


# ============================================================
# 自动检测文件格式
# ============================================================
def detect_format(filepath):
    """检测握手包文件格式"""
    filepath = Path(filepath)
    ext = filepath.suffix.lower()

    format_map = {
        ".hc22000": "hc22000",
        ".22000": "hc22000",
        ".hccapx": "hccapx",
        ".cap": "cap",
        ".pcap": "cap",
        ".pcapng": "cap",
    }

    return format_map.get(ext, "unknown")


# ============================================================
# 准备 hashcat 输入文件
# ============================================================
def prepare_hashfile(filepath):
    """
    自动检测格式并转换为 hashcat 可用的 hc22000 格式
    返回准备好的文件路径
    """
    filepath = Path(filepath)
    fmt = detect_format(filepath)

    if fmt == "hc22000":
        print(f"[*] 文件已是 hc22000 格式: {filepath}")
        return filepath
    elif fmt in ("cap", "hccapx"):
        print(f"[*] 检测到 {fmt} 格式，正在转换...")
        return convert_cap_to_hc22000(filepath)
    else:
        print(f"[!] 不支持的格式: {filepath.suffix}")
        print("    支持: .cap, .pcap, .pcapng, .hccapx, .hc22000")
        return None


# ============================================================
# 列出可用的字典文件
# ============================================================
def list_wordlists():
    """列出项目中所有可用的字典文件"""
    # 先输出空行，再输出标题，避免 \n 字符串被破坏
    print()
    print("可用字典:")
    wl_files = sorted(WORDLISTS_DIR.rglob("*.txt"))
    for i, f in enumerate(wl_files, 1):
        size = f.stat().st_size / 1024
        lines = sum(1 for _ in open(f, "r", errors="ignore"))
        rel = f.relative_to(PROJECT_DIR)
        print(f"  [{i}] {rel} ({lines} 条, {size:.0f} KB)")
    return wl_files


# ============================================================
# 调用 hashcat 破解
# ============================================================
def run_hashcat(hash_file, wordlist, attack_mode=0, extra_args=None):
    """
    调用 hashcat 进行 WPA/WPA2 密码破解

    参数：
        hash_file: hc22000 格式的哈希文件
        wordlist: 密码字典路径
        attack_mode: 攻击模式（0=字典, 3=掩码, 6=字典+掩码）
        extra_args: 额外的 hashcat 参数
    """
    if not check_tool("hashcat"):
        print("[!] hashcat 未安装")
        return False

    hash_file = Path(hash_file)
    wordlist = Path(wordlist)

    if not hash_file.exists():
        print(f"[!] 哈希文件不存在: {hash_file}")
        return False

    # 构建命令
    cmd = [
        "hashcat",
        "-m", "22000",           # WPA-PBKDF2-PMKID+EAPOL 模式
        "-a", str(attack_mode),  # 攻击模式
        "--status",              # 显示状态
        "--status-timer", "10",  # 每10秒更新状态
        "-o", str(CAPTURES_DIR / "hashcat_cracked.txt"),  # 输出文件
        str(hash_file),
    ]

    if attack_mode == 0:
        # 字典攻击
        if not wordlist.exists():
            print(f"[!] 字典不存在: {wordlist}")
            return False
        cmd.append(str(wordlist))
    elif attack_mode == 3:
        # 掩码攻击（默认8位纯数字）
        cmd.append("?d?d?d?d?d?d?d?d")

    if extra_args:
        cmd.extend(extra_args)

    # 分开输出空行和正文，避免换行字面量断裂
    print()
    print("[*] 启动 hashcat...")
    print("    模式:   WPA/WPA2 (22000)")
    print(f"    攻击:   {'字典' if attack_mode == 0 else '掩码' if attack_mode == 3 else '混合'}")
    print(f"    哈希:   {hash_file}")
    if attack_mode == 0:
        print(f"    字典:   {wordlist}")
    print(f"    命令:   {' '.join(cmd)}")
    print()

    try:
        process = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()

        # 检查结果
        cracked_file = CAPTURES_DIR / "hashcat_cracked.txt"
        if cracked_file.exists() and cracked_file.stat().st_size > 0:
            print()
            print("[+] 破解结果:")
            with open(cracked_file, "r") as f:
                for line in f:
                    print(f"    {line.strip()}")
            return True
        else:
            print()
            print("[!] 未找到密码")
            return False

    except KeyboardInterrupt:
        print()
        print("[*] 用户中断")
        return False
    except Exception as e:
        print(f"[!] hashcat 执行出错: {e}")
        return False


# ============================================================
# 掩码攻击（纯数字暴力破解）
# ============================================================
def mask_attack(hash_file, min_len=8, max_len=12):
    """
    使用掩码模式暴力破解纯数字密码
    WiFi 密码最少8位，大部分中国用户设置8-11位纯数字
    """
    if not check_tool("hashcat"):
        print("[!] hashcat 未安装")
        return False

    hash_file = Path(hash_file)

    for length in range(min_len, max_len + 1):
        mask = "?d" * length
        # 原先这里通过 \n 前缀换行，改为分离输出更稳妥
        print()
        print(f"[*] 尝试 {length} 位纯数字 (掩码: {mask})")

        cmd = [
            "hashcat",
            "-m", "22000",
            "-a", "3",
            "--status",
            "--status-timer", "15",
            "-o", str(CAPTURES_DIR / "hashcat_cracked.txt"),
            str(hash_file),
            mask,
        ]

        try:
            process = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
            process.wait()

            cracked_file = CAPTURES_DIR / "hashcat_cracked.txt"
            if cracked_file.exists() and cracked_file.stat().st_size > 0:
                print()
                print("[+] 破解成功！")
                with open(cracked_file, "r") as f:
                    print(f.read())
                return True
        except KeyboardInterrupt:
            print()
            print("[*] 跳过当前长度")
            continue

    return False


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Hashcat 离线破解辅助工具")
    sub = parser.add_subparsers(dest="command", help="子命令")

    # check 子命令
    sub.add_parser("check", help="检查环境")

    # convert 子命令
    p_convert = sub.add_parser("convert", help="转换握手包格式")
    p_convert.add_argument("file", help="输入文件路径 (.cap/.pcap/.hccapx)")
    p_convert.add_argument("-o", "--output", help="输出文件路径")

    # crack 子命令
    p_crack = sub.add_parser("crack", help="字典攻击")
    p_crack.add_argument("hashfile", help="哈希文件路径")
    p_crack.add_argument("-w", "--wordlist", help="字典文件路径")
    p_crack.add_argument("--list-wordlists", action="store_true", help="列出可用字典")

    # mask 子命令
    p_mask = sub.add_parser("mask", help="掩码暴力攻击（纯数字）")
    p_mask.add_argument("hashfile", help="哈希文件路径")
    p_mask.add_argument("--min", type=int, default=8, help="最短长度")
    p_mask.add_argument("--max", type=int, default=12, help="最长长度")

    args = parser.parse_args()

    if args.command == "check":
        check_environment()

    elif args.command == "convert":
        prepare_hashfile(args.file)

    elif args.command == "crack":
        if args.list_wordlists:
            list_wordlists()
            return
        if not args.wordlist:
            # 默认使用生成的字典
            default_wl = WORDLISTS_DIR / "wifi_dict_final.txt"
            if default_wl.exists():
                args.wordlist = str(default_wl)
            else:
                print("[!] 请指定字典: -w 路径 （或先运行 wordlist_gen.py 生成）")
                list_wordlists()
                return

        hf = prepare_hashfile(args.hashfile)
        if hf:
            run_hashcat(hf, args.wordlist)

    elif args.command == "mask":
        hf = prepare_hashfile(args.hashfile)
        if hf:
            mask_attack(hf, args.min, args.max)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
