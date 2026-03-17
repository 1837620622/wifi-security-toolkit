#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hashcat 离线破解辅助工具 v2.0
功能：管理握手包文件，调用 hashcat 进行 GPU 加速破解
升级功能：
  1. 规则攻击（rule-based）：使用变异规则扩展字典覆盖率
  2. 混合攻击（hybrid）：字典+掩码组合攻击
  3. Brain模式：跨攻击避免重复候选，提升效率
  4. 中国密码特化规则：针对中国用户密码习惯的自定义规则
  5. 智能攻击推荐：根据路由器品牌推荐最优攻击方式
学术参考：
  - hashcat Brain (hashcat docs): 候选去重，跨攻击模式记忆
  - Slow Candidates Mode: 集成PassGAN/PCFG/OMEN等生成器
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
RULES_DIR = PROJECT_DIR / "rules"


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
# 规则攻击（rule-based，字典变异扩展）
# ============================================================
def generate_chinese_rules(output_path=None):
    """
    生成中国密码特化规则文件
    基于中国用户密码习惯设计的 hashcat 规则集

    规则语法参考 hashcat wiki：
      $ = 追加字符, ^ = 前插字符, c = 首字母大写,
      l = 全小写, u = 全大写, r = 反转,
      sa@ = 替换a为@, se3 = 替换e为3 (leet speak)
    """
    if output_path is None:
        output_path = RULES_DIR / "chinese_wifi.rule"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rules = [
        # ---- 基础变换 ----
        ":",              # 原始密码
        "c",              # 首字母大写
        "u",              # 全大写
        "r",              # 反转
        "d",              # 重复（password -> passwordpassword）
        # ---- 数字后缀（中国用户最爱） ----
        "$1",             # 追加1
        "$1$2$3",         # 追加123
        "$1$2$3$4",       # 追加1234
        "$1$2$3$4$5$6",   # 追加123456
        "$5$2$0",         # 追加520
        "$1$3$1$4",       # 追加1314
        "$8$8$8",         # 追加888
        "$6$6$6",         # 追加666
        "$0$0$0",         # 追加000
        "$1$1$1",         # 追加111
        "$1$6$8",         # 追加168
        "$1$8$8",         # 追加188
        "$5$2$1",         # 追加521
        "$0$1",           # 追加01
        "$1$1",           # 追加11
        "$2$2",           # 追加22
        "$6$6",           # 追加66
        "$8$8",           # 追加88
        "$9$9",           # 追加99
        # ---- 数字前缀 ----
        "^1",             # 前插1
        "^3^2^1",         # 前插123
        "^0^2^5",         # 前插520
        # ---- Leet Speak（常见替换） ----
        "sa@",            # a -> @
        "se3",            # e -> 3
        "si1",            # i -> 1
        "so0",            # o -> 0
        "ss5",            # s -> 5
        "sa@ se3",        # a->@ 且 e->3
        "sa@ se3 si1 so0",  # 全套leet
        # ---- 首字母大写+数字后缀 ----
        "c $1$2$3",       # Password123
        "c $5$2$0",       # Password520
        "c $8$8$8",       # Password888
        "c $1$3$1$4",     # Password1314
        # ---- 特殊字符 ----
        "$!",             # 追加!
        "$@",             # 追加@
        "$#",             # 追加#
        "$.",             # 追加.
        # ---- 年份追加 ----
        "$2$0$2$4",       # 追加2024
        "$2$0$2$3",       # 追加2023
        "$2$0$2$5",       # 追加2025
        "$2$0$2$0",       # 追加2020
        # ---- 组合变换 ----
        "c $1",           # 首字母大写+追加1
        "c $1$2",         # 首字母大写+追加12
        "u $1$2$3",       # 全大写+追加123
        "r $1$2$3",       # 反转+追加123
        "c sa@ $1$2$3",   # 首字母大写+leet+追加123
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# 中国WiFi密码特化规则 v1.0\n")
        f.write("# 基于中国用户密码习惯设计\n")
        f.write("# 规则数量: {}\n".format(len(rules)))
        for rule in rules:
            f.write(rule + "\n")

    print(f"[+] 中国特化规则已生成: {output_path}")
    print(f"    规则数量: {len(rules)} 条")
    print(f"    每个字典词将产生 {len(rules)} 个变体")
    return output_path


def run_rule_attack(hash_file, wordlist, rule_file=None, brain=False):
    """
    规则攻击：使用变异规则扩展字典覆盖率

    参数：
        hash_file: hc22000 格式的哈希文件
        wordlist: 基础字典
        rule_file: 规则文件（默认使用中国特化规则）
        brain: 是否启用Brain模式（跨攻击去重）
    """
    if not check_tool("hashcat"):
        print("[!] hashcat 未安装")
        return False

    hash_file = Path(hash_file)
    wordlist = Path(wordlist)

    # 默认使用中国特化规则
    if rule_file is None:
        rule_file = RULES_DIR / "chinese_wifi.rule"
        if not rule_file.exists():
            generate_chinese_rules(rule_file)
    else:
        rule_file = Path(rule_file)

    if not rule_file.exists():
        # 尝试使用hashcat内置规则
        for builtin in ["/opt/homebrew/share/hashcat/rules/best64.rule",
                        "/usr/local/share/hashcat/rules/best64.rule",
                        "/usr/share/hashcat/rules/best64.rule"]:
            if Path(builtin).exists():
                rule_file = Path(builtin)
                break
        else:
            print("[!] 无可用规则文件")
            return False

    cmd = [
        "hashcat",
        "-m", "22000",
        "-a", "0",              # 字典攻击
        "-r", str(rule_file),   # 规则文件
        "--status",
        "--status-timer", "10",
        "-o", str(CAPTURES_DIR / "hashcat_cracked.txt"),
        str(hash_file),
        str(wordlist),
    ]

    if brain:
        cmd.insert(1, "-z")    # Brain模式

    print()
    print("[*] 启动规则攻击...")
    print(f"    模式:   WPA/WPA2 (22000) + 规则变异")
    print(f"    哈希:   {hash_file}")
    print(f"    字典:   {wordlist}")
    print(f"    规则:   {rule_file}")
    if brain:
        print(f"    Brain:  已启用（跨攻击候选去重）")
    print(f"    命令:   {' '.join(cmd)}")
    print()

    try:
        process = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()
        return _check_cracked()
    except KeyboardInterrupt:
        print()
        print("[*] 用户中断")
        return False
    except Exception as e:
        print(f"[!] 执行出错: {e}")
        return False


def run_hybrid_attack(hash_file, wordlist, mask="?d?d?d?d", mode=6, brain=False):
    """
    混合攻击：字典+掩码组合

    参数：
        hash_file: hc22000 哈希文件
        wordlist: 基础字典
        mask: 掩码（默认4位数字后缀）
        mode: 攻击模式（6=字典+掩码, 7=掩码+字典）
        brain: 是否启用Brain模式

    示例：
        mode=6: 字典词 + 掩码 → password1234
        mode=7: 掩码 + 字典词 → 1234password
    """
    if not check_tool("hashcat"):
        print("[!] hashcat 未安装")
        return False

    hash_file = Path(hash_file)
    wordlist = Path(wordlist)

    cmd = [
        "hashcat",
        "-m", "22000",
        "-a", str(mode),        # 混合攻击模式
        "--status",
        "--status-timer", "10",
        "-o", str(CAPTURES_DIR / "hashcat_cracked.txt"),
        str(hash_file),
    ]

    if mode == 6:
        cmd.extend([str(wordlist), mask])
        desc = f"字典({wordlist.name}) + 掩码({mask})"
    else:
        cmd.extend([mask, str(wordlist)])
        desc = f"掩码({mask}) + 字典({wordlist.name})"

    if brain:
        cmd.insert(1, "-z")

    print()
    print("[*] 启动混合攻击...")
    print(f"    模式:   WPA/WPA2 (22000) + 混合模式{mode}")
    print(f"    组合:   {desc}")
    print(f"    哈希:   {hash_file}")
    if brain:
        print(f"    Brain:  已启用")
    print(f"    命令:   {' '.join(cmd)}")
    print()

    try:
        process = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()
        return _check_cracked()
    except KeyboardInterrupt:
        print()
        print("[*] 用户中断")
        return False
    except Exception as e:
        print(f"[!] 执行出错: {e}")
        return False


def run_smart_attack(hash_file, wordlist=None):
    """
    智能攻击推荐：自动编排多种攻击方式
    按照命中概率从高到低执行：
      1. 字典攻击（基础字典）
      2. 规则攻击（字典+中国特化规则）
      3. 8位纯数字掩码
      4. 混合攻击（字典+数字后缀）
      5. 9-11位纯数字掩码
    """
    hash_file = Path(hash_file)
    if wordlist is None:
        wordlist = WORDLISTS_DIR / "wifi_dict_final.txt"
    else:
        wordlist = Path(wordlist)

    attacks = [
        ("字典攻击", lambda: run_hashcat(hash_file, wordlist)),
        ("规则攻击(中国特化)", lambda: run_rule_attack(hash_file, wordlist)),
        ("8位纯数字掩码", lambda: mask_attack(hash_file, 8, 8)),
        ("混合攻击(字典+3位数字)", lambda: run_hybrid_attack(hash_file, wordlist, "?d?d?d", 6)),
        ("混合攻击(字典+4位数字)", lambda: run_hybrid_attack(hash_file, wordlist, "?d?d?d?d", 6)),
        ("9-11位纯数字掩码", lambda: mask_attack(hash_file, 9, 11)),
    ]

    print()
    print("[*] 智能攻击编排 (按命中概率排序)")
    print("=" * 50)
    for i, (name, _) in enumerate(attacks, 1):
        print(f"  [{i}] {name}")
    print("=" * 50)
    print()

    for i, (name, attack_fn) in enumerate(attacks, 1):
        print(f"\n{'=' * 50}")
        print(f"  攻击 {i}/{len(attacks)}: {name}")
        print(f"{'=' * 50}")
        if attack_fn():
            print(f"\n[+] 在第{i}轮({name})中破解成功！")
            return True

    print("\n[!] 所有攻击方式均未命中")
    return False


def _check_cracked():
    """检查hashcat是否已破解成功"""
    cracked_file = CAPTURES_DIR / "hashcat_cracked.txt"
    if cracked_file.exists() and cracked_file.stat().st_size > 0:
        print()
        print("[+] 破解结果:")
        with open(cracked_file, "r") as f:
            for line in f:
                print(f"    {line.strip()}")
        return True
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

    # rule 子命令 - 规则攻击
    p_rule = sub.add_parser("rule", help="规则攻击（字典变异扩展）")
    p_rule.add_argument("hashfile", help="哈希文件路径")
    p_rule.add_argument("-w", "--wordlist", help="字典文件路径")
    p_rule.add_argument("-r", "--rule-file", help="规则文件路径（默认中国特化规则）")
    p_rule.add_argument("--brain", action="store_true", help="启用Brain模式（去重优化）")

    # hybrid 子命令 - 混合攻击
    p_hybrid = sub.add_parser("hybrid", help="混合攻击（字典+掩码）")
    p_hybrid.add_argument("hashfile", help="哈希文件路径")
    p_hybrid.add_argument("-w", "--wordlist", help="字典文件路径")
    p_hybrid.add_argument("-m", "--mask", default="?d?d?d?d", help="掩码（默认4位数字）")
    p_hybrid.add_argument("--mode", type=int, default=6, choices=[6, 7],
                          help="6=字典+掩码, 7=掩码+字典")
    p_hybrid.add_argument("--brain", action="store_true", help="启用Brain模式")

    # smart 子命令 - 智能攻击
    p_smart = sub.add_parser("smart", help="智能攻击（自动编排多种攻击方式）")
    p_smart.add_argument("hashfile", help="哈希文件路径")
    p_smart.add_argument("-w", "--wordlist", help="字典文件路径")

    # genrule 子命令 - 生成中国特化规则
    sub.add_parser("genrule", help="生成中国密码特化规则文件")

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

    elif args.command == "rule":
        hf = prepare_hashfile(args.hashfile)
        if hf:
            wl = args.wordlist or str(WORDLISTS_DIR / "wifi_dict_final.txt")
            run_rule_attack(hf, wl, args.rule_file, args.brain)

    elif args.command == "hybrid":
        hf = prepare_hashfile(args.hashfile)
        if hf:
            wl = args.wordlist or str(WORDLISTS_DIR / "wifi_dict_final.txt")
            run_hybrid_attack(hf, wl, args.mask, args.mode, args.brain)

    elif args.command == "smart":
        hf = prepare_hashfile(args.hashfile)
        if hf:
            run_smart_attack(hf, args.wordlist)

    elif args.command == "genrule":
        generate_chinese_rules()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
