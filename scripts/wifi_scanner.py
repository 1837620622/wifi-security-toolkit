#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi 网络扫描器 v2.0
核心升级：
  1. 智能识别家庭WiFi vs 企业/校园WiFi
  2. 多源SSID获取（CoreWLAN + system_profiler + networksetup）
  3. 安全类型精确分类
适配：macOS Apple Silicon
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent

# ============================================================
# 安全类型常量（CoreWLAN securityType 枚举值）
# ============================================================
SEC_OPEN = 0
SEC_WPA_PERSONAL = 2
SEC_WPA_ENTERPRISE = 4
SEC_WPA2_PERSONAL = 8
SEC_WPA2_ENTERPRISE = 16
SEC_WPA3_PERSONAL = 32
SEC_WPA3_ENTERPRISE = 64
SEC_WPA_WPA2_PERSONAL = 128       # WPA/WPA2混合个人
SEC_WPA3_TRANSITION = 2048        # WPA3过渡模式
SEC_WPA2_WPA3_MIXED = 4224        # WPA2/WPA3混合

# 家庭WiFi安全类型集合（使用预共享密钥PSK）
HOME_SECURITY_CODES = {
    SEC_WPA_PERSONAL, SEC_WPA2_PERSONAL, SEC_WPA3_PERSONAL,
    SEC_WPA_WPA2_PERSONAL, SEC_WPA3_TRANSITION, SEC_WPA2_WPA3_MIXED,
}

# 企业WiFi安全类型集合（使用802.1X认证）
ENTERPRISE_SECURITY_CODES = {
    SEC_WPA_ENTERPRISE, SEC_WPA2_ENTERPRISE, SEC_WPA3_ENTERPRISE,
}

# 安全类型名称映射
SEC_NAMES = {
    0: "Open",
    2: "WPA-Personal",
    4: "WPA-Enterprise",
    8: "WPA2-Personal",
    16: "WPA2-Enterprise",
    32: "WPA3-Personal",
    64: "WPA3-Enterprise",
    128: "WPA/WPA2-Personal",
    2048: "WPA3-Transition",
    4224: "WPA2/WPA3-Mixed",
}

# ============================================================
# 中国家庭路由器SSID特征库
# ============================================================
HOME_SSID_PATTERNS = [
    "TP-LINK", "TP-Link", "Tenda", "MERCURY", "Mercury",
    "FAST", "HUAWEI", "Huawei", "HONOR", "MiWiFi",
    "Xiaomi", "Redmi", "CMCC-", "ChinaNet-", "CU_",
    "NETGEAR", "ASUS", "D-Link", "Ruijie", "H3C",
    "ZTE", "TOTOLINK", "PHICOMM", "newifi",
]

# 校园/企业WiFi SSID关键词
ENTERPRISE_SSID_KEYWORDS = [
    "eduroam", "802.1x", "1X", "-1X", "Enterprise",
    "campus", "office", "corp", "guest",
]


def classify_network(ssid, security_code):
    """
    智能分类WiFi网络类型
    返回: "home"(家庭), "enterprise"(企业/校园), "open"(开放), "unknown"
    """
    # 安全类型判断（最可靠）
    if security_code == SEC_OPEN:
        return "open"
    if security_code in ENTERPRISE_SECURITY_CODES:
        return "enterprise"
    if security_code in HOME_SECURITY_CODES:
        # 进一步通过SSID名称确认
        if ssid:
            ssid_upper = ssid.upper()
            for kw in ENTERPRISE_SSID_KEYWORDS:
                if kw.upper() in ssid_upper:
                    return "enterprise"
        return "home"

    # 混合类型（包含企业+个人位），检查SSID
    if ssid:
        ssid_upper = ssid.upper()
        for kw in ENTERPRISE_SSID_KEYWORDS:
            if kw.upper() in ssid_upper:
                return "enterprise"
        for pattern in HOME_SSID_PATTERNS:
            if pattern.upper() in ssid_upper:
                return "home"
    return "unknown"


def get_sec_name(code):
    """安全类型码转可读名称"""
    if code in SEC_NAMES:
        return SEC_NAMES[code]
    parts = []
    for bit, name in sorted(SEC_NAMES.items()):
        if bit > 0 and (code & bit):
            parts.append(name)
    return "/".join(parts) if parts else f"Code:{code}"


# ============================================================
# CoreWLAN 扫描
# ============================================================
def scan_corewlan():
    """CoreWLAN扫描，返回 (网络列表, 当前连接信息)"""
    try:
        import CoreWLAN
    except ImportError:
        print("[!] pip3 install pyobjc-framework-CoreWLAN")
        return [], None

    client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
    iface = client.interface()
    if not iface:
        return [], None

    current = {
        "interface": iface.interfaceName() or "en0",
        "ssid": iface.ssid() or "(未连接)",
        "rssi": iface.rssiValue(),
        "channel": iface.wlanChannel().channelNumber() if iface.wlanChannel() else 0,
        "power": iface.powerOn(),
    }

    networks_set, err = iface.scanForNetworksWithName_error_(None, None)
    if err or not networks_set:
        return [], current

    results = []
    for net in networks_set:
        ssid = net.ssid() or ""
        bssid = net.bssid() or ""
        rssi = net.rssiValue()
        ch_obj = net.wlanChannel()
        channel = ch_obj.channelNumber() if ch_obj else 0
        band = "5GHz" if channel > 14 else "2.4GHz"
        try:
            sec_code = net.securityType()
        except Exception:
            sec_code = -1

        security = get_sec_name(sec_code)
        net_type = classify_network(ssid, sec_code)

        results.append({
            "ssid": ssid,
            "bssid": bssid,
            "rssi": rssi,
            "channel": channel,
            "band": band,
            "security": security,
            "security_code": sec_code,
            "type": net_type,
            "_cw_network": net,
        })

    return sorted(results, key=lambda x: x["rssi"], reverse=True), current


# ============================================================
# system_profiler 补充（获取被redacted的SSID）
# ============================================================
def scan_system_profiler():
    """system_profiler扫描（macOS 26+下SSID也可能被redacted）"""
    try:
        r = subprocess.run(
            ["system_profiler", "SPAirPortDataType", "-json"],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(r.stdout)
        networks = []
        for item in data.get("SPAirPortDataType", []):
            for iface in item.get("spairport_airport_interfaces", []):
                for net in iface.get("spairport_airport_other_local_wireless_networks", []):
                    name = net.get("_name", "")
                    if name == "<redacted>":
                        name = ""
                    ch_str = net.get("spairport_network_channel", "")
                    sec = net.get("spairport_security_mode", "")
                    ch = 0
                    if ch_str:
                        try:
                            ch = int(ch_str.split(",")[0].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
                    # 解析安全模式字符串
                    sec_readable = sec.replace("spairport_security_mode_", "").replace("_", "-")
                    networks.append({
                        "ssid": name, "bssid": "", "rssi": 0,
                        "channel": ch,
                        "band": "5GHz" if ch > 14 else "2.4GHz",
                        "security": sec_readable,
                    })
        return networks
    except Exception:
        return []


# ============================================================
# 信号强度可视化
# ============================================================
def signal_bar(rssi):
    if rssi > -50:
        return "█████"
    elif rssi > -60:
        return "████░"
    elif rssi > -70:
        return "███░░"
    elif rssi > -80:
        return "██░░░"
    elif rssi > -90:
        return "█░░░░"
    return "░░░░░"


def type_label(net_type):
    """网络类型中文标签"""
    labels = {
        "home": "🏠家庭",
        "enterprise": "🏢企业",
        "open": "🔓开放",
        "unknown": "❓未知",
    }
    return labels.get(net_type, "❓")


# ============================================================
# 显示扫描结果
# ============================================================
def display(networks, current=None, show_all=False):
    if current:
        status = "已连接" if current.get("ssid") != "(未连接)" else "未连接"
        print(f"[*] 接口: {current.get('interface')}  状态: {status}")
        if status == "已连接":
            print(f"    SSID: {current['ssid']}  RSSI: {current['rssi']}dBm  CH: {current['channel']}")
        print()

    if not networks:
        print("[!] 未发现网络")
        return

    # 分类统计
    home_count = sum(1 for n in networks if n["type"] == "home")
    ent_count = sum(1 for n in networks if n["type"] == "enterprise")
    open_count = sum(1 for n in networks if n["type"] == "open")

    print(f"[*] 共 {len(networks)} 个网络: {home_count} 家庭 | {ent_count} 企业 | {open_count} 开放")
    print()

    # 只显示家庭WiFi（除非 show_all）
    if not show_all:
        display_nets = [n for n in networks if n["type"] in ("home", "unknown")]
        if not display_nets:
            display_nets = networks
        print("[家庭WiFi / 可破解目标]")
    else:
        display_nets = networks
        print("[全部网络]")

    print(f"{'#':>3} {'SSID':<24} {'RSSI':>5} {'CH':>4} {'频段':>5} {'安全类型':<22} {'类型':<8} {'信号'}")
    print("-" * 100)

    for i, n in enumerate(display_nets, 1):
        ssid = n["ssid"] if n["ssid"] else "(需要位置权限)"
        print(f"{i:>3} {ssid:<24} {n['rssi']:>4}  {n['channel']:>3}  {n['band']:>5} {n['security']:<22} {type_label(n['type']):<8} {signal_bar(n['rssi'])}")


# ============================================================
# 保存结果
# ============================================================
def save_results(networks, path=None):
    if path is None:
        path = PROJECT_DIR / "captures" / "scan_results.json"
    else:
        path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # 去掉不可序列化的 _cw_network
    clean = []
    for n in networks:
        d = {k: v for k, v in n.items() if k != "_cw_network"}
        clean.append(d)

    data = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(clean),
        "home_wifi_count": sum(1 for n in clean if n["type"] == "home"),
        "networks": clean,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] 已保存: {path}")


# ============================================================
# 入口
# ============================================================
def scan(save=False, output=None):
    """执行扫描并返回结果（供其他模块调用）"""
    nets, cur = scan_corewlan()
    sp = scan_system_profiler()
    # 尝试用sp补充SSID
    if sp:
        sp_by_ch = {}
        for s in sp:
            if s["ssid"]:
                sp_by_ch.setdefault(s["channel"], []).append(s)
        for n in nets:
            if not n["ssid"] and n["channel"] in sp_by_ch:
                cands = sp_by_ch[n["channel"]]
                if cands:
                    match = cands.pop(0)
                    n["ssid"] = match["ssid"]
                    if n["security"] == "Unknown" and match["security"]:
                        n["security"] = match["security"]
                    n["type"] = classify_network(n["ssid"], n.get("security_code", -1))

    if save:
        save_results(nets, output)
    return nets, cur


def main():
    parser = argparse.ArgumentParser(description="WiFi 扫描器 v2.0")
    parser.add_argument("-c", "--continuous", action="store_true", help="持续扫描")
    parser.add_argument("-i", "--interval", type=int, default=5, help="扫描间隔")
    parser.add_argument("-o", "--output", type=str, help="JSON保存路径")
    parser.add_argument("-s", "--save", action="store_true", help="保存结果")
    parser.add_argument("-a", "--all", action="store_true", help="显示全部网络（含企业）")
    parser.add_argument("--json", action="store_true", help="JSON输出")
    args = parser.parse_args()

    if not args.json:
        print("=" * 50)
        print("  WiFi 扫描器 v2.0 (家庭WiFi智能识别)")
        print("=" * 50)

    if args.continuous:
        print(f"[*] 持续扫描 (间隔{args.interval}s, Ctrl+C停止)")
        try:
            cnt = 0
            while True:
                cnt += 1
                if not args.json:
                    print(f"\n--- 第{cnt}次 ---")
                nets, cur = scan(args.save, args.output)
                if args.json:
                    clean = [{k: v for k, v in n.items() if k != "_cw_network"} for n in nets]
                    print(json.dumps(clean, ensure_ascii=False))
                else:
                    display(nets, cur, args.all)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] 已停止")
    else:
        nets, cur = scan(args.save or bool(args.output), args.output)
        if args.json:
            clean = [{k: v for k, v in n.items() if k != "_cw_network"} for n in nets]
            print(json.dumps(clean, ensure_ascii=False, indent=2))
        else:
            display(nets, cur, args.all)
            if not any(n["ssid"] for n in nets):
                print()
                print("[!] SSID 全部被隐藏（macOS隐私限制）")
                print("    修复: python3 scripts/fix_location.py")
                print("    或在「系统设置 -> 隐私与安全 -> 位置服务」中授权终端")


if __name__ == "__main__":
    main()
