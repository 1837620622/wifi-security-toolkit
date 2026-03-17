#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络分析器
功能：WiFi 连接成功后，分析目标网络的详细信息
包含：网关探测、局域网设备扫描、网络测速、路由器识别
"""

import json
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# ============================================================
# 项目路径
# ============================================================
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent


# ============================================================
# 获取本机网络信息
# ============================================================
def get_network_info(interface="en0"):
    """获取当前网络连接的基本信息"""
    info = {"interface": interface}

    # IP 地址
    try:
        r = subprocess.run(["ipconfig", "getifaddr", interface],
                           capture_output=True, text=True, timeout=5)
        info["ip"] = r.stdout.strip()
    except Exception:
        info["ip"] = "N/A"

    # 子网掩码
    try:
        r = subprocess.run(["ifconfig", interface],
                           capture_output=True, text=True, timeout=5)
        mask_match = re.search(r"netmask\s+(0x[0-9a-f]+)", r.stdout)
        if mask_match:
            hex_mask = mask_match.group(1)
            # 0xffffff00 -> 255.255.255.0
            mask_int = int(hex_mask, 16)
            info["netmask"] = f"{(mask_int >> 24) & 0xff}.{(mask_int >> 16) & 0xff}.{(mask_int >> 8) & 0xff}.{mask_int & 0xff}"
        else:
            info["netmask"] = "N/A"
    except Exception:
        info["netmask"] = "N/A"

    # 网关
    try:
        r = subprocess.run(["route", "-n", "get", "default"],
                           capture_output=True, text=True, timeout=5)
        gw_match = re.search(r"gateway:\s+([\d.]+)", r.stdout)
        info["gateway"] = gw_match.group(1) if gw_match else "N/A"
    except Exception:
        info["gateway"] = "N/A"

    # DNS
    try:
        r = subprocess.run(["scutil", "--dns"],
                           capture_output=True, text=True, timeout=5)
        dns_list = re.findall(r"nameserver\[0\]\s*:\s*([\d.]+)", r.stdout)
        info["dns"] = list(set(dns_list))[:3]
    except Exception:
        info["dns"] = []

    # SSID
    try:
        r = subprocess.run(["networksetup", "-getairportnetwork", interface],
                           capture_output=True, text=True, timeout=5)
        ssid = r.stdout.strip().replace("Current Wi-Fi Network: ", "")
        info["ssid"] = ssid if "not associated" not in ssid.lower() else "(未连接)"
    except Exception:
        info["ssid"] = "N/A"

    return info


# ============================================================
# ARP 局域网设备扫描
# ============================================================
def scan_lan_devices(gateway="192.168.1.1", subnet="192.168.1"):
    """
    通过 ARP 表扫描局域网内的活跃设备
    先用 ping 激活 ARP 缓存，再读取 ARP 表
    """
    print("[*] 扫描局域网设备（ping + ARP）...")

    # 从网关推断子网
    parts = gateway.split(".")
    if len(parts) == 4:
        subnet = ".".join(parts[:3])

    # 快速 ping 扫描（激活 ARP）
    # 使用并行 ping，超时1秒
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        subprocess.Popen(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    # 等待 ping 完成
    time.sleep(3)

    # 读取 ARP 表
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        devices = []
        for line in r.stdout.strip().splitlines():
            # 格式: hostname (IP) at MAC on interface
            match = re.match(
                r"(\S+)\s+\(([\d.]+)\)\s+at\s+([\w:]+)\s+on\s+(\S+)",
                line
            )
            if match:
                hostname, ip, mac, iface = match.groups()
                if mac != "(incomplete)" and ip.startswith(subnet):
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname if hostname != "?" else "",
                        "interface": iface,
                    })
        return devices
    except Exception as e:
        print(f"[!] ARP 扫描失败: {e}")
        return []


# ============================================================
# 路由器识别（HTTP Banner）
# ============================================================
def identify_router(gateway):
    """通过 HTTP 请求尝试识别路由器型号"""
    print(f"[*] 探测路由器 ({gateway})...")
    info = {"ip": gateway, "model": "未知", "server": "N/A"}

    for port in [80, 8080, 443]:
        try:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{gateway}:{port}/"
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "Mozilla/5.0")

            resp = urllib.request.urlopen(req, timeout=3)
            headers = dict(resp.headers)
            body = resp.read(4096).decode("utf-8", errors="ignore")

            # 从 Server 头获取信息
            server = headers.get("Server", "")
            if server:
                info["server"] = server

            # 从页面 title 获取型号
            title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
            if title_match:
                info["title"] = title_match.group(1).strip()

            # 常见路由器品牌关键词识别
            content = (server + " " + body).lower()
            brands = {
                "tp-link": "TP-Link", "tplink": "TP-Link",
                "tenda": "Tenda (腾达)", "mercury": "Mercury (水星)",
                "fast": "FAST (迅捷)", "huawei": "Huawei (华为)",
                "xiaomi": "Xiaomi (小米)", "miwifi": "Xiaomi (小米)",
                "netgear": "Netgear", "asus": "ASUS (华硕)",
                "d-link": "D-Link", "zte": "ZTE (中兴)",
                "ruijie": "Ruijie (锐捷)", "h3c": "H3C",
            }
            for keyword, brand in brands.items():
                if keyword in content:
                    info["model"] = brand
                    break

            info["port"] = port
            break

        except Exception:
            continue

    return info


# ============================================================
# 简易网络测速
# ============================================================
def speed_test():
    """通过下载测试文件来估算网络速度"""
    print("[*] 测速中...")

    # 使用多个测速源
    test_urls = [
        ("http://speedtest.tele2.net/1MB.zip", 1),
        ("http://proof.ovh.net/files/1Mb.dat", 1),
    ]

    for url, size_mb in test_urls:
        try:
            t0 = time.time()
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urllib.request.urlopen(req, timeout=10)
            data = resp.read()
            elapsed = time.time() - t0

            actual_mb = len(data) / (1024 * 1024)
            speed_mbps = actual_mb * 8 / elapsed

            return {
                "download_mbps": round(speed_mbps, 2),
                "downloaded_mb": round(actual_mb, 2),
                "elapsed_sec": round(elapsed, 2),
                "source": url,
            }
        except Exception:
            continue

    return {"download_mbps": 0, "error": "测速失败"}


# ============================================================
# 端口扫描（常见端口快速扫描）
# ============================================================
def quick_port_scan(target_ip, ports=None):
    """对目标 IP 进行常见端口快速扫描"""
    if ports is None:
        ports = [21, 22, 23, 53, 80, 443, 445, 3389, 8080, 8443]

    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
                open_ports.append({"port": port, "service": service})
            sock.close()
        except Exception:
            pass
    return open_ports


# ============================================================
# 综合网络分析报告
# ============================================================
def full_analysis(interface="en0"):
    """生成完整的网络分析报告"""
    print("=" * 55)
    print("  网络分析报告")
    print("=" * 55)

    # 基本信息
    print("\n[1] 网络连接信息")
    info = get_network_info(interface)
    print(f"    SSID:     {info.get('ssid', 'N/A')}")
    print(f"    IP:       {info.get('ip', 'N/A')}")
    print(f"    网关:     {info.get('gateway', 'N/A')}")
    print(f"    子网掩码: {info.get('netmask', 'N/A')}")
    print(f"    DNS:      {', '.join(info.get('dns', []))}")

    gateway = info.get("gateway", "")
    if not gateway or gateway == "N/A":
        print("\n[!] 未检测到网关，网络可能未连接")
        return info

    # 路由器识别
    print("\n[2] 路由器信息")
    router = identify_router(gateway)
    print(f"    品牌/型号: {router.get('model', '未知')}")
    print(f"    Server:    {router.get('server', 'N/A')}")
    if "title" in router:
        print(f"    页面标题:  {router['title']}")
    if "port" in router:
        print(f"    管理端口:  {router['port']}")

    # 路由器端口扫描
    print(f"\n[3] 网关端口扫描 ({gateway})")
    gw_ports = quick_port_scan(gateway)
    if gw_ports:
        for p in gw_ports:
            print(f"    端口 {p['port']:>5} ({p['service']}) - 开放")
    else:
        print("    无常见开放端口")

    # 局域网设备
    print("\n[4] 局域网设备")
    devices = scan_lan_devices(gateway)
    if devices:
        print(f"    发现 {len(devices)} 个设备:")
        for d in sorted(devices, key=lambda x: [int(p) for p in x["ip"].split(".")]):
            hostname = f" ({d['hostname']})" if d["hostname"] else ""
            print(f"    {d['ip']:<16} {d['mac']}{hostname}")
    else:
        print("    未发现其他设备")

    # 测速
    print("\n[5] 网络测速")
    speed = speed_test()
    if speed.get("download_mbps", 0) > 0:
        print(f"    下载速度: {speed['download_mbps']} Mbps")
        print(f"    下载量:   {speed['downloaded_mb']} MB / {speed['elapsed_sec']} s")
    else:
        print(f"    {speed.get('error', '测速失败')}")

    # 保存报告
    report = {
        "network_info": info,
        "router": router,
        "gateway_ports": gw_ports,
        "devices": devices,
        "speed": speed,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    report_path = PROJECT_DIR / "captures" / "network_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n[+] 报告已保存: {report_path}")

    return report


# ============================================================
# 入口
# ============================================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description="网络分析器")
    parser.add_argument("-i", "--interface", default="en0", help="网络接口")
    parser.add_argument("--speed-only", action="store_true", help="仅测速")
    parser.add_argument("--devices-only", action="store_true", help="仅扫描设备")
    args = parser.parse_args()

    if args.speed_only:
        result = speed_test()
        print(f"下载速度: {result.get('download_mbps', 0)} Mbps")
    elif args.devices_only:
        info = get_network_info(args.interface)
        gw = info.get("gateway", "192.168.1.1")
        devices = scan_lan_devices(gw)
        for d in devices:
            print(f"{d['ip']:<16} {d['mac']}  {d.get('hostname', '')}")
    else:
        full_analysis(args.interface)


if __name__ == "__main__":
    main()
