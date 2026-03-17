#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
位置权限修复工具 v3.0
功能：修复 macOS 位置服务权限，解决 CoreWLAN 扫描 SSID/BSSID 显示为 None 的问题
原因：macOS 13+ 将 WiFi 网络标识视为位置数据，需要授权后才能读取
修复方式：通过 sudo + Touch ID 直接修改 locationd 授权配置
"""

import os
import subprocess
import sys
import time


# ============================================================
# 核心修复：通过 sudo + Touch ID 直接修改 locationd 授权
# ============================================================
def fix_locationd_authorization():
    """
    通过 sudo 直接修改 /var/db/locationd/clients.plist
    将当前 Python 可执行文件添加到位置服务授权列表
    支持 Touch ID 认证（需配置 pam_tid.so）
    """
    python_exe = sys.executable
    # 获取可能的 Python 可执行文件路径
    targets = [python_exe]
    # 添加带版本号的路径
    import re
    base = os.path.dirname(python_exe)
    name = os.path.basename(python_exe)
    if not re.search(r'\d', name):
        # python3 -> 也添加 python3.12 等
        for f in os.listdir(base):
            if f.startswith('python3.') and os.path.isfile(os.path.join(base, f)):
                targets.append(os.path.join(base, f))
    elif re.search(r'python3\.\d+', name):
        # python3.12 -> 也添加 python3
        generic = os.path.join(base, 'python3')
        if os.path.isfile(generic) and generic not in targets:
            targets.append(generic)

    targets = list(set(targets))

    # 构建 sudo 执行的 Python 脚本
    fix_script = f'''
import plistlib, uuid, subprocess, os

plist_path = "/var/db/locationd/clients.plist"
with open(plist_path, "rb") as f:
    d = plistlib.load(f)

targets = {targets!r}
added = []

for exe in targets:
    if not os.path.isfile(exe):
        continue
    found = False
    for k, v in d.items():
        if isinstance(v, dict) and v.get("Executable") == exe:
            if not v.get("Authorized"):
                v["Authorized"] = True
                v["Registered"] = True
                added.append("\u66f4\u65b0: " + exe)
            else:
                added.append("\u5df2\u6388\u6743: " + exe)
            found = True
            break
    if not found:
        key = uuid.uuid4().hex[:8].upper() + ":e" + exe + ":"
        d[key] = {{
            "Authorized": True,
            "Executable": exe,
            "Registered": True,
        }}
        added.append("\u65b0\u589e: " + exe)

with open(plist_path, "wb") as f:
    plistlib.dump(d, f, fmt=plistlib.FMT_BINARY)

for a in added:
    print(a)

subprocess.run(["killall", "locationd"], capture_output=True)
print("LOCATIOND_RESTARTED")
'''

    print("[*] 正在通过 sudo 修改 locationd 授权配置...")
    print("[*] 请用 Touch ID 或输入密码确认")
    print()

    r = subprocess.run(
        ["sudo", sys.executable, "-c", fix_script],
        capture_output=True, text=True, timeout=60
    )

    if r.returncode != 0:
        print(f"[!] 执行失败: {r.stderr.strip()}")
        return False

    output = r.stdout.strip()
    for line in output.split('\n'):
        if line and line != 'LOCATIOND_RESTARTED':
            print(f"[+] {line}")

    if 'LOCATIOND_RESTARTED' in output:
        print("[+] locationd 已重启")
        # 等待 locationd 重启完成
        time.sleep(1)
        return True

    return False


def diagnose_environment():
    """诊断运行环境"""
    print("[诊断] 运行环境:")
    print(f"  Python:  {sys.executable}")
    print(f"  版本:    {sys.version.split()[0]}")
    try:
        r = subprocess.run(["sw_vers", "-productVersion"],
                           capture_output=True, text=True, timeout=5)
        print(f"  macOS:   {r.stdout.strip()}")
    except Exception:
        pass
    term = os.environ.get("TERM_PROGRAM", "未知")
    print(f"  终端:    {term}")
    # Touch ID 支持检测
    tid = False
    try:
        with open("/etc/pam.d/sudo_local") as f:
            content = f.read()
            # 检查是否有未注释的 pam_tid.so 行
            for line in content.splitlines():
                stripped = line.strip()
                if "pam_tid.so" in stripped and not stripped.startswith("#"):
                    tid = True
                    break
    except Exception:
        pass
    print(f"  Touch ID sudo: {'\u2705 已启用' if tid else '\u274c 未启用'}")
    print()


def check_permission():
    """检查当前位置权限状态"""
    try:
        import CoreLocation
        manager = CoreLocation.CLLocationManager.alloc().init()
        status = manager.authorizationStatus()
        enabled = CoreLocation.CLLocationManager.locationServicesEnabled()

        print("[*] 位置服务总开关: " + ("开启" if enabled else "关闭"))
        status_names = {
            0: "未确定(从未请求)", 1: "受限", 2: "拒绝",
            3: "已授权(始终)", 4: "已授权(使用时)"
        }
        print("[*] 应用授权状态: " + status_names.get(status, f"未知({status})"))

        if not enabled:
            print()
            print("[!] 位置服务总开关未开启！")
            print("    请前往: 系统设置 -> 隐私与安全 -> 位置服务 -> 开启总开关")

        return status in (3, 4) and enabled
    except ImportError:
        print("[!] pip3 install pyobjc-framework-CoreLocation")
        return False


def open_settings():
    """打开系统隐私设置页面"""
    subprocess.run([
        "open",
        "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
    ])
    print("[*] 已打开系统设置 -> 位置服务")
    print("    请在列表中找到 Python 或终端程序，勾选允许")


def verify_wifi_scan():
    """验证WiFi扫描是否能获取SSID"""
    print("[*] 验证WiFi扫描...")
    try:
        import CoreWLAN
        client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
        iface = client.interface()
        if not iface:
            print("[!] 未找到WiFi接口")
            return False

        nets, err = iface.scanForNetworksWithName_error_(None, None)
        if not nets:
            print("[!] 扫描未发现网络")
            return False

        # 统计SSID获取情况
        total = len(nets)
        with_ssid = sum(1 for n in nets if n.ssid())
        with_bssid = sum(1 for n in nets if n.bssid())

        print(f"[*] 扫描到 {total} 个网络")
        print(f"    SSID可见:  {with_ssid}/{total}")
        print(f"    BSSID可见: {with_bssid}/{total}")

        if with_ssid > 0:
            # 显示前3个SSID作为示例
            examples = [n.ssid() for n in nets if n.ssid()][:3]
            print(f"    示例SSID: {', '.join(examples)}")
            print()
            print(chr(9989) + " WiFi扫描正常！SSID和BSSID可以正确获取")
            return True
        else:
            print()
            print("[!] 所有SSID仍为空")
            print("    可能原因:")
            print("    1. 权限刚授权，需要重启终端/IDE后生效")
            print("    2. 权限授予了错误的Python版本")
            print(f"       当前Python: {sys.executable}")
            print("    3. 位置服务总开关未开启")
            return False
    except Exception as e:
        print(f"[!] 验证出错: {e}")
        return False


def main():
    print("=" * 50)
    print("  macOS 位置权限修复工具 v3.0")
    print("  解决 WiFi 扫描 SSID 显示为空的问题")
    print("  支持 Touch ID 认证")
    print("=" * 50)
    print()

    # 环境诊断
    diagnose_environment()

    # 检查权限
    authorized = check_permission()
    print()

    if authorized:
        print("[+] 位置权限已就绪")
        print()
        verify_wifi_scan()
        return

    print("[*] 位置权限未授权，尝试修复...")
    print()
    print("  [1] Touch ID 一键修复（推荐，sudo直接授权）")
    print("  [2] 打开系统设置手动授权")
    print("  [3] 仅验证WiFi扫描")
    print()

    try:
        choice = input("选择 (1/2/3): ").strip()
    except EOFError:
        choice = "1"

    if choice == "2":
        open_settings()
        print()
        print("[*] 授权步骤:")
        print("    1. 在位置服务列表中找到 Python 或当前终端程序")
        print("    2. 勾选允许访问位置")
        print("    3. 关闭设置，重启终端")
    elif choice == "3":
        verify_wifi_scan()
    else:
        # Touch ID 一键修复
        success = fix_locationd_authorization()
        print()
        if success:
            verify_wifi_scan()
        else:
            print("[*] sudo方式失败，尝试打开系统设置...")
            open_settings()


if __name__ == "__main__":
    main()
