#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
位置权限修复工具
功能：请求 macOS 位置服务权限，解决 CoreWLAN 扫描 SSID/BSSID 显示为 None 的问题
原因：macOS 13+ 将 WiFi 网络标识视为位置数据，需要授权后才能读取
"""

import subprocess
import sys
import time


def request_location_permission():
    """通过 CoreLocation 请求位置权限"""
    try:
        import objc
        from Foundation import NSObject, NSRunLoop, NSDate
        import CoreLocation
    except ImportError:
        print("[!] 缺少依赖: pip3 install pyobjc-framework-CoreLocation")
        return False

    class LocationDelegate(NSObject):
        def init(self):
            self = objc.super(LocationDelegate, self).init()
            if self is None:
                return None
            self.authorized = False
            self.done = False
            return self

        def locationManagerDidChangeAuthorization_(self, manager):
            status = manager.authorizationStatus()
            status_names = {
                0: "未确定", 1: "受限", 2: "拒绝",
                3: "已授权（始终）", 4: "已授权（使用时）",
            }
            name = status_names.get(status, f"未知({status})")
            print(f"[*] 位置权限状态: {name}")
            if status in (3, 4):
                self.authorized = True
            self.done = True

    manager = CoreLocation.CLLocationManager.alloc().init()
    delegate = LocationDelegate.alloc().init()
    manager.setDelegate_(delegate)

    print("[*] 正在请求位置服务权限...")
    print("[*] 如果弹出系统对话框，请点击「允许」")
    print()

    manager.requestWhenInUseAuthorization()

    timeout = 30
    start = time.time()
    while not delegate.done and (time.time() - start) < timeout:
        NSRunLoop.currentRunLoop().runUntilDate_(
            NSDate.dateWithTimeIntervalSinceNow_(0.5)
        )

    if delegate.authorized:
        print()
        print(chr(9989) + " 位置权限已授权！WiFi 扫描现在可以获取 SSID 和 BSSID")
        return True
    elif delegate.done:
        print()
        print("[!] 位置权限被拒绝")
        print("    请手动开启: 系统设置 -> 隐私与安全 -> 位置服务 -> 勾选 Python/终端")
        return False
    else:
        print()
        print("[!] 等待超时")
        print("    请手动开启: 系统设置 -> 隐私与安全 -> 位置服务")
        return False


def check_permission():
    """检查当前位置权限状态"""
    try:
        import CoreLocation
        manager = CoreLocation.CLLocationManager.alloc().init()
        status = manager.authorizationStatus()
        enabled = CoreLocation.CLLocationManager.locationServicesEnabled()

        print("[*] 位置服务总开关: " + ("开启" if enabled else "关闭"))
        status_names = {
            0: "未确定", 1: "受限", 2: "拒绝",
            3: "已授权(始终)", 4: "已授权(使用时)"
        }
        print("[*] 应用授权状态: " + status_names.get(status, f"未知({status})"))
        return status in (3, 4)
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


def main():
    print("=" * 50)
    print("  macOS 位置权限修复工具")
    print("  解决 WiFi 扫描 SSID 显示为空的问题")
    print("=" * 50)
    print()

    authorized = check_permission()
    print()

    if authorized:
        print("[+] 位置权限已就绪，WiFi 扫描应能正常获取 SSID")
        print()
        print("[*] 验证扫描...")
        try:
            import CoreWLAN
            client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
            iface = client.interface()
            nets, err = iface.scanForNetworksWithName_error_(None, None)
            if nets:
                net = list(nets)[0]
                ssid = net.ssid()
                if ssid:
                    print(f"[+] 验证通过: 可以获取 SSID (示例: {ssid})")
                else:
                    print("[!] SSID 仍为空，可能需要重启终端后重试")
        except Exception as e:
            print(f"[!] 验证出错: {e}")
        return

    print("[*] 位置权限未授权，尝试修复...")
    print()
    print("  [1] 自动请求权限（推荐）")
    print("  [2] 打开系统设置手动授权")
    print()

    try:
        choice = input("选择 (1/2): ").strip()
    except EOFError:
        choice = "1"

    if choice == "2":
        open_settings()
    else:
        try:
            import CoreLocation
        except ImportError:
            print("[*] 安装 pyobjc-framework-CoreLocation...")
            subprocess.run([
                sys.executable, "-m", "pip", "install",
                "pyobjc-framework-CoreLocation", "-q"
            ])
        request_location_permission()


if __name__ == "__main__":
    main()
