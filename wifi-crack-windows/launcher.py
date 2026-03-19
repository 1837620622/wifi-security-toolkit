#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi Cracker v3.0 Windows - 启动器
交互式菜单界面 + 自动环境检测 + 一键安装依赖
"""

import os
import sys
import subprocess
import ctypes
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def print_banner():
    admin_tag = " [管理员]" if is_admin() else ""
    print(f"""
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║     WiFi Cracker v3.0 - Windows{admin_tag:<14s}         ║
  ║     全球密码库 + 握手包捕获 + GPU离线破解                ║
  ║                                                          ║
  ╠══════════════════════════════════════════════════════════╣
  ║                                                          ║
  ║   [1]  扫描附近WiFi网络                                  ║
  ║   [2]  查看系统已保存的WiFi密码                          ║
  ║   [3]  PMKID/握手包模式（推荐，只断网1次+GPU破解）       ║
  ║   [4]  智能攻击（Phase 0-5 全流程）                      ║
  ║   [5]  hashcat独立破解（已有.22000文件）                  ║
  ║                                                          ║
  ║   [6]  环境检测（检查依赖是否就绪）                      ║
  ║   [7]  安装依赖（自动安装Python库）                      ║
  ║                                                          ║
  ║   [0]  退出                                              ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝
""")


def check_python_deps():
    """检查Python依赖"""
    deps = {
        'pywifi': False,
        'scapy': False,
        'requests': False,
        'comtypes': False,
    }
    for pkg in deps:
        try:
            __import__(pkg)
            deps[pkg] = True
        except ImportError:
            pass
    return deps


def check_environment():
    """环境检测"""
    print("\n  ══ 环境检测 ══\n")

    # Python
    print(f"  Python:     {sys.version.split()[0]}")
    print(f"  管理员:     {'✓ 是' if is_admin() else '✗ 否'}")

    # Python依赖
    deps = check_python_deps()
    print(f"\n  Python依赖:")
    all_ok = True
    for pkg, ok in deps.items():
        status = "✓ 已安装" if ok else "✗ 未安装"
        print(f"    {pkg:15s} {status}")
        if not ok:
            all_ok = False

    # hashcat
    hashcat_path = None
    for item in os.listdir(SCRIPT_DIR):
        if item.lower().startswith("hashcat") and os.path.isdir(os.path.join(SCRIPT_DIR, item)):
            candidate = os.path.join(SCRIPT_DIR, item, "hashcat.exe")
            if os.path.exists(candidate):
                hashcat_path = candidate
    print(f"\n  hashcat:    {'✓ ' + hashcat_path if hashcat_path else '✗ 未找到'}")

    # GPU
    try:
        r = subprocess.run('nvidia-smi --query-gpu=name --format=csv,noheader',
                         shell=True, capture_output=True, text=True, timeout=5)
        gpu = r.stdout.strip() if r.returncode == 0 else "未检测到NVIDIA GPU"
    except:
        gpu = "未检测到"
    print(f"  GPU:        {gpu}")

    # WiFi
    try:
        r = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                         capture_output=True, text=True, timeout=5,
                         encoding='utf-8', errors='replace')
        wifi_name = ""
        for line in r.stdout.split('\n'):
            if ('说明' in line or 'Description' in line) and ':' in line:
                wifi_name = line.split(':', 1)[-1].strip()
                break
        print(f"  WiFi网卡:   {wifi_name or '未检测到'}")
    except:
        print(f"  WiFi网卡:   未检测到")

    # 字典
    dict_exists = os.path.exists(os.path.join(SCRIPT_DIR, "wpa-sec-cracked.txt"))
    print(f"  wpa-sec字典: {'✓ 已有' if dict_exists else '✗ 未找到'}")

    # captures
    cap_dir = os.path.join(SCRIPT_DIR, "captures")
    hash_files = []
    if os.path.exists(cap_dir):
        hash_files = [f for f in os.listdir(cap_dir) if f.endswith('.22000')]
    print(f"  哈希文件:   {len(hash_files)}个 {hash_files if hash_files else ''}")

    print()
    if all_ok:
        print("  ✓ 所有依赖已就绪，可以使用全部功能")
    else:
        missing = [k for k, v in deps.items() if not v]
        print(f"  ✗ 缺少依赖: {', '.join(missing)}")
        print(f"    输入 7 自动安装")

    input("\n  按回车返回菜单...")


def install_deps():
    """安装Python依赖"""
    print("\n  ══ 安装依赖 ══\n")
    deps = check_python_deps()
    missing = [k for k, v in deps.items() if not v]

    if not missing:
        print("  ✓ 所有依赖已安装，无需操作")
        input("\n  按回车返回菜单...")
        return

    print(f"  需要安装: {', '.join(missing)}")
    print(f"  执行: pip install {' '.join(missing)}\n")

    subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing)

    # 验证
    print("\n  验证安装...")
    deps2 = check_python_deps()
    for pkg, ok in deps2.items():
        if pkg in missing:
            print(f"    {pkg}: {'✓ 成功' if ok else '✗ 失败'}")

    input("\n  按回车返回菜单...")


def run_scan():
    """扫描WiFi"""
    subprocess.run([sys.executable, 'wifi_crack.py', '--scan'])
    input("\n  按回车返回菜单...")


def run_show_passwords():
    """显示已保存密码"""
    if not is_admin():
        print("\n  [!] 查看已保存密码需要管理员权限")
        print("  [!] 正在请求UAC提权...")
        script = os.path.join(SCRIPT_DIR, "wifi_crack.py")
        params = f'"{script}" --show-passwords'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, SCRIPT_DIR, 1)
        time.sleep(1)
        return
    subprocess.run([sys.executable, 'wifi_crack.py', '--show-passwords'])
    input("\n  按回车返回菜单...")


def run_pmkid():
    """PMKID/握手包模式"""
    target = input("  输入目标SSID（留空则交互选择）: ").strip()
    cmd = [sys.executable, 'wifi_crack.py', '--pmkid']
    if target:
        cmd.extend(['-t', target])

    if not is_admin():
        # 自动提权
        script = os.path.join(SCRIPT_DIR, "wifi_crack.py")
        params = f'"{script}" --pmkid'
        if target:
            params += f' -t "{target}"'
        params += ' & pause'
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd",
            f'/k cd /d "{SCRIPT_DIR}" && {sys.executable} {params}',
            SCRIPT_DIR, 1
        )
        print("  [*] 已在管理员窗口中启动，请查看新弹出的窗口")
        input("\n  按回车返回菜单...")
        return

    subprocess.run(cmd)
    input("\n  按回车返回菜单...")


def run_smart_attack():
    """智能攻击"""
    target = input("  输入目标SSID（留空则交互选择）: ").strip()
    cmd = [sys.executable, 'wifi_crack.py']
    if target:
        cmd.extend(['-t', target])
    subprocess.run(cmd)
    input("\n  按回车返回菜单...")


def run_hashcat_crack():
    """hashcat独立破解"""
    cap_dir = os.path.join(SCRIPT_DIR, "captures")
    hash_files = []
    if os.path.exists(cap_dir):
        hash_files = [f for f in os.listdir(cap_dir) if f.endswith('.22000')]

    if hash_files:
        print(f"\n  发现以下哈希文件:")
        for i, f in enumerate(hash_files):
            size = os.path.getsize(os.path.join(cap_dir, f))
            print(f"    [{i+1}] {f} ({size} bytes)")
        choice = input(f"  选择文件编号（1-{len(hash_files)}）或输入路径: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(hash_files):
                hash_path = os.path.join(cap_dir, hash_files[idx])
            else:
                hash_path = choice
        except:
            hash_path = choice
    else:
        hash_path = input("  输入.22000哈希文件路径: ").strip()

    if not hash_path or not os.path.exists(hash_path):
        print(f"  [!] 文件不存在: {hash_path}")
        input("\n  按回车返回菜单...")
        return

    subprocess.run([sys.executable, 'wifi_crack.py', '--hashcat', '--hash', hash_path])
    input("\n  按回车返回菜单...")


def main():
    # 首次运行检查依赖
    deps = check_python_deps()
    missing = [k for k, v in deps.items() if not v]
    if missing:
        print(f"\n  [!] 缺少Python依赖: {', '.join(missing)}")
        ans = input("  是否自动安装？(Y/n): ").strip().lower()
        if ans != 'n':
            subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing)
            print("  安装完成，启动中...\n")
            time.sleep(1)

    while True:
        clear()
        print_banner()
        choice = input("  请选择: ").strip()

        if choice == '0':
            print("\n  再见！")
            break
        elif choice == '1':
            run_scan()
        elif choice == '2':
            run_show_passwords()
        elif choice == '3':
            run_pmkid()
        elif choice == '4':
            run_smart_attack()
        elif choice == '5':
            run_hashcat_crack()
        elif choice == '6':
            check_environment()
        elif choice == '7':
            install_deps()
        else:
            print("  [!] 无效选择")
            time.sleep(1)


if __name__ == '__main__':
    main()
