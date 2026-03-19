#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows WiFi 扫描/连接模块
双引擎架构：pywifi（主引擎，速度快）+ netsh（备用引擎，兼容性强）
"""

import subprocess
import time
import re
import xml.etree.ElementTree as ET
import tempfile
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from enum import IntEnum


@dataclass
class WiFiNetwork:
    """WiFi网络信息"""
    ssid: str
    bssid: str = ""
    rssi: int = -100       # 信号强度 dBm
    signal: int = 0        # 信号百分比 0-100
    security: str = ""     # 安全类型
    channel: int = 0
    band: str = ""         # 2.4GHz / 5GHz
    radio_type: str = ""   # 802.11ax 等


class ConnectResult:
    """连接结果"""
    def __init__(self, success: bool, password: str = "", ssid: str = "",
                 method: str = "", duration: float = 0, error: str = ""):
        self.success = success
        self.password = password
        self.ssid = ssid
        self.method = method
        self.duration = duration
        self.error = error


class WiFiEngine:
    """WiFi引擎基类"""
    def scan(self) -> List[WiFiNetwork]:
        raise NotImplementedError

    def connect(self, ssid: str, password: str, security: str = "WPA2PSK") -> bool:
        raise NotImplementedError

    def disconnect(self) -> bool:
        raise NotImplementedError

    def current_ssid(self) -> Optional[str]:
        raise NotImplementedError

    def is_available(self) -> bool:
        raise NotImplementedError


# ============================================================
# 引擎1: pywifi（速度快，直接调用Windows Native WiFi API）
# ============================================================
class PyWiFiEngine(WiFiEngine):
    """基于pywifi的WiFi引擎（推荐，速度更快）"""

    def __init__(self):
        self._available = False
        self._iface = None
        self._const = None
        self._Profile = None
        try:
            import pywifi
            from pywifi import const, Profile
            self._const = const
            self._Profile = Profile
            wifi = pywifi.PyWiFi()
            ifaces = wifi.interfaces()
            if ifaces:
                self._iface = ifaces[0]
                self._available = True
        except ImportError:
            pass
        except Exception:
            pass

    def is_available(self) -> bool:
        return self._available

    def get_interface_name(self) -> str:
        if self._iface:
            return self._iface.name()
        return ""

    def scan(self) -> List[WiFiNetwork]:
        if not self._available:
            return []
        try:
            self._iface.scan()
            time.sleep(4)  # 等待扫描完成
            results = self._iface.scan_results()

            # 去重（保留信号最强的）
            best = {}
            for r in results:
                ssid = r.ssid.strip()
                if not ssid:
                    continue
                bssid = getattr(r, 'bssid', '') or ''
                rssi = getattr(r, 'signal', -100)
                if isinstance(rssi, int) and rssi > 0:
                    rssi = rssi - 100  # pywifi有时返回正数

                if ssid not in best or rssi > best[ssid].rssi:
                    # 解析安全类型
                    akm = getattr(r, 'akm', [])
                    security = self._akm_to_str(akm)

                    best[ssid] = WiFiNetwork(
                        ssid=ssid,
                        bssid=bssid,
                        rssi=rssi,
                        signal=max(0, min(100, rssi + 100)),
                        security=security,
                    )

            # 按信号排序
            networks = sorted(best.values(), key=lambda n: n.rssi, reverse=True)
            return networks
        except Exception as e:
            print(f"  [!] pywifi扫描失败: {e}")
            return []

    def _akm_to_str(self, akm) -> str:
        if not akm or not self._const:
            return "Open"
        akm_map = {
            0: "Open",
            1: "WPA",
            2: "WPAPSK",
            3: "WPA2",
            4: "WPA2PSK",
            5: "WPA3",
            6: "WPA3SAE",
        }
        if isinstance(akm, list):
            names = [akm_map.get(a, f"Unknown({a})") for a in akm]
            return "/".join(names) if names else "Open"
        return akm_map.get(akm, "Unknown")

    def connect(self, ssid: str, password: str, security: str = "WPA2PSK") -> bool:
        """尝试连接WiFi，返回是否成功"""
        if not self._available:
            return False
        try:
            self._iface.disconnect()
            time.sleep(0.3)

            profile = self._Profile()
            profile.ssid = ssid
            profile.auth = self._const.AUTH_ALG_OPEN

            # 根据安全类型设置AKM
            sec_upper = security.upper()
            if "WPA3" in sec_upper or "SAE" in sec_upper:
                profile.akm = [self._const.AKM_TYPE_WPA2PSK]  # pywifi不直接支持WPA3，降级
            elif "WPA2" in sec_upper:
                profile.akm = [self._const.AKM_TYPE_WPA2PSK]
            elif "WPA" in sec_upper:
                profile.akm = [self._const.AKM_TYPE_WPAPSK]
            else:
                profile.akm = [self._const.AKM_TYPE_WPA2PSK]

            profile.cipher = self._const.CIPHER_TYPE_CCMP
            profile.key = password

            self._iface.remove_all_network_profiles()
            tmp_profile = self._iface.add_network_profile(profile)
            self._iface.connect(tmp_profile)

            # 等待连接结果（最多3秒）
            for _ in range(15):
                time.sleep(0.2)
                status = self._iface.status()
                if status == self._const.IFACE_CONNECTED:
                    return True
                if status == self._const.IFACE_DISCONNECTED:
                    return False

            # 超时，检查最终状态
            return self._iface.status() == self._const.IFACE_CONNECTED

        except Exception as e:
            return False

    def disconnect(self) -> bool:
        if not self._available:
            return False
        try:
            self._iface.disconnect()
            time.sleep(0.5)
            return True
        except:
            return False

    def current_ssid(self) -> Optional[str]:
        """获取当前连接的SSID"""
        # pywifi没有直接获取当前SSID的API，用netsh获取
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
            )
            for line in result.stdout.split('\n'):
                if 'SSID' in line and 'BSSID' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return ssid
        except:
            pass
        return None

    def status(self) -> int:
        if not self._available:
            return -1
        try:
            return self._iface.status()
        except:
            return -1


# ============================================================
# 引擎2: netsh命令行（兼容性最强，不需要额外库）
# ============================================================
class NetshEngine(WiFiEngine):
    """基于netsh命令行的WiFi引擎（备用，兼容性强）"""

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
            )
            return result.returncode == 0
        except:
            return False

    def scan(self) -> List[WiFiNetwork]:
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=15, encoding='utf-8', errors='replace'
            )
            if result.returncode != 0:
                return []

            networks = []
            current = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue

                if line.startswith('SSID') and 'BSSID' not in line:
                    # 新的SSID
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            current = {'ssid': ssid}

                elif 'BSSID' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        current['bssid'] = parts[1].strip()

                elif ('身份验证' in line or 'Authentication' in line.lower()):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        current['security'] = parts[1].strip()

                elif ('信号' in line or 'Signal' in line) and '%' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        try:
                            signal = int(parts[1].strip().replace('%', ''))
                            current['signal'] = signal
                            current['rssi'] = signal - 100  # 粗略转换
                        except:
                            pass

                elif ('频道' in line or 'Channel' in line) and 'GHz' not in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        try:
                            current['channel'] = int(parts[1].strip())
                        except:
                            pass

                elif ('波段' in line or 'Band' in line):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        current['band'] = parts[1].strip()

                elif ('无线电类型' in line or 'Radio type' in line.lower()):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        current['radio_type'] = parts[1].strip()

                # 当收集到bssid时保存（一个SSID可能有多个BSSID）
                if 'ssid' in current and 'bssid' in current and current.get('signal'):
                    networks.append(WiFiNetwork(
                        ssid=current['ssid'],
                        bssid=current.get('bssid', ''),
                        rssi=current.get('rssi', -100),
                        signal=current.get('signal', 0),
                        security=current.get('security', ''),
                        channel=current.get('channel', 0),
                        band=current.get('band', ''),
                        radio_type=current.get('radio_type', ''),
                    ))
                    # 重置bssid相关字段但保留ssid和security
                    ssid_backup = current.get('ssid', '')
                    security_backup = current.get('security', '')
                    current = {'ssid': ssid_backup, 'security': security_backup}

            # 去重（保留信号最强的）
            best = {}
            for n in networks:
                if n.ssid not in best or n.rssi > best[n.ssid].rssi:
                    best[n.ssid] = n
            return sorted(best.values(), key=lambda n: n.rssi, reverse=True)

        except Exception as e:
            print(f"  [!] netsh扫描失败: {e}")
            return []

    def connect(self, ssid: str, password: str, security: str = "WPA2PSK") -> bool:
        """通过netsh创建临时profile并连接"""
        xml_path = None
        success = False
        try:
            # 创建WiFi profile XML
            xml_content = self._create_profile_xml(ssid, password, security)

            # 写入临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False,
                                            encoding='utf-8') as f:
                f.write(xml_content)
                xml_path = f.name

            # 添加profile
            result = subprocess.run(
                ['netsh', 'wlan', 'add', 'profile', f'filename={xml_path}'],
                capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
            )
            if result.returncode != 0:
                return False

            # 连接
            result = subprocess.run(
                ['netsh', 'wlan', 'connect', f'name={ssid}', f'ssid={ssid}'],
                capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
            )
            if result.returncode != 0:
                return False

            # 等待连接结果（轮询，最多3秒）
            for _ in range(6):
                time.sleep(0.5)
                current = self.current_ssid()
                if current and current == ssid:
                    success = True
                    return True

            return False

        except Exception:
            return False
        finally:
            # 删除临时XML文件
            if xml_path:
                try:
                    os.unlink(xml_path)
                except:
                    pass
            # 失败时清理profile，成功时保留（后续disconnect会处理）
            if not success:
                try:
                    subprocess.run(
                        ['netsh', 'wlan', 'delete', 'profile', f'name={ssid}'],
                        capture_output=True, text=True, timeout=5,
                        encoding='utf-8', errors='replace'
                    )
                except:
                    pass

    def _create_profile_xml(self, ssid: str, password: str, security: str) -> str:
        """生成WiFi连接所需的XML profile"""
        sec_upper = security.upper()
        if "WPA3" in sec_upper or "SAE" in sec_upper:
            auth = "WPA3SAE"
            encrypt = "AES"
            key_type = "passPhrase"
        elif "WPA2" in sec_upper:
            auth = "WPA2PSK"
            encrypt = "AES"
            key_type = "passPhrase"
        elif "WPA" in sec_upper:
            auth = "WPAPSK"
            encrypt = "TKIP"
            key_type = "passPhrase"
        else:
            auth = "WPA2PSK"
            encrypt = "AES"
            key_type = "passPhrase"

        # 对SSID中的特殊字符做XML转义
        ssid_escaped = ssid.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        ssid_hex = ssid.encode('utf-8').hex()

        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid_escaped}</name>
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
                <authentication>{auth}</authentication>
                <encryption>{encrypt}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>{key_type}</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

    def disconnect(self) -> bool:
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'disconnect'],
                capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
            )
            time.sleep(0.5)
            return result.returncode == 0
        except:
            return False

    def current_ssid(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if ('SSID' in line and 'BSSID' not in line):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return ssid
        except:
            pass
        return None


# ============================================================
# WiFiScanner: 统一扫描/连接接口（自动选择最优引擎）
# ============================================================
class WiFiScanner:
    """WiFi扫描器 - 自动选择最优引擎"""

    def __init__(self, prefer_pywifi: bool = True):
        self.pywifi_engine = PyWiFiEngine()
        self.netsh_engine = NetshEngine()
        self._primary = None
        self._fallback = None

        if prefer_pywifi and self.pywifi_engine.is_available():
            self._primary = self.pywifi_engine
            self._fallback = self.netsh_engine
            self.engine_name = "pywifi"
        elif self.netsh_engine.is_available():
            self._primary = self.netsh_engine
            self._fallback = self.pywifi_engine if self.pywifi_engine.is_available() else None
            self.engine_name = "netsh"
        else:
            self.engine_name = "none"

    def is_available(self) -> bool:
        return self._primary is not None

    def scan(self) -> List[WiFiNetwork]:
        """扫描WiFi（双引擎合并：pywifi触发主动扫描 + netsh获取完整信息）"""
        # 第1步：用pywifi触发主动扫描（刷新系统WiFi缓存）
        if self.pywifi_engine.is_available():
            try:
                self.pywifi_engine._iface.scan()
                time.sleep(5)  # 等待扫描完成
            except:
                pass

        # 第2步：用netsh获取完整结果（BSSID、频道、波段等更全）
        netsh_results = self.netsh_engine.scan()

        # 第3步：用pywifi补充netsh可能遗漏的网络
        if self.pywifi_engine.is_available():
            try:
                pywifi_results = self.pywifi_engine.scan()
                netsh_ssids = {n.ssid for n in netsh_results}
                for n in pywifi_results:
                    if n.ssid not in netsh_ssids:
                        netsh_results.append(n)
            except:
                pass

        if netsh_results:
            # 按信号强度排序
            return sorted(netsh_results, key=lambda n: n.rssi, reverse=True)

        # 全部失败，最后降级
        if self.pywifi_engine.is_available():
            return self.pywifi_engine.scan()
        return []

    def try_connect(self, ssid: str, password: str, security: str = "WPA2PSK") -> bool:
        """尝试连接（优先用pywifi，更快）"""
        if self._primary:
            result = self._primary.connect(ssid, password, security)
            if result:
                return True
        # 主引擎失败，尝试备用
        if self._fallback and self._fallback.is_available():
            return self._fallback.connect(ssid, password, security)
        return False

    def disconnect(self) -> bool:
        if self._primary:
            return self._primary.disconnect()
        return False

    def current_ssid(self) -> Optional[str]:
        # netsh获取当前SSID最可靠
        return self.netsh_engine.current_ssid()

    def reconnect(self, ssid: str) -> bool:
        """恢复到之前的WiFi连接"""
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'connect', f'name={ssid}'],
                capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
            )
            time.sleep(3)
            current = self.current_ssid()
            return current == ssid
        except:
            return False

    def get_saved_passwords(self) -> dict:
        """获取系统已保存的WiFi密码"""
        passwords = {}
        try:
            # 获取所有profile
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
            )
            profiles = []
            for line in result.stdout.split('\n'):
                if '所有用户配置文件' in line or 'All User Profile' in line:
                    name = line.split(':', 1)[-1].strip()
                    if name:
                        profiles.append(name)

            # 获取每个profile的密码
            for profile in profiles:
                try:
                    result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'profile', f'name={profile}', 'key=clear'],
                        capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
                    )
                    for line in result.stdout.split('\n'):
                        if ('关键内容' in line or 'Key Content' in line):
                            pwd = line.split(':', 1)[-1].strip()
                            if pwd:
                                passwords[profile] = pwd
                except:
                    continue
        except:
            pass
        return passwords
