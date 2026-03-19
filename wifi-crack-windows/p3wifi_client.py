#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p3wifi 全球WiFi密码库客户端
基于 3wifi.dev 开放API，数据库包含全球数千万条WiFi密码记录
支持 BSSID/ESSID 查询，无需认证
"""

import requests
import time
import gzip
import os
from typing import List, Optional, Tuple
from dataclasses import dataclass


# ============================================================
# API配置
# ============================================================
API_BASE_URL = "https://3wifi.dev/api/apiquery"
API_TIMEOUT = 15
USER_AGENT = "WiFiCracker/3.0-Windows (SecurityAudit)"

# wpa-sec 字典下载地址
WPA_SEC_URL = "https://wpa-sec.stanev.org/dict/cracked.txt.gz"
WPA_SEC_TIMEOUT = 60


@dataclass
class WiFiRecord:
    """单条WiFi密码记录"""
    bssid: str = ""
    essid: str = ""
    password: str = ""
    wps_pin: str = ""
    source: str = ""


def query_by_bssid(bssid: str) -> Tuple[Optional[str], Optional[str]]:
    """
    通过BSSID查询密码
    返回: (密码, 错误信息)  密码为None表示未找到
    """
    if not bssid:
        return None, "BSSID为空"

    # 规范化BSSID格式（小写，冒号分隔）
    bssid = bssid.strip().upper().replace('-', ':')

    try:
        params = {
            'bssid': bssid,
        }
        headers = {
            'User-Agent': USER_AGENT,
        }

        resp = requests.get(API_BASE_URL, params=params, headers=headers,
                          timeout=API_TIMEOUT, verify=True)

        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"

        data = resp.json()

        if not data.get('result'):
            error = data.get('error', '未知错误')
            return None, f"API返回失败: {error}"

        # 解析结果
        records = data.get('data', {})
        for key, record_list in records.items():
            if isinstance(record_list, list):
                for record in record_list:
                    pwd = record.get('key', '').strip()
                    if pwd and len(pwd) >= 8:
                        return pwd, None

        return None, None  # 未收录

    except requests.exceptions.Timeout:
        return None, "请求超时"
    except requests.exceptions.ConnectionError:
        return None, "网络连接失败"
    except Exception as e:
        return None, str(e)


def query_full(bssid: str, essid: str = "") -> List[WiFiRecord]:
    """
    完整查询，返回所有匹配的历史记录（可能有多个历史密码）
    """
    results = []
    if not bssid:
        return results

    bssid = bssid.strip().upper().replace('-', ':')

    try:
        params = {'bssid': bssid}
        if essid:
            params['essid'] = essid

        headers = {'User-Agent': USER_AGENT}
        resp = requests.get(API_BASE_URL, params=params, headers=headers,
                          timeout=API_TIMEOUT, verify=True)

        if resp.status_code != 200:
            return results

        data = resp.json()
        if not data.get('result'):
            return results

        for key, record_list in data.get('data', {}).items():
            if isinstance(record_list, list):
                for record in record_list:
                    pwd = record.get('key', '').strip()
                    if pwd and len(pwd) >= 8:
                        results.append(WiFiRecord(
                            bssid=record.get('bssid', bssid),
                            essid=record.get('essid', essid),
                            password=pwd,
                            wps_pin=record.get('wps', ''),
                            source=f"p3wifi-{record.get('id', 'unknown')}",
                        ))

    except Exception:
        pass

    return results


def download_wpa_sec_dict(output_path: str, max_size_mb: int = 10) -> Tuple[bool, str]:
    """
    下载 wpa-sec 全球社区破解的WiFi密码字典
    返回: (是否成功, 消息)
    """
    try:
        if os.path.exists(output_path):
            size_mb = os.path.getsize(output_path) / (1024 * 1024)
            if size_mb > 1:
                return True, f"字典已存在 ({size_mb:.1f}MB)"

        headers = {'User-Agent': USER_AGENT}
        resp = requests.get(WPA_SEC_URL, headers=headers, timeout=WPA_SEC_TIMEOUT,
                          stream=True, verify=True)

        if resp.status_code != 200:
            return False, f"下载失败 HTTP {resp.status_code}"

        # 流式下载并解压
        total = 0
        max_bytes = max_size_mb * 1024 * 1024

        with open(output_path, 'wb') as f:
            if WPA_SEC_URL.endswith('.gz'):
                # gzip压缩的，需要解压
                import io
                content = resp.content
                try:
                    decompressed = gzip.decompress(content)
                    f.write(decompressed)
                    total = len(decompressed)
                except:
                    f.write(content)
                    total = len(content)
            else:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        break

        size_mb = total / (1024 * 1024)
        return True, f"下载完成 ({size_mb:.1f}MB)"

    except requests.exceptions.Timeout:
        return False, "下载超时"
    except Exception as e:
        return False, str(e)


def load_wpa_sec_passwords(file_path: str, top_n: int = 0) -> List[str]:
    """
    加载 wpa-sec 字典文件中的密码
    top_n: 取前N条，0=全部
    """
    passwords = []
    try:
        if not os.path.exists(file_path):
            return passwords

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                pwd = line.strip()
                if pwd and len(pwd) >= 8:
                    passwords.append(pwd)
                    if top_n > 0 and len(passwords) >= top_n:
                        break
    except:
        pass

    return passwords
