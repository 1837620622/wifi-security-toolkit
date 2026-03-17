#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi密码共享数据库查询器 v1.0
原理：模拟WiFi万能钥匙客户端协议，查询云端共享密码数据库
通过提供SSID+BSSID即可秒级查询已被分享的WiFi密码

数据来源：WiFi万能钥匙用户共享的WiFi密码（约8亿装机量的密码池）
速度：秒级查询，无需任何攻击行为
适配：macOS / Linux / Windows（纯HTTP请求，无需外置网卡）

参考：
  - LockGit/Hacking - attackWiFi.py（Python2原版）
  - 5alt/lianwifi - WiFi万能钥匙macOS API
  - WiFi万能钥匙协议逆向分析
"""

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from pathlib import Path

# ============================================================
# 项目路径
# ============================================================
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
CAPTURES_DIR = PROJECT_DIR / "captures"
CRACKED_FILE = CAPTURES_DIR / "cracked.json"

# ============================================================
# 颜色常量
# ============================================================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ============================================================
# AES加密/解密（兼容无pycryptodome环境）
# ============================================================
_AES_KEY = b"!I50#LSSciCx&q6E"
_AES_IV = b"$t%s%12#2b474pXF"
_SIGN_SALT = "*Lm%qiOHVEedH3%A^uFFsZvFH9T8QAZe"
_API_URL = "http://ap.51y5.net/ap/fa.sec"

try:
    from Crypto.Cipher import AES as _AES
    _HAS_AES = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES as _AES
        _HAS_AES = True
    except ImportError:
        _HAS_AES = False


def _pad(data):
    """PKCS补齐到16字节倍数（用空格填充）"""
    pad_len = 16 - len(data) % 16
    return data + ' ' * pad_len


def _aes_encrypt(plaintext):
    """AES-CBC加密，返回十六进制大写字符串"""
    if not _HAS_AES:
        return None
    cipher = _AES.new(_AES_KEY, _AES.MODE_CBC, _AES_IV)
    padded = _pad(plaintext).encode('utf-8') if isinstance(plaintext, str) else _pad(plaintext)
    encrypted = cipher.encrypt(padded)
    return encrypted.hex().upper()


def _aes_decrypt(hex_str):
    """AES-CBC解密十六进制字符串"""
    if not _HAS_AES:
        return None
    cipher = _AES.new(_AES_KEY, _AES.MODE_CBC, _AES_IV)
    raw = bytes.fromhex(hex_str)
    decrypted = cipher.decrypt(raw)
    return decrypted


def _md5(s):
    """计算MD5哈希"""
    return hashlib.md5(s.encode('utf-8')).hexdigest()


# ============================================================
# WiFi万能钥匙API查询
# ============================================================
def query_wifi_masterkey(ssid, bssid):
    """
    通过WiFi万能钥匙API查询WiFi密码
    参数:
        ssid: WiFi名称
        bssid: WiFi的MAC地址（格式 xx:xx:xx:xx:xx:xx）
    返回:
        密码字符串 或 None
    """
    if not _HAS_AES:
        print(f"    {RED}[!] 缺少pycryptodome库，无法使用万能钥匙查询{RESET}")
        print(f"    安装: pip3 install pycryptodome")
        return None

    # 构造请求JSON（模拟WiFi万能钥匙Android客户端）
    dt = OrderedDict()
    dt['origChanId'] = 'xiaomi'
    dt['appId'] = 'A0008'
    dt['ts'] = str(int(time.time() * 1000))
    dt['netModel'] = 'w'
    dt['chanId'] = 'guanwang'
    dt['imei'] = '357541051318147'
    dt['qid'] = ''
    dt['mac'] = 'e8:92:a4:9b:16:42'
    dt['capSsid'] = ssid
    dt['lang'] = 'cn'
    dt['longi'] = '108.94'
    dt['nbaps'] = ''
    dt['capBssid'] = bssid
    dt['bssid'] = bssid
    dt['mapSP'] = 't'
    dt['userToken'] = ''
    dt['verName'] = '4.1.8'
    dt['ssid'] = ssid
    dt['verCode'] = '3028'
    dt['uhid'] = 'a0000000000000000000000000000001'
    dt['lati'] = '34.26'
    dt['dhid'] = '9374df1b6a3c4072a0271d52cbb2c7b6'

    # JSON序列化 -> URL编码 -> AES加密
    json_str = json.dumps(dt, ensure_ascii=False, separators=(',', ':'))
    encoded = urllib.parse.quote(json_str)
    ed = _aes_encrypt(encoded)
    if not ed:
        return None

    # 构造POST参数
    post_data = {
        'appId': 'A0008',
        'pid': '00300109',
        'ed': ed,
        'st': 'm',
        'et': 'a',
    }

    # 计算签名
    ss = ""
    for key in sorted(post_data):
        ss += post_data[key]
    sign = _md5(ss + _SIGN_SALT)
    post_data['sign'] = sign

    # 发送HTTP请求
    try:
        data = urllib.parse.urlencode(post_data).encode('utf-8')
        req = urllib.request.Request(_API_URL, data=data)
        req.add_header('User-Agent', 'Mozilla/5.0')
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8')
            result = json.loads(content)

            # 解析返回结果
            if 'aps' in result and len(result['aps']) > 0:
                epwd = result['aps'][0].get('pwd', '')
                if epwd:
                    # AES解密密码
                    decrypted = _aes_decrypt(epwd)
                    if decrypted:
                        # 前3字节是密码长度，后续是urlencode的密码
                        try:
                            length = int(decrypted[:3])
                            pwd_encoded = decrypted[3:3 + length].decode('utf-8', errors='ignore')
                            pwd = urllib.parse.unquote(pwd_encoded)
                            return pwd
                        except (ValueError, UnicodeDecodeError):
                            # 尝试直接解码
                            try:
                                pwd = decrypted.rstrip(b'\x00 ').decode('utf-8', errors='ignore')
                                if pwd and len(pwd) >= 8:
                                    return pwd
                            except Exception:
                                pass
            return None
    except Exception as e:
        return None


# ============================================================
# WPS PIN计算器（基于MAC地址的离线计算）
# ============================================================
def compute_wps_pins(bssid):
    """
    根据BSSID/MAC地址计算可能的WPS PIN码
    很多路由器的WPS PIN是根据MAC地址算法生成的
    返回: [(pin, 算法名), ...]
    """
    mac = bssid.upper().replace(':', '').replace('-', '')
    if len(mac) != 12:
        return []

    pins = []
    mac_int = int(mac, 16)
    mac_suffix = int(mac[-6:], 16)

    # 算法1: 基于MAC后6位取模
    pin7 = mac_suffix % 10000000
    checksum = _wps_checksum(pin7)
    pin = f"{pin7:07d}{checksum}"
    pins.append((pin, "MAC后缀取模"))

    # 算法2: 24位MAC后缀
    pin7 = (mac_suffix * 10 + 1) % 10000000
    checksum = _wps_checksum(pin7)
    pin = f"{pin7:07d}{checksum}"
    pins.append((pin, "MAC后缀变体1"))

    # 算法3: 常见静态PIN
    static_pins = [
        ("12345670", "最常见默认PIN"),
        ("00000000", "空PIN"),
        ("01234567", "顺序PIN"),
    ]
    pins.extend(static_pins)

    # 算法4: 基于MAC的TP-Link算法
    # TP-Link: 取MAC后3字节异或后取模
    b4 = int(mac[6:8], 16)
    b5 = int(mac[8:10], 16)
    b6 = int(mac[10:12], 16)
    tp_seed = (b4 * 256 * 256 + b5 * 256 + b6) ^ 0x55AA55
    pin7 = tp_seed % 10000000
    checksum = _wps_checksum(pin7)
    pin = f"{pin7:07d}{checksum}"
    pins.append((pin, "TP-Link算法"))

    # 算法5: 基于MAC的D-Link/Tenda算法
    dl_seed = mac_suffix ^ 0xDECADE
    pin7 = dl_seed % 10000000
    checksum = _wps_checksum(pin7)
    pin = f"{pin7:07d}{checksum}"
    pins.append((pin, "D-Link/Tenda算法"))

    return pins


def _wps_checksum(pin7):
    """计算WPS PIN的第8位校验位"""
    accum = 0
    t = pin7 * 10
    accum += 3 * ((t // 10000000) % 10)
    accum += 1 * ((t // 1000000) % 10)
    accum += 3 * ((t // 100000) % 10)
    accum += 1 * ((t // 10000) % 10)
    accum += 3 * ((t // 1000) % 10)
    accum += 1 * ((t // 100) % 10)
    accum += 3 * ((t // 10) % 10)
    return (10 - (accum % 10)) % 10


# ============================================================
# 加载/保存破解记录
# ============================================================
def load_cracked():
    """加载已破解记录"""
    if CRACKED_FILE.exists():
        try:
            with open(CRACKED_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cracked(ssid, password, source="db_query"):
    """保存破解结果"""
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    data = load_cracked()
    data[ssid] = {
        "password": password,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
    }
    with open(CRACKED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ============================================================
# 获取扫描目标（含BSSID）
# ============================================================
def get_scan_targets():
    """
    扫描周围WiFi获取SSID+BSSID列表
    macOS使用airport命令获取BSSID信息
    """
    targets = []

    # 方法1: 使用airport命令（可获取BSSID）
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    try:
        r = subprocess.run(
            [airport_path, "-s"],
            capture_output=True, text=True, timeout=15
        )
        lines = r.stdout.strip().split('\n')
        if len(lines) > 1:
            for line in lines[1:]:
                # airport -s 输出格式:
                #  SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
                parts = line.split()
                if len(parts) >= 7:
                    # BSSID在第2列（MAC格式 xx:xx:xx:xx:xx:xx）
                    bssid = None
                    for p in parts:
                        if len(p) == 17 and p.count(':') == 5:
                            bssid = p
                            break
                    if bssid:
                        # SSID是BSSID前面的所有内容
                        bssid_idx = line.index(bssid)
                        ssid = line[:bssid_idx].strip()
                        if ssid:
                            targets.append({
                                "ssid": ssid,
                                "bssid": bssid,
                            })
    except Exception:
        pass

    # 方法2: 使用CoreWLAN扫描补充
    if not targets:
        sys.path.insert(0, str(SCRIPT_DIR))
        try:
            from wifi_scanner import scan
            nets, cur = scan()
            for n in nets:
                ssid = n.get("ssid", "")
                bssid = n.get("bssid", "")
                if ssid and bssid:
                    targets.append({"ssid": ssid, "bssid": bssid})
        except Exception:
            pass

    return targets


# ============================================================
# 批量查询主流程
# ============================================================
def batch_query(targets):
    """
    批量查询WiFi密码数据库
    """
    total = len(targets)
    found = []
    cracked = load_cracked()

    print(f"\n{BOLD}{'=' * 60}")
    print(f"  WiFi密码数据库查询器 v1.0")
    print(f"  数据源: WiFi万能钥匙共享密码库")
    print(f"{'=' * 60}{RESET}")
    print(f"  目标数: {total}")
    print()

    for idx, t in enumerate(targets):
        ssid = t["ssid"]
        bssid = t["bssid"]

        # 跳过已破解
        if ssid in cracked:
            print(f"  [{idx+1}/{total}] {ssid:<24} 已破解(跳过)")
            continue

        sys.stdout.write(f"\r  [{idx+1}/{total}] {ssid:<24} ({bssid}) 查询中...")
        sys.stdout.flush()

        pwd = query_wifi_masterkey(ssid, bssid)
        if pwd:
            found.append((ssid, bssid, pwd))
            save_cracked(ssid, pwd, "wifi_masterkey_db")
            print(f"\r  [{idx+1}/{total}] {ssid:<24} {GREEN}{BOLD}>>> 命中！密码: {pwd}{RESET}")
        else:
            print(f"\r  [{idx+1}/{total}] {ssid:<24} 未收录               ")

        # 避免请求过快
        time.sleep(0.3)

    # 最终报告
    print()
    print(f"{BOLD}{'=' * 60}")
    print(f"  查询完成")
    print(f"{'=' * 60}{RESET}")
    if found:
        print(f"  {GREEN}{BOLD}命中 {len(found)} 个WiFi密码：{RESET}")
        for ssid, bssid, pwd in found:
            print(f"    {ssid:<24} {pwd}")
        print(f"\n  密码已保存到: {CRACKED_FILE}")
    else:
        print(f"  {YELLOW}未命中（目标WiFi可能未被万能钥匙用户分享）{RESET}")
    print(f"{'=' * 60}")

    return found


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="WiFi密码共享数据库查询器 v1.0")
    parser.add_argument("--ssid", type=str, help="查询指定SSID")
    parser.add_argument("--bssid", type=str, help="目标BSSID（MAC地址）")
    parser.add_argument("--scan", action="store_true",
                        help="自动扫描周围WiFi并批量查询")
    parser.add_argument("--wps-pin", type=str,
                        help="根据BSSID计算WPS PIN码")
    parser.add_argument("--show-cracked", action="store_true",
                        help="显示所有已破解的WiFi")
    args = parser.parse_args()

    # 显示已破解记录
    if args.show_cracked:
        cracked = load_cracked()
        if not cracked:
            print("  暂无破解记录")
        else:
            print(f"\n  {GREEN}{BOLD}已破解的WiFi ({len(cracked)}个):{RESET}")
            print(f"  {'SSID':<28} {'密码':<24} {'来源':<20} {'时间'}")
            print(f"  {'-' * 90}")
            for ssid, info in cracked.items():
                pwd = info.get("password", "?")
                src = info.get("source", "N/A")
                t = info.get("time", "N/A")
                print(f"  {ssid:<28} {pwd:<24} {src:<20} {t}")
        return

    # WPS PIN计算
    if args.wps_pin:
        bssid = args.wps_pin
        pins = compute_wps_pins(bssid)
        print(f"\n  BSSID: {bssid}")
        print(f"  WPS PIN候选 ({len(pins)}条):")
        print(f"  {'#':>3} {'PIN':<12} {'算法'}")
        print(f"  {'-' * 35}")
        for i, (pin, algo) in enumerate(pins, 1):
            print(f"  {i:>3} {pin:<12} {algo}")
        return

    # 单个SSID查询
    if args.ssid and args.bssid:
        print(f"\n  查询: SSID={args.ssid}  BSSID={args.bssid}")
        print(f"  正在查询WiFi万能钥匙数据库...")
        pwd = query_wifi_masterkey(args.ssid, args.bssid)
        if pwd:
            print(f"  {GREEN}{BOLD}>>> 密码: {pwd}{RESET}")
            save_cracked(args.ssid, pwd, "wifi_masterkey_db")
            print(f"  已保存到: {CRACKED_FILE}")
        else:
            print(f"  {YELLOW}未找到密码（该WiFi可能未被分享）{RESET}")

        # 同时显示WPS PIN
        pins = compute_wps_pins(args.bssid)
        if pins:
            print(f"\n  WPS PIN候选:")
            for pin, algo in pins[:3]:
                print(f"    {pin}  ({algo})")
        return

    if args.ssid and not args.bssid:
        print(f"  {RED}[!] 查询需要同时提供 --ssid 和 --bssid{RESET}")
        print(f"  提示: 使用 --scan 自动扫描获取BSSID")
        return

    # 自动扫描+批量查询
    if args.scan:
        print(f"{CYAN}[*] 正在扫描周围WiFi（获取BSSID信息）...{RESET}")
        targets = get_scan_targets()
        if not targets:
            print(f"  {YELLOW}未扫描到WiFi（可能需要位置权限）{RESET}")
            print(f"  提示: 手动指定 --ssid 和 --bssid 查询")
            return
        print(f"  扫描到 {len(targets)} 个WiFi:")
        for i, t in enumerate(targets[:20], 1):
            print(f"    {i:>3}. {t['ssid']:<24} {t['bssid']}")
        if len(targets) > 20:
            print(f"    ... 还有 {len(targets) - 20} 个")
        print()
        batch_query(targets)
        return

    # 默认：显示帮助
    print(f"\n{BOLD}  WiFi密码共享数据库查询器 v1.0{RESET}")
    print(f"  数据来源: WiFi万能钥匙用户共享密码库")
    print()
    print(f"  用法:")
    print(f"    --scan                      自动扫描周围WiFi并批量查询密码")
    print(f"    --ssid X --bssid Y          查询指定WiFi的密码")
    print(f"    --wps-pin XX:XX:XX:XX:XX:XX 根据MAC计算WPS PIN码")
    print(f"    --show-cracked              显示所有已破解的WiFi")
    print()
    print(f"  示例:")
    print(f"    python3 {Path(__file__).name} --scan")
    print(f"    python3 {Path(__file__).name} --ssid CMCC-532 --bssid 80:89:17:FC:6E:5D")
    print(f"    python3 {Path(__file__).name} --wps-pin 80:89:17:FC:6E:5D")


if __name__ == "__main__":
    main()
