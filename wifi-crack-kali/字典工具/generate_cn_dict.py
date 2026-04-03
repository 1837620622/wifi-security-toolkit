#!/usr/bin/env python3
# ============================================================
# 中国 WiFi 密码字典生成器
#
# 生成适合中国 WiFi 环境的密码字典，包含：
# - 8位纯数字（最常见）
# - 常见弱密码
# - 手机号码模式
# - 生日+常见后缀
# - 拼音组合
#
# 用法: python3 generate_cn_dict.py
# 输出: cn_wifi_dict.txt
#
# 作者: 传康Kk (微信:1837620622)
# ============================================================

import itertools
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(SCRIPT_DIR, "cn_wifi_dict.txt")

passwords = set()

# ============================================================
# 1. 常见弱密码 TOP 200
# ============================================================
common = [
    "12345678", "123456789", "1234567890", "00000000", "11111111",
    "22222222", "33333333", "44444444", "55555555", "66666666",
    "77777777", "88888888", "99999999", "12341234", "11112222",
    "12345678a", "1234567890a", "a12345678", "a123456789",
    "password", "password1", "password123", "admin123", "admin1234",
    "qwerty123", "qwertyui", "asdfghjk", "zxcvbnm1",
    "iloveyou", "woaini520", "woaini1314", "5201314520",
    "aaa123456", "abc123456", "abcd1234", "1q2w3e4r", "q1w2e3r4",
    "1qaz2wsx", "qazwsxedc", "password1234", "p@ssw0rd",
    "xiaomi123", "huawei123", "wifi1234", "wifi12345", "wifiwifi",
    "internet", "chinaunicom", "chinamobile", "chinanet",
    "66668888", "88886666", "18181818", "16161616", "13131313",
    "11223344", "22334455", "33445566", "44556677", "55667788",
    "12121212", "13141314", "52015201", "13141314a",
    "147258369", "741852963", "369258147", "159357159",
    "11111111a", "asd123456", "qwe123456", "zxc123456",
    "a1234567", "aa123456", "aaa12345", "abc12345",
    "test1234", "guest1234", "user1234", "home1234",
    "meiyoumima", "woxiangshangwang", "mimashishenme",
    "aaaaaaaa", "bbbbbbbb", "abcdefgh", "abcd5678",
    "01234567", "98765432", "87654321", "76543210",
    "10101010", "20202020", "20252025", "20262026", "20242024",
    "2025202520252025", "2026202620262026",
]
passwords.update(common)

# ============================================================
# 2. 8位纯数字常见模式
# ============================================================
# 重复模式
for d in range(10):
    passwords.add(str(d) * 8)

# 递增递减
passwords.add("01234567")
passwords.add("12345678")
passwords.add("23456789")
passwords.add("98765432")
passwords.add("87654321")
passwords.add("76543210")

# 日期模式: 19xx/20xx 年 + 月日
for year in range(1960, 2027):
    for month in range(1, 13):
        for day in range(1, 32):
            # 8位: 20001231
            pw = "%04d%02d%02d" % (year, month, day)
            if len(pw) == 8:
                passwords.add(pw)

# ============================================================
# 3. 手机号码模式（11位，1开头）
# ============================================================
# 常见手机号前缀
prefixes = [
    "130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
    "150", "151", "152", "153", "155", "156", "157", "158", "159",
    "170", "171", "172", "173", "175", "176", "177", "178",
    "180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
    "190", "191", "192", "193", "195", "196", "197", "198", "199",
]
# 常见尾号模式（减少量级）
for prefix in prefixes:
    # 尾号全同
    for d in range(10):
        passwords.add(prefix + str(d) * 8)
    # 尾号递增
    passwords.add(prefix + "12345678")
    passwords.add(prefix + "00000000")
    passwords.add(prefix + "88888888")
    passwords.add(prefix + "66666666")

# ============================================================
# 4. 拼音+数字组合
# ============================================================
pinyin_words = [
    "woaini", "iloveu", "woshibaba", "woshimama", "jiayou",
    "zhangsan", "lisi", "wangwu", "xiaoming", "xiaohong",
    "mima", "wifi", "wangluo", "shangwang", "password",
    "admin", "guest", "test", "hello", "welcome",
    "love", "baby", "happy", "lucky", "dragon",
    "china", "beijing", "shanghai", "guangzhou", "shenzhen",
]
suffixes = [
    "123", "1234", "12345", "123456", "1234567", "12345678",
    "520", "521", "1314", "666", "888", "999",
    "2024", "2025", "2026", "01", "02",
]
for word in pinyin_words:
    passwords.add(word)
    for suf in suffixes:
        pw = word + suf
        if 8 <= len(pw) <= 16:
            passwords.add(pw)
        pw2 = suf + word
        if 8 <= len(pw2) <= 16:
            passwords.add(pw2)

# ============================================================
# 5. 键盘模式
# ============================================================
keyboard = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qweasdzxc", "1q2w3e4r5t", "qwer1234",
    "zaq12wsx", "1qazxsw2", "qaswdefr",
    "1234qwer", "qwer5678", "asdf1234",
    "zxcv1234", "poiuytrewq", "lkjhgfdsa",
    "mnbvcxz1", "1234asdf", "5678qwer",
]
passwords.update(keyboard)

# ============================================================
# 6. WiFi 默认密码模式
# ============================================================
# TP-LINK/小米/华为路由器常见默认密码模式
for brand in ["tp", "tplink", "xiaomi", "huawei", "cmcc", "chinanet"]:
    for suf in ["123", "1234", "12345", "123456", "888", "666"]:
        pw = brand + suf
        if 8 <= len(pw) <= 16:
            passwords.add(pw)

# ============================================================
# 过滤：WiFi 密码至少 8 位
# ============================================================
passwords = sorted([p for p in passwords if 8 <= len(p) <= 63])

# 写入文件
with open(OUTPUT, "w", encoding="utf-8") as f:
    for pw in passwords:
        f.write(pw + "\n")

print("[✓] 字典生成完成: %s" % OUTPUT)
print("[✓] 密码数量: %d" % len(passwords))
print("[✓] 文件大小: %.1f MB" % (os.path.getsize(OUTPUT) / 1024 / 1024))
