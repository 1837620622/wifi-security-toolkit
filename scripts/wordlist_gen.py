#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中国家庭 WiFi 智能密码字典生成器
功能：融合在线开源字典 + 本地智能生成，创建高命中率密码字典
数据源：SecLists WPA Top4800、中国常用密码 Top10000、本地模式生成
"""

import argparse
import os
import sys
from pathlib import Path

# ============================================================
# 项目路径
# ============================================================
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
ONLINE_DIR = PROJECT_DIR / "wordlists" / "online"
DEFAULT_OUTPUT = PROJECT_DIR / "wordlists" / "wifi_dict_final.txt"

# ============================================================
# 手机号前缀（按市场份额排序，移动 > 联通 > 电信）
# ============================================================
PHONE_PREFIXES_ALL = [
    "138", "139", "136", "137", "135", "134", "150", "151", "152",
    "158", "159", "187", "188", "182", "183", "184", "178", "147",
    "172", "198", "130", "131", "132", "155", "156", "185", "186",
    "176", "175", "166", "133", "153", "180", "181", "189", "177",
    "173", "199", "191", "170", "171",
]

# ============================================================
# 核心高频密码（手工精选，命中率最高的前200个）
# ============================================================
CORE_TOP = [
    # 纯数字 - 中国最常见
    "12345678", "123456789", "1234567890", "88888888", "00000000",
    "11111111", "66666666", "99999999", "12341234", "87654321",
    "98765432", "11223344", "13141314", "52013140", "14521452",
    "15201520", "55555555", "77777777", "22222222", "33333333",
    "44444444", "01234567", "10101010", "12344321", "20082008",
    "20102010", "20202020", "19901990", "20002000", "56789012",
    "13572468", "24681357", "147258369", "123123123", "321321321",
    "520131400", "131452000", "775852100", "521131400",
    "1234567890", "0987654321", "1111111111",
    # 字母数字 - 全球+中国高频
    "password", "password1", "iloveyou", "sunshine", "football",
    "computer", "superman", "internet", "1qaz2wsx", "baseball",
    "whatever", "princess", "abcd1234", "starwars", "trustno1",
    "password1", "qwerty123", "qwertyui", "asdf1234", "1234qwer",
    "qwertyuiop", "q1w2e3r4", "asdfghjk", "asdfasdf", "zxcvbnm1",
    "qwer1234", "1q2w3e4r", "qazwsxed", "1qaz2wsx",
    # 拼音+数字 - 中国特色
    "woaini520", "woaini1314", "woaini123", "woaini521",
    "woaini000", "woaini888", "woaini666", "woaini111",
    "aini1314", "aini5200", "iloveu520",
    "5201314a", "a5201314", "1314520a",
    "wifi1234", "wifi12345678", "wifi8888",
    "admin123", "admin888", "admin1234",
    "abc12345", "abc123456", "abc1234567",
    "aa123456", "a123456789", "a12345678",
    "asd12345", "asd123456", "qwe123456",
    "wang1234", "li123456", "zhang123",
    # 特殊含义数字
    "52013140", "52013141", "13145200", "13145201",
    "77585211", "77582511", "31415926",
    "5201314520", "1314520520",
    "11111234", "12345600", "00123456",
    "10203040", "11121314",
]


class DictGenerator:
    """字典生成器核心类"""

    def __init__(self, min_len=8, max_len=20):
        self.min_len = max(min_len, 8)
        self.max_len = max_len
        self.passwords = []       # 有序列表（按优先级）
        self.seen = set()         # 去重集合
        self.stats = {}           # 各模块统计

    def _add(self, pwd):
        """添加密码（去重 + 长度过滤）"""
        pwd = str(pwd).strip()
        if self.min_len <= len(pwd) <= self.max_len and pwd not in self.seen:
            self.seen.add(pwd)
            self.passwords.append(pwd)
            return True
        return False

    def _add_batch(self, passwords):
        """批量添加"""
        count = 0
        for p in passwords:
            if self._add(p):
                count += 1
        return count

    # --------------------------------------------------------
    # 模块1：加载在线开源字典
    # --------------------------------------------------------
    def load_online_dicts(self):
        """
        按优先级加载在线字典：
        1. 中国常用密码 top10000（命中率最高）
        2. SecLists WPA top4800（国际通用）
        3. 中国弱密码 1000
        """
        count = 0
        files = [
            ("chinese_top10000.txt", "中国常用密码 Top10000"),
            ("seclists_wpa_top4800.txt", "SecLists WPA Top4800"),
            ("chinese_weak1000.txt", "中国弱密码 Top1000"),
        ]
        for fname, desc in files:
            fpath = ONLINE_DIR / fname
            if fpath.exists():
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                added = self._add_batch(words)
                count += added
                print(f"    {desc}: +{added} 条")
            else:
                print(f"    [!] 未找到 {fpath.name}（可运行 download_dicts.py 下载）")

        self.stats["online"] = count
        return count

    # --------------------------------------------------------
    # 模块2：核心高频密码
    # --------------------------------------------------------
    def gen_core_top(self):
        """加载手工精选的核心高频密码"""
        count = self._add_batch(CORE_TOP)
        self.stats["core"] = count
        return count

    # --------------------------------------------------------
    # 模块3：纯数字模式
    # --------------------------------------------------------
    def gen_numeric(self):
        """生成纯数字密码模式"""
        before = len(self.passwords)

        # 重复数字 8-10位
        for d in "0123456789":
            for length in (8, 9, 10):
                self._add(d * length)

        # 顺序 / 逆序
        for seq in ["12345678", "123456789", "1234567890",
                     "01234567", "87654321", "987654321", "0987654321"]:
            self._add(seq)

        # AABB 模式：11223344, 11112222
        for a in range(10):
            for b in range(10):
                if a != b:
                    self._add(f"{a}{a}{b}{b}{a}{a}{b}{b}")
                    self._add(f"{a}{a}{a}{a}{b}{b}{b}{b}")
                    self._add(f"{a}{b}" * 4)

        # 吉利数字组合
        lucky = ["168", "188", "518", "520", "521", "588",
                 "666", "688", "888", "886", "999", "1314",
                 "5200", "5201", "5211", "7758"]
        for n1 in lucky:
            for n2 in lucky:
                combo = n1 + n2
                self._add(combo)

        # 年份+吉利数字
        for year in range(1980, 2026):
            for suf in ["0000", "1111", "1234", "5678", "8888", "6666", "1314", "5200"]:
                self._add(f"{year}{suf}")

        self.stats["numeric"] = len(self.passwords) - before
        return self.stats["numeric"]

    # --------------------------------------------------------
    # 模块4：手机号码模式
    # --------------------------------------------------------
    def gen_phone(self, prefixes=None):
        """
        手机号码密码生成
        策略：前缀 + 高频尾号模式（而非全量穷举）
        """
        before = len(self.passwords)
        if prefixes is None:
            prefixes = PHONE_PREFIXES_ALL

        # 高频尾号模式
        tails_8 = set()
        # 重复尾号
        for d in range(10):
            tails_8.add(f"{d}" * 8)
            for d2 in range(10):
                tails_8.add(f"{d}{d}{d}{d}{d2}{d2}{d2}{d2}")
        # 顺序尾号
        tails_8.update(["12345678", "87654321", "00001111", "11110000",
                        "11112222", "22223333", "66668888", "88889999",
                        "52013140", "13145200", "52001314", "00000000"])
        # 生日尾号（月日变体）
        for m in range(1, 13):
            for d in range(1, 32):
                md = f"{m:02d}{d:02d}"
                for prefix_4 in ["0000", "1111", "1234", "2000", "1999",
                                  "1998", "1997", "1996", "1995", "1990",
                                  "1985", "1980", "8888", "6666"]:
                    tails_8.add(prefix_4 + md)
                    tails_8.add(md + prefix_4)

        for prefix in prefixes:
            for tail in tails_8:
                self._add(prefix + tail)

        self.stats["phone"] = len(self.passwords) - before
        return self.stats["phone"]

    # --------------------------------------------------------
    # 模块5：生日日期
    # --------------------------------------------------------
    def gen_birthday(self, year_start=1960, year_end=2010):
        """生成 YYYYMMDD 格式的生日密码"""
        before = len(self.passwords)
        for year in range(year_start, year_end + 1):
            for month in range(1, 13):
                max_day = 31
                if month in (4, 6, 9, 11):
                    max_day = 30
                elif month == 2:
                    max_day = 29
                for day in range(1, max_day + 1):
                    date8 = f"{year}{month:02d}{day:02d}"
                    self._add(date8)
                    # MMDDYYYY
                    self._add(f"{month:02d}{day:02d}{year}")
                    # 6位日期+后缀
                    d6 = f"{year % 100:02d}{month:02d}{day:02d}"
                    for suf in ["00", "11", "88", "99", "ab", "aa", "88", "520", "1314"]:
                        self._add(d6 + suf)

        self.stats["birthday"] = len(self.passwords) - before
        return self.stats["birthday"]

    # --------------------------------------------------------
    # 模块6：拼音 + 数字组合
    # --------------------------------------------------------
    def gen_pinyin(self):
        """生成拼音词汇+数字的组合密码"""
        before = len(self.passwords)

        words = [
            "woaini", "aini", "love", "happy", "lucky",
            "nihao", "hello", "wifi", "mima", "jiayou",
            "zhongguo", "china", "forever", "always",
            "baby", "angel", "iloveu", "iloveyou",
            "woshisb", "caonima", "xiaomi", "huawei",
            "tplink", "admin", "root", "master",
            "password", "passwd", "qwerty",
        ]
        surnames = [
            "wang", "li", "zhang", "liu", "chen", "yang",
            "zhao", "huang", "zhou", "wu", "xu", "sun",
        ]
        suffixes = [
            "123", "1234", "12345", "123456", "1234567", "12345678",
            "520", "521", "1314", "888", "666", "999",
            "000", "111", "222", "168", "188", "008",
            "01", "02", "06", "08", "11", "12", "18",
            "20", "21", "22", "66", "77", "88", "99",
        ]

        for word in words + surnames:
            for suf in suffixes:
                self._add(word + suf)
                self._add(suf + word)
            # 首字母大写变体
            cap = word.capitalize()
            for suf in suffixes[:10]:
                self._add(cap + suf)

        self.stats["pinyin"] = len(self.passwords) - before
        return self.stats["pinyin"]

    # --------------------------------------------------------
    # 模块7：键盘模式
    # --------------------------------------------------------
    def gen_keyboard(self):
        """生成键盘布局模式密码"""
        before = len(self.passwords)
        patterns = [
            "qwertyui", "qwerty123", "qwerty1234", "qwerty12345",
            "asdfghjk", "asdf1234", "asdfghjkl",
            "zxcvbnm1", "zxcv1234", "zxcvbnm12", "zxcvbnm123",
            "1qaz2wsx", "2wsx3edc", "3edc4rfv",
            "qazwsxed", "qazwsx123", "qazwsxedc",
            "1q2w3e4r", "q1w2e3r4", "5t6y7u8i",
            "poiuytre", "lkjhgfds", "mnbvcxz1",
            "qweasdzx", "qweasd123", "1234qwer", "qwer1234asdf",
            "abcdefgh", "abcd1234", "abcdef12", "abc12345",
            "abc123456", "a1b2c3d4", "1a2b3c4d",
            "aabbccdd", "abcdabcd", "abcabc12",
        ]
        for p in patterns:
            self._add(p)
            self._add(p.upper())
            self._add(p.capitalize())
            # 加数字后缀
            for s in ["1", "12", "123", "!", "@"]:
                self._add(p + s)

        self.stats["keyboard"] = len(self.passwords) - before
        return self.stats["keyboard"]

    # --------------------------------------------------------
    # 全量生成
    # --------------------------------------------------------
    def generate_all(self, phone_prefixes=None, year_start=1960, year_end=2010):
        """按优先级顺序生成全部密码"""
        print("[1/7] 加载核心高频密码...")
        n = self.gen_core_top()
        print(f"      +{n} 条，累计: {len(self.passwords)}")

        print("[2/7] 加载在线开源字典...")
        n = self.load_online_dicts()
        print(f"      +{n} 条，累计: {len(self.passwords)}")

        print("[3/7] 生成纯数字密码...")
        n = self.gen_numeric()
        print(f"      +{n} 条，累计: {len(self.passwords)}")

        print("[4/7] 生成手机号码密码...")
        n = self.gen_phone(phone_prefixes)
        print(f"      +{n} 条，累计: {len(self.passwords)}")

        print("[5/7] 生成生日日期密码...")
        n = self.gen_birthday(year_start, year_end)
        print(f"      +{n} 条，累计: {len(self.passwords)}")

        print("[6/7] 生成拼音组合密码...")
        n = self.gen_pinyin()
        print(f"      +{n} 条，累计: {len(self.passwords)}")

        print("[7/7] 生成键盘模式密码...")
        n = self.gen_keyboard()
        print(f"      +{n} 条，累计: {len(self.passwords)}")

    # --------------------------------------------------------
    # 导出
    # --------------------------------------------------------
    def export(self, output_path):
        """导出字典文件（保持优先级排序）"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            for pwd in self.passwords:
                f.write(pwd + "\n")

        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"\n[+] 字典已导出: {output_path}")
        print(f"[+] 总计: {len(self.passwords)} 条密码")
        print(f"[+] 文件大小: {size_mb:.2f} MB")

        # 输出各模块统计
        print("\n[统计]")
        for name, count in self.stats.items():
            print(f"    {name}: {count} 条")


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="WiFi 密码字典生成器")
    parser.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT), help="输出路径")
    parser.add_argument("--phone-prefix", nargs="*", help="指定手机号前缀")
    parser.add_argument("--year-start", type=int, default=1960, help="生日起始年")
    parser.add_argument("--year-end", type=int, default=2010, help="生日结束年")
    parser.add_argument("--min-len", type=int, default=8, help="最短密码长度")
    parser.add_argument("--max-len", type=int, default=20, help="最长密码长度")
    parser.add_argument("--quick", action="store_true", help="快速模式（仅高频密码）")
    args = parser.parse_args()

    print("=" * 50)
    print("  WiFi 密码字典生成器 v2.0")
    print("  数据源：在线开源字典 + 本地智能生成")
    print("=" * 50)
    print()

    gen = DictGenerator(min_len=args.min_len, max_len=args.max_len)

    if args.quick:
        print("[快速模式]")
        gen.gen_core_top()
        gen.load_online_dicts()
        gen.gen_keyboard()
    else:
        gen.generate_all(
            phone_prefixes=args.phone_prefix,
            year_start=args.year_start,
            year_end=args.year_end,
        )

    gen.export(args.output)


if __name__ == "__main__":
    main()
