#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
社工字典生成器（CUPP 思路）
功能：根据目标个人信息生成高针对性 WiFi 密码字典
原理：中国用户常用姓名拼音+生日+手机号等个人信息组合作为密码
"""

import argparse
import itertools
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
DEFAULT_OUTPUT = PROJECT_DIR / "wordlists" / "smart_target.txt"

# 常见数字后缀
NUM_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "0", "00", "000", "01", "02",
    "11", "22", "33", "66", "77", "88", "99",
    "111", "222", "666", "888", "999",
    "520", "521", "1314", "168", "188",
    "!", "@", "#", ".", "~",
]

# 常见连接符
CONNECTORS = ["", ".", "_", "@", "#"]

# leet speak 替换表
LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}

# 路由器品牌默认密码模式
ROUTER_PATTERNS = {
    "TP-LINK": ["8位纯数字", "MAC后8位"],
    "Tenda": ["8位纯数字"],
    "MERCURY": ["8位纯数字"],
    "FAST": ["8位纯数字"],
    "HUAWEI": ["8位字母数字"],
    "MiWiFi": ["用户设置"],
    "CMCC": ["8位纯数字"],
    "ChinaNet": ["8位纯数字"],
}


class SmartDictGenerator:
    """社工字典生成器"""

    def __init__(self, min_len=8, max_len=20):
        self.min_len = max(min_len, 8)
        self.max_len = max_len
        self.passwords = []
        self.seen = set()
        self.info = {}

    def _add(self, pwd):
        pwd = str(pwd).strip()
        if self.min_len <= len(pwd) <= self.max_len and pwd not in self.seen:
            self.seen.add(pwd)
            self.passwords.append(pwd)

    def _add_variants(self, base):
        """为基础词生成各种变体"""
        if not base:
            return
        # 原始 + 数字后缀
        for suf in NUM_SUFFIXES:
            self._add(base + suf)
            self._add(suf + base)
        # 首字母大写
        cap = base.capitalize()
        for suf in NUM_SUFFIXES[:15]:
            self._add(cap + suf)
        # 全大写
        upper = base.upper()
        for suf in NUM_SUFFIXES[:10]:
            self._add(upper + suf)
        # leet speak
        leet = base
        for ch, rep in LEET.items():
            leet = leet.replace(ch, rep)
        if leet != base:
            for suf in NUM_SUFFIXES[:10]:
                self._add(leet + suf)

    def collect_info_interactive(self):
        """交互式收集目标信息"""
        print("[*] 输入目标信息（不知道的直接回车跳过）")
        print()
        prompts = {
            "name_pinyin": "姓名拼音（如 zhangsan）: ",
            "surname": "姓氏拼音（如 zhang）: ",
            "firstname": "名字拼音（如 san）: ",
            "birthday": "生日 YYYYMMDD（如 19901225）: ",
            "phone": "手机号（如 13812345678）: ",
            "qq": "QQ号: ",
            "spouse_name": "配偶/对象名拼音: ",
            "spouse_birthday": "配偶生日 YYYYMMDD: ",
            "child_name": "孩子名拼音: ",
            "child_birthday": "孩子生日 YYYYMMDD: ",
            "pet_name": "宠物名: ",
            "door_number": "门牌号（如 1502）: ",
            "car_plate": "车牌号后几位: ",
            "company": "公司名缩写: ",
            "ssid": "目标WiFi SSID名称: ",
        }
        for key, prompt in prompts.items():
            try:
                val = input(f"  {prompt}").strip()
                if val:
                    self.info[key] = val
            except EOFError:
                break

    def generate(self):
        """根据收集的信息生成字典"""
        info = self.info
        words = []  # 收集所有关键词

        # 姓名相关
        for key in ["name_pinyin", "surname", "firstname",
                    "spouse_name", "child_name", "pet_name", "company"]:
            val = info.get(key, "")
            if val:
                words.append(val.lower())

        # 日期相关
        dates = []
        for key in ["birthday", "spouse_birthday", "child_birthday"]:
            val = info.get(key, "")
            if val and len(val) == 8:
                dates.append(val)           # 19901225
                dates.append(val[4:])       # 1225
                dates.append(val[2:])       # 901225
                dates.append(val[:4])       # 1990
                dates.append(val[4:6] + val[6:8])  # 1225

        # 数字相关
        numbers = []
        for key in ["phone", "qq", "door_number", "car_plate"]:
            val = info.get(key, "")
            if val:
                numbers.append(val)
                if len(val) >= 4:
                    numbers.append(val[-4:])  # 后4位
                    numbers.append(val[-8:])  # 后8位

        # 生成组合
        print(f"[*] 关键词: {len(words)} | 日期: {len(dates)} | 数字: {len(numbers)}")
        print("[*] 生成密码组合...")

        # 1. 关键词变体
        for w in words:
            self._add_variants(w)

        # 2. 关键词 + 日期
        for w in words:
            for d in dates:
                self._add(w + d)
                self._add(d + w)
                self._add(w.capitalize() + d)

        # 3. 关键词 + 数字
        for w in words:
            for n in numbers:
                self._add(w + n)
                self._add(n + w)
                self._add(w.capitalize() + n)

        # 4. 双关键词组合
        for w1 in words:
            for w2 in words:
                if w1 != w2:
                    for conn in CONNECTORS:
                        self._add(w1 + conn + w2)

        # 5. 日期 + 数字
        for d in dates:
            for n in numbers:
                self._add(d + n)
                self._add(n + d)

        # 6. 纯数字（手机号、QQ、日期直接作密码）
        for n in numbers + dates:
            self._add(n)
            for suf in ["", "0", "00", "1", "a", "!"]:
                self._add(n + suf)

        # 7. SSID品牌推测
        ssid = info.get("ssid", "")
        if ssid:
            self._gen_router_defaults(ssid)

        # 8. 常见爱情密码 + 个人信息
        love_words = ["woaini", "iloveu", "forever", "happy", "love"]
        for lw in love_words:
            for w in words[:3]:
                self._add(lw + w)
                self._add(w + lw)
            for d in dates[:3]:
                self._add(lw + d)

    def _gen_router_defaults(self, ssid):
        """根据SSID推测路由器品牌并生成默认密码模式"""
        ssid_upper = ssid.upper()
        brand = None
        for b in ROUTER_PATTERNS:
            if b.upper() in ssid_upper:
                brand = b
                break
        if not brand:
            return
        print(f"[*] 检测到路由器品牌: {brand}")
        patterns = ROUTER_PATTERNS[brand]
        if "8位纯数字" in patterns:
            # 从SSID中提取可能的数字后缀
            import re
            nums = re.findall(r"\d+", ssid)
            for n in nums:
                # 可能是MAC地址片段，尝试扩展
                for prefix in ["", "0", "00", "1", "11"]:
                    combo = prefix + n
                    if len(combo) == 8:
                        self._add(combo)
                    self._add(n + "0" * max(0, 8 - len(n)))

    def export(self, output_path):
        """导出字典"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for pwd in self.passwords:
                f.write(pwd + chr(10))
        size_kb = output_path.stat().st_size / 1024
        print(f"[+] 已生成: {output_path}")
        print(f"[+] 总计: {len(self.passwords)} 条 ({size_kb:.0f} KB)")


def main():
    parser = argparse.ArgumentParser(description="社工字典生成器")
    parser.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT), help="输出路径")
    parser.add_argument("--ssid", type=str, help="目标WiFi SSID")
    parser.add_argument("--name", type=str, help="姓名拼音")
    parser.add_argument("--birthday", type=str, help="生日 YYYYMMDD")
    parser.add_argument("--phone", type=str, help="手机号")
    args = parser.parse_args()

    print("=" * 50)
    print("  社工字典生成器 (CUPP风格)")
    print("  根据目标个人信息生成高针对性密码")
    print("=" * 50)
    print()

    gen = SmartDictGenerator()

    # 命令行参数
    if args.name:
        gen.info["name_pinyin"] = args.name
    if args.birthday:
        gen.info["birthday"] = args.birthday
    if args.phone:
        gen.info["phone"] = args.phone
    if args.ssid:
        gen.info["ssid"] = args.ssid

    # 如果没有命令行参数，交互式输入
    if not gen.info:
        gen.collect_info_interactive()

    if not gen.info:
        print("[!] 未输入任何信息")
        return

    gen.generate()
    gen.export(args.output)


if __name__ == "__main__":
    main()
