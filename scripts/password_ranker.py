#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能密码排序器 v1.0
基于 Markov 链 + PCFG 概率模型对密码字典进行智能排序

核心算法：
  1. 字符级 N-gram Markov 链：计算字符转移概率
  2. PCFG 结构分析：统计密码结构模式的概率分布
  3. 综合评分：Markov概率 × 结构概率 = 最终优先级

学术参考：
  - GENPass (Xia et al., 2019): 多源深度学习密码猜测模型
  - Recurrent GANs Password Cracker (Nam et al., 2020): 循环GAN密码破解
  - Improving targeted password guessing (Ou et al., 2026): 利用PII优化定向猜测
  - A Systematic Review on Password Guessing Tasks (Yu et al., 2023): 密码猜测任务综述
  - hashcat Brain / Slow Candidates Mode: 高级候选生成器集成

适配：独立运行或被其他模块调用
"""

import argparse
import math
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
ONLINE_DIR = PROJECT_DIR / "wordlists" / "online"

# ============================================================
# 颜色常量
# ============================================================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


# ============================================================
# PCFG 结构分析器
# ============================================================
class PCFGAnalyzer:
    """
    概率上下文无关文法(PCFG)结构分析器
    将密码分解为结构模板（如 D8=8位纯数字, L4D4=4字母4数字）
    并统计各结构的出现概率
    """

    def __init__(self):
        # 结构模式计数器
        self.structure_counts = Counter()
        # 各类型的填充值分布
        self.digit_counts = defaultdict(Counter)     # 按长度分组的数字串分布
        self.alpha_counts = defaultdict(Counter)     # 按长度分组的字母串分布
        self.special_counts = defaultdict(Counter)   # 按长度分组的特殊字符分布
        self.total = 0

    @staticmethod
    def get_structure(password):
        """
        将密码分解为结构模板
        例如：'zhang1990' -> 'L5D4'
             '12345678' -> 'D8'
             'abc@1234' -> 'L3S1D4'
        """
        structure = []
        i = 0
        while i < len(password):
            if password[i].isdigit():
                # 数字段
                j = i
                while j < len(password) and password[j].isdigit():
                    j += 1
                structure.append(f"D{j - i}")
                i = j
            elif password[i].isalpha():
                # 字母段
                j = i
                while j < len(password) and password[j].isalpha():
                    j += 1
                structure.append(f"L{j - i}")
                i = j
            else:
                # 特殊字符段
                j = i
                while j < len(password) and not password[j].isdigit() and not password[j].isalpha():
                    j += 1
                structure.append(f"S{j - i}")
                i = j
        return "".join(structure)

    def train(self, passwords):
        """用密码列表训练PCFG模型"""
        for pwd in passwords:
            struct = self.get_structure(pwd)
            self.structure_counts[struct] += 1
            self.total += 1

            # 提取各段的填充值
            i = 0
            for seg in re.findall(r'[A-Z]\d+', struct):
                seg_type = seg[0]
                seg_len = int(seg[1:])
                segment_value = pwd[i:i + seg_len]
                i += seg_len

                if seg_type == 'D':
                    self.digit_counts[seg_len][segment_value] += 1
                elif seg_type == 'L':
                    self.alpha_counts[seg_len][segment_value.lower()] += 1
                elif seg_type == 'S':
                    self.special_counts[seg_len][segment_value] += 1

    def get_structure_prob(self, password):
        """获取密码结构的概率"""
        if self.total == 0:
            return 0.0
        struct = self.get_structure(password)
        count = self.structure_counts.get(struct, 0)
        return count / self.total if count > 0 else 1e-10

    def get_top_structures(self, n=20):
        """获取最常见的密码结构"""
        return self.structure_counts.most_common(n)


# ============================================================
# Markov 链密码评分器
# ============================================================
class MarkovScorer:
    """
    基于字符级 N-gram Markov 链的密码概率评分器
    利用字符转移概率评估密码的"自然程度"
    概率越高的密码越可能是真实密码
    """

    def __init__(self, order=2):
        """
        初始化 Markov 评分器
        参数:
            order: N-gram 的阶数（2=bigram, 3=trigram）
        """
        self.order = order
        # 转移计数：context -> {next_char: count}
        self.transitions = defaultdict(Counter)
        # 起始字符分布
        self.start_counts = Counter()
        # 总训练样本数
        self.total_passwords = 0
        # 字符集大小（用于平滑）
        self.charset_size = 0
        self.charset = set()

    def train(self, passwords):
        """用密码列表训练 Markov 模型"""
        self.total_passwords = len(passwords)

        for pwd in passwords:
            if len(pwd) < 2:
                continue

            # 记录起始字符
            start = pwd[:self.order]
            self.start_counts[start] += 1

            # 记录所有字符
            for ch in pwd:
                self.charset.add(ch)

            # 记录转移
            for i in range(len(pwd) - self.order):
                context = pwd[i:i + self.order]
                next_char = pwd[i + self.order]
                self.transitions[context][next_char] += 1

        self.charset_size = max(len(self.charset), 1)

    def score(self, password):
        """
        计算密码的 Markov 对数概率分数
        分数越高（越接近0）= 越像真实密码
        使用拉普拉斯平滑避免零概率
        """
        if len(password) < self.order + 1:
            return -100.0

        log_prob = 0.0

        # 起始概率
        start = password[:self.order]
        total_starts = sum(self.start_counts.values())
        if total_starts > 0:
            start_prob = (self.start_counts.get(start, 0) + 1) / (total_starts + self.charset_size ** self.order)
            log_prob += math.log(start_prob)
        else:
            log_prob += math.log(1e-10)

        # 转移概率
        for i in range(len(password) - self.order):
            context = password[i:i + self.order]
            next_char = password[i + self.order]

            context_total = sum(self.transitions[context].values())
            if context_total > 0:
                # 拉普拉斯平滑
                trans_prob = (self.transitions[context].get(next_char, 0) + 1) / (context_total + self.charset_size)
            else:
                trans_prob = 1.0 / self.charset_size

            log_prob += math.log(trans_prob)

        # 按密码长度归一化，避免长密码被惩罚
        normalized = log_prob / len(password)
        return normalized


# ============================================================
# 中国密码特征加分器
# ============================================================
class ChinesePasswordBooster:
    """
    基于中国用户密码习惯的特征加分器
    对符合中国密码特征的候选给予额外加分

    参考研究：
    - 中国用户约60-70%使用纯数字密码
    - 手机号、生日、吉利数字是最常见模式
    - 拼音+数字组合次之
    """

    # 高频模式正则表达式及其权重
    PATTERNS = [
        # 手机号模式（11位，1开头）
        (re.compile(r'^1[3-9]\d{9}$'), 2.0, "手机号"),
        # 8位纯数字（最常见的WiFi密码）
        (re.compile(r'^\d{8}$'), 1.8, "8位纯数字"),
        # 生日模式 YYYYMMDD
        (re.compile(r'^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$'), 1.6, "生日日期"),
        # 重复数字
        (re.compile(r'^(\d)\1{7,}$'), 1.5, "重复数字"),
        # 吉利数字组合（含520/1314/666/888）
        (re.compile(r'(?:520|1314|666|888|168)'), 1.3, "吉利数字"),
        # 拼音+数字
        (re.compile(r'^[a-z]{2,8}\d{2,8}$', re.IGNORECASE), 1.2, "拼音+数字"),
        # 常见弱密码前缀
        (re.compile(r'^(?:woaini|iloveu|qwerty|asdf|admin|password)', re.IGNORECASE), 1.4, "常见弱前缀"),
        # 键盘模式
        (re.compile(r'^(?:1qaz2wsx|qwertyui|asdfghjk|zxcvbnm)', re.IGNORECASE), 1.3, "键盘模式"),
        # 9-10位纯数字
        (re.compile(r'^\d{9,10}$'), 1.4, "9-10位纯数字"),
        # QQ号模式（5-12位数字）
        (re.compile(r'^\d{5,12}$'), 1.1, "数字序列"),
    ]

    @classmethod
    def boost_score(cls, password):
        """
        计算中国密码特征加分
        返回：加分倍数（>=1.0）
        """
        max_boost = 1.0
        for pattern, boost, _ in cls.PATTERNS:
            if pattern.search(password):
                max_boost = max(max_boost, boost)
        return max_boost

    @classmethod
    def get_matched_patterns(cls, password):
        """获取密码匹配的所有中国特征模式"""
        matched = []
        for pattern, boost, name in cls.PATTERNS:
            if pattern.search(password):
                matched.append((name, boost))
        return matched


# ============================================================
# 综合密码排序器
# ============================================================
class PasswordRanker:
    """
    综合密码排序器：融合 Markov + PCFG + 中国特征 三重评分
    最终得分 = Markov分数 × PCFG结构概率 × 中国特征加分

    算法流程：
    1. 使用训练语料构建 Markov 和 PCFG 模型
    2. 对每个密码候选计算综合得分
    3. 按得分降序排列（高分优先尝试）
    """

    def __init__(self, markov_order=2):
        self.markov = MarkovScorer(order=markov_order)
        self.pcfg = PCFGAnalyzer()
        self.trained = False

    def train_from_files(self, file_paths):
        """从多个密码文件训练模型"""
        all_passwords = []
        for fpath in file_paths:
            fpath = Path(fpath)
            if fpath.exists():
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    passwords = [line.strip() for line in f if line.strip() and len(line.strip()) >= 8]
                all_passwords.extend(passwords)
                print(f"    训练语料: {fpath.name} ({len(passwords)} 条)")

        if not all_passwords:
            print(f"{YELLOW}[!] 无训练语料，将使用内置模型{RESET}")
            self._train_builtin()
            return

        print(f"    总训练样本: {len(all_passwords)} 条")
        self.markov.train(all_passwords)
        self.pcfg.train(all_passwords)
        self.trained = True

        # 输出结构分析结果
        print()
        print(f"    {CYAN}密码结构分析 (Top 10):{RESET}")
        for struct, count in self.pcfg.get_top_structures(10):
            pct = count / self.pcfg.total * 100
            print(f"      {struct:<15} {count:>6} ({pct:5.1f}%)")

    def _train_builtin(self):
        """使用内置的基础语料训练"""
        # 内置的典型中国WiFi密码模式样本
        builtin = [
            "12345678", "123456789", "1234567890", "88888888", "00000000",
            "11111111", "66666666", "99999999", "87654321", "12341234",
            "woaini520", "woaini1314", "woaini123", "iloveyou",
            "qwerty123", "1qaz2wsx", "password", "admin123",
            "abc12345", "a12345678", "zhang1990", "wang1234",
            "13800138000", "13912345678", "15012345678",
            "19901225", "19951001", "20001231", "52013140",
            "asd123456", "qwe123456", "zxc123456",
        ]
        self.markov.train(builtin)
        self.pcfg.train(builtin)
        self.trained = True

    def score_password(self, password):
        """
        计算密码的综合评分
        返回：(总分, Markov分数, PCFG分数, 中国特征加分)
        """
        if not self.trained:
            self._train_builtin()

        markov_score = self.markov.score(password)
        pcfg_prob = self.pcfg.get_structure_prob(password)
        cn_boost = ChinesePasswordBooster.boost_score(password)

        # PCFG概率取对数并归一化
        pcfg_log = math.log(pcfg_prob) if pcfg_prob > 0 else -20.0

        # 综合得分 = Markov归一化分数 + PCFG对数概率 + 中国特征加分的对数
        total = markov_score + pcfg_log * 0.3 + math.log(cn_boost)

        return total, markov_score, pcfg_log, cn_boost

    def rank_wordlist(self, input_path, output_path=None, top_n=None):
        """
        对字典文件进行智能排序

        参数:
            input_path: 输入字典路径
            output_path: 输出排序后的字典路径（默认覆盖原文件同目录生成 _ranked 文件）
            top_n: 只保留前N个（默认全部保留）
        """
        input_path = Path(input_path)
        if not input_path.exists():
            print(f"{RED}[!] 字典不存在: {input_path}{RESET}")
            return None

        # 读取字典
        print(f"[*] 读取字典: {input_path}")
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

        total = len(passwords)
        print(f"[*] 字典规模: {total:,} 条")

        if total == 0:
            print(f"{RED}[!] 字典为空{RESET}")
            return None

        # 评分
        print(f"[*] 正在评分排序（Markov + PCFG + 中国特征）...")
        scored = []
        for i, pwd in enumerate(passwords):
            if (i + 1) % 50000 == 0:
                pct = (i + 1) / total * 100
                sys.stdout.write(f"\r    进度: {i + 1:,}/{total:,} ({pct:.1f}%)")
                sys.stdout.flush()
            score = self.score_password(pwd)[0]
            scored.append((score, pwd))

        if total >= 50000:
            print()

        # 按分数降序排列（高分 = 高概率 = 优先尝试）
        scored.sort(key=lambda x: x[0], reverse=True)

        if top_n and top_n < len(scored):
            scored = scored[:top_n]
            print(f"[*] 保留前 {top_n:,} 条")

        # 输出
        if output_path is None:
            stem = input_path.stem
            output_path = input_path.parent / f"{stem}_ranked.txt"
        else:
            output_path = Path(output_path)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for _, pwd in scored:
                f.write(pwd + "\n")

        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"{GREEN}[+] 排序完成: {output_path}{RESET}")
        print(f"[+] 总计: {len(scored):,} 条 ({size_mb:.2f} MB)")

        # 显示Top20
        print()
        print(f"    {CYAN}排序后 Top 20（最可能的密码）:{RESET}")
        for i, (score, pwd) in enumerate(scored[:20], 1):
            patterns = ChinesePasswordBooster.get_matched_patterns(pwd)
            tags = " ".join(f"[{name}]" for name, _ in patterns)
            struct = PCFGAnalyzer.get_structure(pwd)
            print(f"      {i:>3}. {pwd:<20} 分数:{score:>7.2f}  结构:{struct:<10} {tags}")

        return output_path


# ============================================================
# 自动发现训练语料
# ============================================================
def find_training_files():
    """自动发现项目中可用的训练语料"""
    candidates = [
        ONLINE_DIR / "chinese_top10000.txt",
        ONLINE_DIR / "chinese_top100000.txt",
        ONLINE_DIR / "chinese_top1000.txt",
        ONLINE_DIR / "chinese_weak1000.txt",
        ONLINE_DIR / "seclists_wpa_top4800.txt",
        ONLINE_DIR / "seclists_wpa_top447.txt",
    ]
    found = [f for f in candidates if f.exists()]
    return found


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="智能密码排序器 v1.0 (Markov + PCFG + 中国特征)"
    )
    parser.add_argument("wordlist", help="待排序的字典文件路径")
    parser.add_argument("-o", "--output", help="输出路径（默认生成 _ranked 后缀文件）")
    parser.add_argument("-n", "--top", type=int, help="只保留前N条高概率密码")
    parser.add_argument("--order", type=int, default=2, help="Markov阶数（默认2）")
    parser.add_argument("--train", nargs="*", help="额外训练语料文件路径")
    parser.add_argument("--score", type=str, help="评估单个密码的得分")
    args = parser.parse_args()

    print(f"{BOLD}{'=' * 55}")
    print(f"  智能密码排序器 v1.0")
    print(f"  算法: Markov链 + PCFG结构 + 中国密码特征")
    print(f"{'=' * 55}{RESET}")
    print()

    # 构建排序器
    ranker = PasswordRanker(markov_order=args.order)

    # 训练
    print("[1/2] 训练概率模型...")
    training_files = find_training_files()
    if args.train:
        training_files.extend([Path(f) for f in args.train])

    if training_files:
        ranker.train_from_files(training_files)
    else:
        print(f"    {YELLOW}未找到训练语料，使用内置模型{RESET}")
        ranker._train_builtin()

    # 单密码评分模式
    if args.score:
        print()
        total, markov, pcfg, cn = ranker.score_password(args.score)
        print(f"[*] 密码: {args.score}")
        print(f"    Markov分数:   {markov:.4f}")
        print(f"    PCFG分数:     {pcfg:.4f}")
        print(f"    中国特征加分: {cn:.2f}x")
        print(f"    综合得分:     {total:.4f}")
        struct = PCFGAnalyzer.get_structure(args.score)
        print(f"    密码结构:     {struct}")
        patterns = ChinesePasswordBooster.get_matched_patterns(args.score)
        if patterns:
            print(f"    匹配模式:     {', '.join(name for name, _ in patterns)}")
        return

    # 排序字典
    print()
    print("[2/2] 排序字典...")
    ranker.rank_wordlist(args.wordlist, args.output, args.top)


if __name__ == "__main__":
    main()
