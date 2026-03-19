#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashcat GPU离线破解模块
支持: 字典攻击、掩码攻击、规则攻击
Windows上使用NVIDIA CUDA / AMD OpenCL后端
"""

import subprocess
import os
import re
import time
import shutil
from typing import Optional, List, Tuple
from dataclasses import dataclass, field


@dataclass
class HashcatResult:
    """破解结果"""
    success: bool = False
    password: str = ""
    attack: str = ""       # 攻击类型描述
    speed: str = ""        # 破解速度
    duration: float = 0    # 耗时(秒)
    error: str = ""


@dataclass
class HashcatConfig:
    """hashcat配置"""
    hash_file: str = ""           # .22000哈希文件
    wordlists: List[str] = field(default_factory=list)   # 字典文件列表
    mask_attacks: List[str] = field(default_factory=list) # 掩码列表
    rules: List[str] = field(default_factory=list)        # 规则文件列表
    timeout: int = 2400           # 超时(秒)，默认40分钟
    workload: int = 3             # 工作负载 1-4
    optimized: bool = True        # 使用优化内核
    verbose: bool = True
    pot_file: str = ""            # 已破解密码存储


def find_hashcat() -> Optional[str]:
    """查找hashcat可执行文件路径"""
    # 0. 本项目目录下的hashcat（预置）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for item in os.listdir(script_dir):
        if item.lower().startswith("hashcat") and os.path.isdir(os.path.join(script_dir, item)):
            candidate = os.path.join(script_dir, item, "hashcat.exe")
            if os.path.exists(candidate):
                return candidate

    # 1. PATH中查找
    path = shutil.which("hashcat")
    if path:
        return path

    # 2. 常见安装位置
    common_paths = [
        r"C:\hashcat\hashcat.exe",
        r"C:\Program Files\hashcat\hashcat.exe",
        r"C:\Tools\hashcat\hashcat.exe",
        os.path.expanduser(r"~\Desktop\hashcat\hashcat.exe"),
        os.path.expanduser(r"~\Downloads\hashcat\hashcat.exe"),
    ]

    # 搜索hashcat-*目录
    for base in [r"C:\\", os.path.expanduser("~\\Desktop"),
                 os.path.expanduser("~\\Downloads")]:
        if os.path.exists(base):
            try:
                for item in os.listdir(base):
                    if item.lower().startswith("hashcat"):
                        candidate = os.path.join(base, item, "hashcat.exe")
                        if os.path.exists(candidate):
                            return candidate
            except:
                pass

    for p in common_paths:
        if os.path.exists(p):
            return p

    return None


def check_hashcat() -> Tuple[bool, str]:
    """检查hashcat是否可用"""
    path = find_hashcat()
    if not path:
        return False, "hashcat未安装 (下载: https://hashcat.net/hashcat/)"

    try:
        result = subprocess.run(
            [path, '--version'],
            capture_output=True, text=True, timeout=10
        )
        version = result.stdout.strip()
        return True, f"hashcat {version} ({path})"
    except Exception as e:
        return False, f"hashcat执行失败: {e}"


def benchmark() -> Tuple[int, str]:
    """
    hashcat WPA基准测试
    返回: (速度H/s, 信息)
    """
    path = find_hashcat()
    if not path:
        return 0, "hashcat未找到"

    try:
        result = subprocess.run(
            [path, '-b', '-m', '22000', '--machine-readable'],
            capture_output=True, text=True, timeout=120
        )

        # 解析速度
        for line in result.stdout.split('\n'):
            if '22000' in line and 'HASH_TYPE' not in line:
                parts = line.strip().split(':')
                for part in parts:
                    try:
                        speed = int(float(part))
                        if speed > 100:
                            return speed, f"GPU速度: {speed} H/s"
                    except:
                        continue

        # 尝试从非machine-readable输出解析
        speed_match = re.search(r'(\d+\.?\d*)\s*[kKmM]?H/s', result.stdout)
        if speed_match:
            speed_str = speed_match.group(0)
            speed_val = float(speed_match.group(1))
            if 'k' in speed_str.lower():
                speed_val *= 1000
            elif 'm' in speed_str.lower():
                speed_val *= 1000000
            return int(speed_val), f"GPU速度: {speed_str}"

        return 0, "基准测试完成但无法解析速度"

    except subprocess.TimeoutExpired:
        return 0, "基准测试超时"
    except Exception as e:
        return 0, f"基准测试失败: {e}"


def _hashcat_cwd() -> Optional[str]:
    """获取hashcat所在目录（hashcat必须在自己的目录下运行才能找到OpenCL内核）"""
    path = find_hashcat()
    if path:
        return os.path.dirname(os.path.abspath(path))
    return None


def crack_with_dict(config: HashcatConfig) -> HashcatResult:
    """hashcat字典攻击 (attack mode 0)"""
    path = find_hashcat()
    if not path:
        return HashcatResult(error="hashcat未找到")

    if not config.hash_file or not os.path.exists(config.hash_file):
        return HashcatResult(error=f"哈希文件不存在: {config.hash_file}")

    if not config.wordlists:
        return HashcatResult(error="未指定字典文件")

    hashcat_dir = _hashcat_cwd()
    abs_hash = os.path.abspath(config.hash_file)
    start = time.time()

    for wordlist in config.wordlists:
        if not os.path.exists(wordlist):
            continue
        abs_wl = os.path.abspath(wordlist)

        cmd = [
            path,
            '-m', '22000',
            '-a', '0',
            '-w', str(config.workload),
            '--quiet',
            '--potfile-disable',
        ]

        if config.optimized:
            cmd.append('-O')

        cmd.extend([abs_hash, abs_wl])

        for rule in config.rules:
            if os.path.exists(rule):
                cmd.extend(['-r', os.path.abspath(rule)])

        if config.verbose:
            print(f"    [hashcat] 字典攻击: {os.path.basename(wordlist)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=config.timeout, cwd=hashcat_dir
            )

            password = _extract_password(result.stdout, config.hash_file)
            if password:
                duration = time.time() - start
                return HashcatResult(
                    success=True,
                    password=password,
                    attack=f"字典攻击({os.path.basename(wordlist)})",
                    duration=duration,
                )

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            if config.verbose:
                print(f"    [hashcat] 错误: {e}")

    duration = time.time() - start
    return HashcatResult(
        error="字典攻击未命中",
        duration=duration,
        attack="字典攻击",
    )


def crack_with_mask(config: HashcatConfig) -> HashcatResult:
    """hashcat掩码攻击 (attack mode 3)"""
    path = find_hashcat()
    if not path:
        return HashcatResult(error="hashcat未找到")

    if not config.hash_file or not os.path.exists(config.hash_file):
        return HashcatResult(error=f"哈希文件不存在: {config.hash_file}")

    masks = config.mask_attacks if config.mask_attacks else get_smart_masks()
    hashcat_dir = _hashcat_cwd()
    abs_hash = os.path.abspath(config.hash_file)

    start = time.time()

    for mask in masks:
        cmd = [
            path,
            '-m', '22000',
            '-a', '3',
            '-w', str(config.workload),
            '--quiet',
            '--potfile-disable',
        ]

        if config.optimized:
            cmd.append('-O')

        cmd.extend([abs_hash, mask])

        if config.verbose:
            print(f"    [hashcat] 掩码攻击: {mask}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=config.timeout, cwd=hashcat_dir
            )

            password = _extract_password(result.stdout, config.hash_file)
            if password:
                duration = time.time() - start
                return HashcatResult(
                    success=True,
                    password=password,
                    attack=f"掩码攻击({mask})",
                    duration=duration,
                )

        except subprocess.TimeoutExpired:
            if config.verbose:
                print(f"    [hashcat] 掩码 {mask} 超时")
        except Exception as e:
            if config.verbose:
                print(f"    [hashcat] 错误: {e}")

    duration = time.time() - start
    return HashcatResult(
        error="掩码攻击未命中",
        duration=duration,
        attack="掩码攻击",
    )


def crack_all(config: HashcatConfig) -> HashcatResult:
    """依次执行字典攻击和掩码攻击"""
    # 先字典
    if config.wordlists:
        result = crack_with_dict(config)
        if result.success:
            return result

    # 再掩码
    result = crack_with_mask(config)
    return result


def get_smart_masks() -> List[str]:
    """
    智能掩码列表（按概率从高到低、耗时从短到长排序）
    GTX 1650 Ti 约 100K-150K H/s（比M1 Metal快2-3倍）
    """
    return [
        # 优先级1: 生日格式（约200万组合，约15秒）
        "19?d?d?d?d?d?d",         # 199XMMDD
        "20?d?d?d?d?d?d",         # 200XMMDD
        # 优先级2: 1开头的8位（手机号后8位等，1000万组合，约1.5分钟）
        "1?d?d?d?d?d?d?d",
        # 优先级3: 完整8位纯数字（1亿组合，约15分钟）
        "?d?d?d?d?d?d?d?d",
        # 优先级4: 常见前缀+数字（各约2.6亿组合）
        "?l?d?d?d?d?d?d?d",       # 小写字母+7位数字
        "?d?d?d?d?d?d?d?d?d",     # 9位纯数字（10亿，约2.5小时）
    ]


def _extract_password(output: str, hash_file: str) -> Optional[str]:
    """从hashcat输出中提取破解到的密码"""
    # hashcat --quiet 模式下成功时输出格式:
    # WPA*02*...*...:password
    # 即哈希行后跟冒号和密码
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 必须以WPA*开头才是有效的破解结果行
        if line.startswith('WPA*') and ':' in line:
            # 最后一个冒号后面是密码
            password = line.rsplit(':', 1)[-1].strip()
            if password and 8 <= len(password) <= 63:
                return password

    # 尝试从 --show 获取（用pot文件中的记录）
    path = find_hashcat()
    hashcat_dir = _hashcat_cwd()
    if path and os.path.exists(hash_file):
        try:
            abs_hash = os.path.abspath(hash_file)
            result = subprocess.run(
                [path, '-m', '22000', '--show', abs_hash],
                capture_output=True, text=True, timeout=10,
                cwd=hashcat_dir
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('WPA*') and ':' in line:
                    password = line.rsplit(':', 1)[-1].strip()
                    if password and 8 <= len(password) <= 63:
                        return password
        except:
            pass

    return None


def generate_wordlist(passwords: List[str], output_dir: str) -> Optional[str]:
    """生成临时字典文件"""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "wifi_crack_wordlist.txt")
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(passwords) + '\n')
        return path
    except Exception:
        return None
