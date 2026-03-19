# WiFi Cracker v3.0 Windows 版

Windows 专用 WiFi 安全测试工具，基于 Python + pywifi + netsh trace + hashcat GPU。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 核心特性

- **握手包捕获（无需监控模式）** — 利用 netsh trace ETW 捕获 EAPoL 握手包，不需要特殊网卡
- **hashcat GPU离线破解** — NVIDIA CUDA 加速，14万条字典不到2秒跑完
- **全球WiFi密码库** — 对接 3wifi.dev 开放数据库（数千万条记录）
- **中国定制字典** — 14万条高命中率密码（生日、手机号、吉利数字、键盘模式等）
- **双引擎WiFi扫描** — pywifi + netsh 合并结果，覆盖更全
- **系统密码提取** — 读取 Windows 已保存的所有 WiFi 密码
- **UAC自动提权** — 需要管理员权限时自动请求
- **WiFi自动恢复** — 操作后自动恢复原连接
- **下载即用** — hashcat 预置在项目目录，无需额外安装

## 智能攻击流程（Phase 0-5）

```
Phase 0（秒级）    系统已保存密码检查（不断网）
Phase 1（秒级）    p3wifi 全球密码库查询（不断网）
Phase 2（秒级）    TOP密码快速验证（断网，约70条）
Phase 3（秒级）    握手包捕获（断网1次，netsh trace ETW）
Phase 4（秒~分钟） hashcat GPU破解（不断网）
                     ├─ 4a: 字典攻击（14万条，<2秒）
                     └─ 4b: 掩码暴力（8位纯数字等）
Phase 5（兜底）    在线字典爆破（断网，逐个密码尝试连接）
                     ├─ 5a: 中国高频密码（5000条）
                     └─ 5b: 完整字典（最多1万条）
```

## 使用方法

```bash
# 扫描附近WiFi
python wifi_crack.py --scan

# PMKID/握手包模式（推荐，自动提权，只断网1次）
python wifi_crack.py --pmkid
python wifi_crack.py --pmkid -t "目标SSID"

# 完整智能攻击（Phase 0-5全流程）
python wifi_crack.py
python wifi_crack.py -t "TP-LINK_XXXX"

# 查看系统已保存的WiFi密码（需管理员）
python wifi_crack.py --show-passwords

# hashcat独立破解（已有.22000哈希文件）
python wifi_crack.py --hashcat --hash captures/xxx.22000
python wifi_crack.py --hashcat --hash captures/xxx.22000 --mask
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `-t` | 指定目标SSID |
| `-d` | 外部字典文件路径 |
| `--delay` | 在线爆破间隔（毫秒，默认200） |
| `--scan` | 仅扫描不爆破 |
| `--pmkid` | PMKID/握手包捕获模式（推荐，自动管理员提权） |
| `--hashcat` | hashcat GPU独立破解模式 |
| `--hash` | hashcat哈希文件路径（.22000） |
| `--mask` | 仅掩码暴力攻击 |
| `--show-passwords` | 显示系统已保存WiFi密码 |
| `--no-pywifi` | 不使用pywifi引擎，仅用netsh |

## 项目结构

```
wifi-crack-windows/
├── wifi_crack.py          # 主程序（智能攻击编排 + PMKID模式）
├── wifi_scanner.py        # WiFi扫描/连接（pywifi + netsh 双引擎）
├── pmkid_capture.py       # 握手包/PMKID捕获（netsh trace ETW）
├── p3wifi_client.py       # 全球WiFi密码库（3wifi.dev API）
├── dict_generator.py      # 中国定制字典生成器（14万条）
├── hashcat_crack.py       # hashcat GPU离线破解
├── hashcat-6.2.6/         # hashcat v6.2.6（预置，下载即用）
├── captures/              # 握手包/哈希文件输出目录
├── wpa-sec-cracked.txt    # wpa-sec全球社区破解字典
├── requirements.txt       # Python依赖
└── README.md
```

## 系统要求

| 要求 | 说明 |
|------|------|
| 操作系统 | Windows 10/11 |
| Python | 3.8+ |
| WiFi网卡 | 任意（不需要监控模式） |
| GPU | NVIDIA（CUDA）推荐，AMD（OpenCL）可用 |
| 管理员权限 | 握手包捕获需要（自动请求） |

## 与 macOS 版的区别

| 功能 | macOS 版 (Go) | Windows 版 (Python) |
|------|--------------|-------------------|
| WiFi扫描 | CoreWLAN (CGO) | pywifi + netsh |
| 握手包捕获 | tcpdump -I 监控模式 | **netsh trace ETW（无需监控模式）** |
| deauth攻击 | bettercap | 不支持（Intel网卡限制） |
| GPU后端 | Metal (M1, ~52K H/s) | CUDA (GTX1650Ti, ~12K H/s) |
| 系统密码 | Keychain | netsh show profile |
| 部署方式 | go build 编译 | 下载即用（hashcat预置） |

## License

MIT
