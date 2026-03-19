# WiFi Security Toolkit v3.0

全平台 WiFi 安全测试工具集，支持 macOS / Windows / 云服务器(腾讯云) / Kaggle，集成全球密码库 + 智能攻击编排 + hashcat GPU 加速。

> **声明**: 仅限授权安全测试和网络安全学习使用，请遵守当地法律法规。未经授权访问他人网络属违法行为。

## 项目概览

本项目提供三套独立的 WiFi 安全测试方案，覆盖不同操作系统和使用场景：

| 方案 | 目录 | 技术栈 | 适用场景 |
|-----|------|--------|---------|
| **macOS 版** | `wifi-crack-mac/` | Go + CoreWLAN + hashcat Metal | Mac 用户，Apple Silicon GPU 加速 |
| **Windows 版** | `wifi-crack-windows/` | Python + pywifi + netsh + hashcat CUDA | Windows 用户，NVIDIA GPU 加速 |
| **Notebook 版** | `wifi-crack-notebook/` | Jupyter + Kaggle 免费 GPU | 无本地 GPU，利用云端免费算力 |
| **云服务器版** | `wifi-crack-cloud/` | Bash + hashcat CUDA | 腾讯云/阿里云 GPU 服务器一键破解 |
| **握手包捕获工具** | `wifi-handshake-capture/` | Python + netsh/Scapy | Windows交互式捕获，可打包EXE |
| **Python 跨平台版** | `wifi-crack-python/` | Python + pywifi + GUI | 跨平台图形界面，来源 wlan-sec-test-tool |

## 核心功能

- **全球 WiFi 密码库** — 对接 3wifi.dev 开放数据库（数千万条记录），BSSID 直查密码
- **智能攻击编排** — 自动分 5 阶段递进攻击，从秒级到分钟级逐步升级
- **握手包捕获** — macOS 用 tcpdump + bettercap，Windows 用 netsh trace ETW
- **hashcat GPU 破解** — macOS Metal / Windows CUDA / Kaggle T4/P100 三种 GPU 后端
- **中国定制字典** — 内置高命中率密码（生日、手机号、吉利数字、键盘模式等）
- **掩码暴力攻击** — 8 位纯数字约 20-32 分钟穷举（取决于 GPU）
- **WiFi 自动恢复** — 操作前记录当前连接，完成后自动恢复

## 三版对比

| 功能 | macOS 版 (Go) | Windows 版 (Python) | Notebook 版 (Kaggle) |
|-----|--------------|-------------------|--------------------|
| WiFi 扫描 | CoreWLAN (CGO) | pywifi + netsh 双引擎 | N/A（离线破解） |
| 握手包捕获 | tcpdump + bettercap | netsh trace ETW | N/A（需本地捕获） |
| GPU 后端 | Metal (~52K H/s) | CUDA (~12K+ H/s) | T4 (~80K) / P100 (~120K) |
| 全球密码库 | p3wifi (3wifi.dev) | p3wifi (3wifi.dev) | wpa-sec 字典 |
| 字典规模 | 5,000 条 | 140,000 条 | 750,000 条 (wpa-sec) |
| 系统密码提取 | Keychain（未实现） | netsh show profile | N/A |
| 部署方式 | `go build` 编译 | 下载即用 | Kaggle 在线运行 |

## 智能攻击流程

```
Phase 1（秒级）    全球WiFi密码库查询（3wifi.dev API）
     ↓ 未命中
Phase 2（秒级）    TOP密码快速验证（路由器默认 + 高频密码）
     ↓ 未命中
Phase 3（分钟级）  握手包捕获 + GPU字典攻击
     ↓ 未命中
Phase 4（32分钟）  GPU掩码暴力攻击（8位纯数字起步）
     ↓ 未命中
Phase 5（兜底）    在线完整字典爆破
```

## 快速开始

### macOS 用户

```bash
cd wifi-crack-mac
go build -o wifi-crack .
./wifi-crack           # 智能攻击模式
./wifi-crack --scan    # 仅扫描
```

详见 → [wifi-crack-mac/README.md](wifi-crack-mac/README.md)

### Windows 用户

```bash
cd wifi-crack-windows
pip install -r requirements.txt
python wifi_crack.py          # 智能攻击模式
python wifi_crack.py --pmkid  # PMKID模式（推荐）
```

详见 → [wifi-crack-windows/README.md](wifi-crack-windows/README.md)

### Kaggle 云端 GPU

1. 上传 `.22000` 握手包文件到 Kaggle Dataset
2. 上传 `wifi-crack-notebook/kaggle-hashcat-wifi-crack.ipynb`
3. 开启 GPU 加速器，运行全部 Cell

详见 → [wifi-crack-notebook/README.md](wifi-crack-notebook/README.md)

### 云服务器（腾讯云/阿里云）

```bash
# 上传到服务器后一键运行
cd wifi-crack-cloud
bash crack.sh handshake.22000    # 指定.22000文件
bash crack.sh                    # 交互式粘贴hashline
```

详见 → [wifi-crack-cloud/README.md](wifi-crack-cloud/README.md)

### Python 跨平台 GUI 版

```bash
cd wifi-crack-python
pip install -r requirements.txt
python wlan_sec_test_tool_gui.py   # 图形界面
python wlan_sec_test_tool.py       # 命令行
```

详见 → [wifi-crack-python/README.md](wifi-crack-python/README.md)

## hashcat GPU 性能对比

| GPU | WPA 速度 | 8位数字耗时 | 9位数字耗时 |
|-----|---------|-----------|-----------|
| Kaggle P100 | ~120,000 H/s | ~14 分钟 | ~2.3 小时 |
| Kaggle T4 | ~80,000 H/s | ~20 分钟 | ~3.5 小时 |
| Apple M1 Metal | ~52,000 H/s | ~32 分钟 | ~5.3 小时 |
| NVIDIA GTX 1650Ti | ~12,000 H/s | ~2.3 小时 | ~23 小时 |

## 在线密码数据源

| 数据源 | 类型 | 状态 | 说明 |
|-------|------|------|-----|
| 3wifi.dev API | BSSID 查密码 | ✅ 可用 | 全球数千万条，无需认证 |
| wpa-sec 字典 | 已破解密码下载 | ✅ 可用 | 全球社区 GPU 破解的真实密码 |
| 万能钥匙 | 中国密码库 | ❌ 已废弃 | appId 封禁，保留优雅降级 |

## 项目结构

```
wifi-security-toolkit/
│
├── wifi-crack-mac/                   # macOS版（Go + CoreWLAN + hashcat Metal）
│   ├── main.go                       #   主程序入口（智能攻击编排）
│   ├── go.mod                        #   Go模块定义
│   ├── internal/                     #   核心模块
│   │   ├── scanner/                  #     WiFi扫描/连接（CGO + CoreWLAN）
│   │   ├── cracker/                  #     在线爆破引擎
│   │   ├── capture/                  #     握手包捕获（tcpdump + bettercap）
│   │   ├── hashcrack/                #     hashcat GPU破解
│   │   ├── p3wifi/                   #     全球密码库（3wifi.dev API）
│   │   ├── dict/                     #     中国定制字典生成器
│   │   └── masterkey/                #     [已废弃] 万能钥匙API
│   ├── HARDWARE_REPORT.md            #   M1硬件能力评估报告
│   └── README.md                     #   macOS版说明文档
│
├── wifi-crack-windows/               # Windows版（Python + pywifi + netsh + hashcat）
│   ├── wifi_crack.py                 #   主程序（智能攻击编排 + PMKID模式）
│   ├── wifi_scanner.py               #   WiFi扫描/连接（pywifi + netsh双引擎）
│   ├── pmkid_capture.py              #   握手包/PMKID捕获（netsh trace ETW）
│   ├── p3wifi_client.py              #   全球密码库（3wifi.dev API）
│   ├── dict_generator.py             #   中国定制字典生成器（14万条）
│   ├── hashcat_crack.py              #   hashcat GPU破解
│   ├── requirements.txt              #   Python依赖
│   └── README.md                     #   Windows版说明文档
│
├── wifi-crack-notebook/              # Notebook版（Kaggle免费GPU破解）
│   ├── kaggle-hashcat-wifi-crack.ipynb  # Kaggle GPU破解笔记本
│   └── README.md                     #   Notebook版说明文档
│
├── wifi-crack-cloud/                 # 云服务器版（腾讯云/阿里云一键破解）
│   ├── crack.sh                      #   一键破解脚本（安装+字典+9轮攻击）
│   └── README.md                     #   云服务器版说明文档
│
├── wifi-crack-python/                # Python跨平台版（GUI图形界面）
│   ├── wlan_sec_test_tool.py         #   跨平台WiFi安全测试主程序
│   ├── wlan_sec_test_tool_gui.py     #   GUI图形界面版本
│   ├── wifi_macos.py                 #   macOS专用WiFi模块
│   ├── requirements.txt              #   Python依赖
│   └── README.md                     #   跨平台版说明文档
│
├── generate_dict.py                  # 密码字典生成器（50万+条）
├── .gitignore
└── README.md                         # 本文件（项目总览）
```

## 密码字典生成器

项目附带独立的密码字典生成器，可生成 50 万+ 条去重密码：

```bash
python generate_dict.py
# 输出 wifi_dict.txt（约 20MB）
```

**字典内容按优先级排列**：纯数字高频模式 → 手机号 → 情感数字 → 弱口令 → 键盘模式 → 拼音组合 → 扩展变体

## 技术栈总览

| 模块 | macOS | Windows | Notebook |
|-----|-------|---------|----------|
| WiFi 扫描 | CGO + CoreWLAN | pywifi + netsh | N/A |
| WiFi 连接 | CoreWLAN | pywifi | N/A |
| 全球密码库 | 3wifi.dev API | 3wifi.dev API | wpa-sec |
| 握手包捕获 | tcpdump + bettercap | netsh trace ETW | N/A |
| GPU 破解 | hashcat Metal | hashcat CUDA | hashcat CUDA |
| 密码字典 | Go 内置生成 | Python 14万条 | wpa-sec 75万条 |

## v3.0 更新日志

- **项目重构** — 分离为 macOS / Windows / Notebook / Python 四个独立模块
- **智能攻击编排器** — 5 阶段递进攻击（密码库 → TOP 验证 → 握手捕获 → GPU 破解 → 兜底）
- **全球 WiFi 密码库** — 对接 3wifi.dev 开放 API（数千万条记录）
- **Kaggle GPU 支持** — 免费 T4/P100 云端破解，无需本地 GPU
- **握手包捕获** — macOS tcpdump + bettercap / Windows netsh trace ETW
- **hashcat GPU 破解** — Metal / CUDA 多后端支持
- **交互式 WiFi 选择** — 单选/多选/范围/全选
- **WiFi 接口自动恢复** — 监控模式结束后自动恢复

## 免责声明

本项目所涉及的技术、思路和工具仅供学习交流以及合法合规的安全技术研究。

**合法使用场景**：
- 学术研究与安全教学
- 已获得明确书面授权的渗透测试
- 测试个人完全拥有并控制的网络设备

**任何超出上述范围的用途均可构成违法行为，使用者需自行承担全部法律责任。**

相关法律：《中华人民共和国网络安全法》《刑法》第 285、286 条

## License

MIT
