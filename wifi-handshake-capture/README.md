# WiFi握手包捕获工具 - Windows独立版

Windows 交互式握手包/PMKID捕获工具，扫描WiFi → 选择目标 → 一键捕获 → 输出 hashline

> 仅限授权安全测试使用，请遵守当地法律法规。

## 功能

- **交互式CLI** — 菜单驱动，扫描→选择→捕获一条龙
- **双引擎捕获** — netsh trace ETW（无需第三方库）+ Scapy+Npcap（可选）
- **PMKID捕获** — 只需一次连接尝试，不需要反复断网
- **EAPoL握手包** — 从ETW跟踪中提取M1+M2握手包
- **批量捕获** — 一键扫描并捕获所有WPA/WPA2网络
- **输出.22000** — 直接输出hashcat兼容的hashline格式
- **剪贴板复制** — 捕获成功后自动复制hashline到剪贴板
- **打包为EXE** — PyInstaller一键打包，下载即用

## 快速开始

### 方式A：直接运行Python

```bash
# 以管理员身份打开CMD
python capture.py
```

### 方式B：打包为EXE后运行

```bash
# 在Windows上运行build.bat
build.bat

# 生成的EXE在dist/目录
# 右键 → 以管理员身份运行
dist\WiFi握手包捕获.exe
```

## 使用流程

```
1. 扫描附近WiFi（自动列出所有网络）
2. 输入编号选择目标（支持多选）
3. 自动捕获PMKID/握手包
4. 输出hashline（自动复制到剪贴板）
5. 将hashline粘贴到hashcat或云端破解
```

## 捕获原理

### netsh trace ETW（方式A，推荐）

1. 启动 Windows 网络跟踪（`netsh trace start capture=yes`）
2. 用随机密码连接目标AP，触发EAPoL交换
3. 停止跟踪，从ETL文件中提取PMKID或M1+M2握手包
4. 生成hashcat 22000格式hashline

### Scapy + Npcap（方式B，可选）

1. 用Scapy嗅探EAPoL帧（需要Npcap）
2. 同时触发EAPoL交换
3. 从捕获的帧中提取PMKID

## 系统要求

| 要求 | 说明 |
|-----|------|
| 操作系统 | Windows 10/11 |
| 权限 | **管理员权限**（netsh trace需要） |
| Python | 3.8+（如果不用EXE） |
| Npcap | 可选（方式B需要，下载: https://npcap.com） |

## 文件说明

```
wifi-handshake-capture/
├── capture.py          # 主程序（交互式CLI）
├── build.bat           # 一键打包为EXE
├── requirements.txt    # Python依赖
├── captures/           # 捕获输出目录（自动创建）
└── README.md           # 本文件
```

## 输出格式

捕获成功后输出 hashcat 22000 格式的 hashline：

**PMKID格式**：
```
WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX***
```

**EAPoL握手包格式**：
```
WPA*02*MIC*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*EAPOL*MP
```

## 后续破解

捕获到hashline后，可以用以下方式破解：

```bash
# Mac本地破解
cd wifi-crack-mac && bash crack-local.sh

# 云服务器破解
cd wifi-crack-cloud && bash crack.sh

# Kaggle免费GPU破解
# 将hashline粘贴到Notebook的RAW_PASTE中

# 直接用hashcat
hashcat -m 22000 hashes.22000 -a 3 '?d?d?d?d?d?d?d?d' -w 3 -O
```

## License

MIT
