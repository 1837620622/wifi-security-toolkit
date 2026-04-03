# WiFi Security Toolkit — WiFi 安全测试工具包

基于 Kali Linux + Scapy + hashcat 的 WPA/WPA2 WiFi 安全测试全流程工具包

覆盖**抓包 → 字典 → 规则 → 掩码 → 混合 → 组合**六大攻击维度，专为中国 WiFi 密码习惯深度优化

## 功能特点

- **Scapy 原始帧注入** — 绕过 aireplay-ng 在部分网卡上的兼容性问题
- **全自动 Deauth + Disassoc 攻击** — 爆发+静默双模式，自动检测 EAPOL 四次握手
- **Mac 本地 GPU 破解脚本 v6.0** — 10 阶段递进攻击，73+ 次独立攻击调用，零重复密码空间
- **中国 WiFi 密码深度优化** — 基于 CERNET 48330 样本研究 + 阿里云 TOP10 + 曹操WiFi 字典研究
- **20+ 字典文件，2.2GB 总量** — 从 4800 条高频到 1.6 亿条超大字典全覆盖
- **616 条 hashcat 规则（36 层）** — Leet Speak、手机号前缀、年份后缀、键盘走位等
- **137 条掩码模式（A-W 区）** — 纯数字、字母+数字、特殊字符、QQ号、手机号变体等
- **Kaggle 云端免费 GPU 破解方案** — 适合无独立 GPU 的用户

## 项目结构

```
wifi-security-toolkit/
├── wifi-crack-kali/                    # Kali Linux 攻击+抓包工具
│   ├── auto_attack.py                  # 全自动攻击脚本（Scapy 单终端）
│   ├── 1_scan.sh                       # 终端1: 扫描 WiFi
│   ├── 2_capture.sh                    # 终端2: airodump-ng 抓包
│   ├── 3_deauth.sh                     # 终端3: Scapy deauth 攻击
│   └── generate_cn_dict.py             # 中国 WiFi 密码字典生成器
├── wifi-crack-notebook/                # 本地/云端 GPU 破解
│   ├── crack_local.sh                  # Mac 本地 GPU 破解脚本 v6.0 (791行)
│   ├── kaggle-hashcat-wifi-crack.ipynb # Kaggle 云端破解笔记本
│   ├── monitor.sh                      # hashcat 进度监控脚本
│   ├── dicts/                          # 字典+规则+掩码库
│   │   ├── china-wifi.rule             # 中国WiFi专用规则 (616条/36层)
│   │   ├── 00-china-wifi-masks.hcmask  # 中国WiFi专用掩码 (137条/A-W区)
│   │   ├── wpa-top4800.txt             # WPA 高频 TOP4800
│   │   ├── cn-top100w.txt              # 中国 TOP 100万密码
│   │   ├── 08-names-pinyin.txt         # 姓名拼音字典 (10MB)
│   │   ├── 06-surnames-birthdays.txt   # 姓氏+生日组合 (120MB)
│   │   └── ... (共23个文件, 2.2GB)
│   ├── captures/                       # .hc22000 握手包目录
│   └── work/                           # hashcat 工作目录
├── .gitignore
└── README.md
```

## 破解脚本攻击流程（10 阶段）

`crack_local.sh` 采用从快到慢、从高命中到低命中的递进策略：

| 阶段 | 攻击方式 | 说明 |
|------|----------|------|
| 1 | SSID 定向字典 | 基于目标 SSID 生成专属字典（含 leet 变体、年份、反转等） |
| 2 | 高命中率字典 | WPA-TOP4800、WPA-SEC、中国 TOP100 万等 |
| 3 | 规则变换 | 字典 + china-wifi.rule(616条) / best64 规则 |
| 4 | 全球大字典 | TOP2M → TOP20M → RockYou → mega160M |
| 5 | 掩码暴力 | 137 条中国专用掩码 + 增量掩码 + 自定义字符集 |
| 6 | 混合攻击 | 字典+掩码(-a 6) / 掩码+字典(-a 7)，含"."和"@"特殊字符 |
| 7 | 组合攻击 | 双字典拼接(-a 1)，姓名+数字、短词+年份等 |
| 8 | 多规则堆叠 | 同时应用两套规则文件（候选量指数级增长） |
| 9 | 随机规则 | hashcat 随机生成 100 万条规则（覆盖未知模式） |
| 10 | 结果统计 | 输出破解成功率、清理临时文件 |

## 核心优化特性

- **字典预过滤**: 纯字典攻击自动过滤 <8 位和 >63 位词条，节省 GPU 资源
- **Hybrid 智能过滤**: 根据掩码长度自动计算字典最小词长，避免生成无效候选
- **is_done 缓存**: 30 秒缓存机制，减少 hashcat --show 频繁调用开销
- **零重复保证**: 规则文件 0 重复、掩码文件 0 重复、脚本攻击调用 0 重复
- **临时文件清理**: 脚本结束自动清除 filtered_/hybrid_ 等临时文件

## 快速开始

### 环境要求

- Kali Linux（推荐 2024+ 版本）
- 支持 Monitor 模式的 USB 无线网卡（推荐 Alfa AWUS036ACH / RTL8812AU 芯片）
- Python 3 + Scapy（Kali 自带）
- hashcat v7.1.2+（Mac 端 `brew install hashcat`）

### Mac 部署步骤

1. Parallels Desktop 安装 Kali Linux ARM64
2. USB 无线网卡透传到 Kali 虚拟机
3. Kali 中将脚本复制到桌面

```bash
cp -r /media/psf/Home/Downloads/Wi-Fi破解/wifi-crack-kali ~/桌面/
```

4. Mac 安装 hashcat（GPU 破解用）

```bash
brew install hashcat
```

### Windows 部署步骤

1. VMware/VirtualBox 安装 Kali Linux
2. USB 无线网卡透传到 Kali 虚拟机
3. 将脚本复制到 Kali 中
4. Windows 安装 hashcat（从 hashcat.net 下载）

### 使用方法

#### 方式1: 全自动抓包（推荐）

```bash
# 1. 扫描找目标
sudo bash 1_scan.sh

# 2. 设置 monitor 模式
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# 3. 全自动攻击（Scapy 同时收发 + 自动检测 EAPOL）
sudo python3 auto_attack.py wlan0mon <BSSID> <频道> [客户端MAC]
```

抓到 M1+M2 握手包后自动停止，自动转换 .hc22000 并同步到 Mac

#### 方式2: Mac 本地 GPU 破解（核心功能）

```bash
# 将 .hc22000 文件放入 captures/ 目录，然后运行
cd wifi-crack-notebook
bash crack_local.sh
```

脚本自动扫描 captures/ 目录中的握手包，执行 10 阶段递进攻击

#### 方式3: Kaggle 云端 GPU 破解

1. 上传 `.hc22000` 文件到 Kaggle Dataset
2. 上传 `wifi-crack-notebook/kaggle-hashcat-wifi-crack.ipynb`
3. 开启 GPU 加速器，运行全部 Cell

## 规则文件详解（china-wifi.rule — 36 层）

| 层级 | 内容 | 示例 |
|------|------|------|
| 1-3 | 基础变换+数字后缀 | `:` `c` `l` `$1$2$3` |
| 4-5 | 特殊字符+年份后缀 | `$!` `$@` `$2$0$2$5` |
| 6 | Leet Speak | `sa@ se3 si1 so0` |
| 7-8 | 复合操作+前缀 | `c $! ` `^1^2^3` |
| 9-10 | 键盘走位+中国文化词 | `$q$w$e$r` `$w$i$f$i` |
| 11-15 | 截断、重复、插入、覆写 | `] $!` `d` `i4!` `o0!` |
| 16-23 | 日期、超级组合、反转 | `$0$8$0$8` `r $@` |
| 24-25 | "."和"@"后缀（CERNET 核心发现） | `$.` `$@$1$2$3$4` |
| 26-28 | 两位年份、弱口令、拼音后缀 | `$8$8` `$n$i$u$b$i` |
| 29-32 | 九宫格走位、前缀、超级组合 | `$1$4$7$8$5$2$3$6$9` |
| 33-36 | 手机号前缀、删除+追加、数字替换 | `^5^3^1` `s0!` |

## 技术细节

### 为什么用 Scapy 而不是 aireplay-ng

部分 USB 无线网卡（如 MediaTek MT7921U）在 aireplay-ng 下帧注入被驱动层阻止，但 Scapy 的 raw socket 方式能正常注入

### 攻击策略: 爆发+静默

- **爆发阶段（2秒）**: 发送 256 帧 Deauth+Disassoc，确保踢掉客户端
- **静默阶段（5秒）**: 完全停止发送，网卡纯监听，等待客户端重连握手
- 循环直到抓到 M1+M2 或手动 Ctrl+C

### EAPOL 握手识别

通过 Key Info 字段的 ACK/MIC/Install 位精确区分 M1/M2/M3/M4

| 消息 | 方向 | ACK | MIC | Install |
|------|------|-----|-----|---------|
| M1 | AP → Client | 1 | 0 | 0 |
| M2 | Client → AP | 0 | 1 | 0 |
| M3 | AP → Client | 1 | 1 | 1 |
| M4 | Client → AP | 0 | 1 | 0 |

### 密码研究参考

- **CERNET 论文**: 分析 48330 个真实 WiFi 密码，76% 为 8-11 位，"."和"@"为最常用特殊字符
- **阿里云 TOP10**: 前三名 12345678/123456789/88888888 覆盖 50.1% 样本
- **曹操WiFi 字典**: 姓名拼音+生日、QQ号、词语拼音、弱口令等组合模式

## 免责声明

本工具仅用于安全研究和授权的渗透测试。未经授权对他人网络进行攻击是违法行为。使用者需自行承担所有法律责任。

## 作者

- 作者: 传康Kk
- 微信: 1837620622
- 咸鱼/B站: 万能程序员
