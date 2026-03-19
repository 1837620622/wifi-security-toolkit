# WiFi Cracker v3.0 (Go + CoreWLAN + hashcat)

macOS 专用 WiFi 安全测试工具，基于 Go + CGO + CoreWLAN + hashcat GPU加速。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 功能特性

- **万能钥匙预查** — 自动查询WiFi万能钥匙密码库（多端点容错，API不可用自动降级）
- **握手包捕获** — tcpdump监控模式捕获EAPOL握手包/PMKID（适配macOS 26.3，airport已移除）
- **Deauth攻击** — 集成bettercap发送反认证帧，迫使客户端重连以捕获握手包
- **hashcat GPU破解** — Apple M1 Metal后端加速，WPA模式约52000 H/s（比在线爆破快1万倍）
- **中国定制字典** — 内置数千条高命中率密码（生日、手机号后8位、吉利数字、键盘模式等）
- **掩码暴力攻击** — 8位纯数字约32分钟穷举，智能掩码按耗时排序
- **缓存加速** — 预缓存目标CWNetwork对象，在线爆破时跳过重复扫描
- **WiFi 自动恢复** — 操作前记录当前WiFi，完成后自动恢复原连接
- **智能过滤** — 自动排除校园网、Portal认证、企业网、开放网络

## 三种攻击模式

### 模式1: 默认模式（万能钥匙 + 在线字典爆破）

```
扫描WiFi → 过滤目标 → 万能钥匙预查 → 构建密码列表 → CoreWLAN在线爆破 → 恢复WiFi
```

### 模式2: 握手包捕获 + GPU离线破解（--capture）

```
扫描WiFi → 过滤目标 → tcpdump监控捕获 → bettercap反认证 → 握手包转hashcat → GPU字典+掩码破解
```

### 模式3: hashcat独立破解（--hashcat --hash）

```
读取.22000哈希文件 → GPU字典攻击 → GPU掩码暴力攻击
```

## 技术栈

| 模块 | 技术 |
|------|------|
| WiFi 扫描 | CGO + CoreWLAN (Objective-C) |
| WiFi 连接 | CoreWLAN associateToNetwork + 缓存加速 |
| 握手包捕获 | tcpdump -I 监控模式 + EAPOL过滤 |
| 反认证攻击 | bettercap wifi.deauth |
| 格式转换 | hcxpcapngtool (pcap → hashcat 22000) |
| 数据包合并 | mergecap (Wireshark) |
| GPU破解 | hashcat -m 22000 (Metal后端) |
| 万能钥匙 | 逆向API协议（AES/CBC + MD5签名） |
| 密码字典 | 静态高频 + 动态生成器 |
| WiFi 恢复 | networksetup + keychain凭证 |

## 系统要求

> 本工具仅支持 macOS，不支持 Windows / Linux

| 要求 | 最低版本 |
|------|---------|
| 操作系统 | macOS 12+ (Monterey及以上) |
| 芯片 | Apple Silicon (M1/M2/M3/M4) 或 Intel |
| Go | 1.21+ |
| Xcode CLI | 必需（`xcode-select --install`） |

## 编译

```bash
# 需要 Go 1.21+ 和 Xcode Command Line Tools
go build -o wifi-crack .
```

## 依赖安装

```bash
# 核心工具（hashcat已预装则跳过）
brew install hashcat aircrack-ng bettercap hcxtools wireshark

# 清理安装缓存
brew cleanup --prune=all
```

## 使用

```bash
# ── 扫描模式 ──
./wifi-crack --scan

# ── 默认模式: 万能钥匙 + 在线字典爆破 ──
./wifi-crack
./wifi-crack -t "TP-LINK_XXXX"
./wifi-crack -d /path/to/dict.txt

# ── 交互选择模式: 列出全部WiFi，手动单选/多选 ──
./wifi-crack --all
./wifi-crack --all --scan

# ── 握手包捕获 + GPU离线破解（需sudo） ──
sudo ./wifi-crack --capture
sudo ./wifi-crack --capture -t "目标SSID"

# ── hashcat独立破解（已有.22000哈希文件） ──
./wifi-crack --hashcat --hash capture_hash.22000
./wifi-crack --hashcat --hash capture_hash.22000 -d big_wordlist.txt
./wifi-crack --hashcat --hash capture_hash.22000 --mask
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-t` | 空 | 指定目标SSID |
| `-d` | 空 | 外部字典文件路径 |
| `--delay` | 200 | 在线爆破每次尝试间隔（毫秒） |
| `--scan` | false | 仅扫描不爆破 |
| `--all` | false | 显示全部WiFi（不过滤），交互式选择目标 |
| `--capture` | false | 握手包捕获+GPU离线破解模式 |
| `--hashcat` | false | hashcat GPU独立破解模式 |
| `--hash` | 空 | hashcat哈希文件路径（.22000格式） |
| `--mask` | false | 仅执行掩码暴力攻击 |
| `-v` | true | 显示详细日志 |
| `--version` | false | 显示版本号 |

## 过滤规则

自动排除以下类型的网络：

- **校园网** — eduroam, iXAUT, campus, university, edu 等
- **运营商热点** — CMCC, ChinaNet, ChinaUnicom 等
- **Portal 认证** — Starbucks, McDonald's, hotel, airport 等
- **企业认证** — WPA2/WPA3 Enterprise
- **开放网络** — 无密码（大概率Portal认证）

## 项目结构

```
.
├── main.go                          # 主程序入口（三种模式流程编排）
├── go.mod                           # Go 模块定义
├── internal/
│   ├── scanner/
│   │   └── wifi_darwin.go           # WiFi 扫描/连接/缓存（CGO + CoreWLAN）
│   ├── cracker/
│   │   └── cracker.go               # 在线爆破引擎（预缓存 + 批量爆破）
│   ├── capture/
│   │   └── capture.go               # 握手包捕获（tcpdump监控 + bettercap deauth）
│   ├── hashcrack/
│   │   └── hashcrack.go             # hashcat GPU离线破解（字典+掩码+混合）
│   ├── dict/
│   │   └── dict.go                  # 中国定制字典（静态 + 动态生成器）
│   └── masterkey/
│       └── masterkey.go             # 万能钥匙API（多端点 + 优雅降级）
├── captures/                        # 握手包捕获输出目录（自动创建）
├── HARDWARE_REPORT.md               # 硬件能力评估报告
├── generate_dict.py                 # Python字典生成器
├── wifi_dict.txt                    # 大型密码字典（约2000万条）
└── README.md
```

## hashcat GPU性能（Apple M1）

| 密码类型 | 组合数 | 预计耗时 |
|------|------|------|
| 8位纯数字 | 1亿 | 约32分钟 |
| 9位纯数字 | 10亿 | 约5.3小时 |
| 10位纯数字 | 100亿 | 约53小时 |
| rockyou字典 | 1430万条 | 约4.6分钟 |
| 中国定制字典 | 约5万条 | 不到1秒 |

## v3.0 更新日志

- **握手包捕获模块** — 新增tcpdump监控模式捕获EAPOL/PMKID，适配macOS 26.3（airport已移除）
- **bettercap Deauth集成** — 自动发送反认证帧迫使客户端重连
- **hashcat GPU破解** — Metal后端加速，支持字典攻击、掩码暴力、混合攻击
- **三种工作模式** — 默认在线爆破、握手包捕获+GPU破解、hashcat独立破解
- **hcxtools集成** — pcap自动转换为hashcat 22000格式
- **中国掩码优化** — 8位纯数字优先（最常见中国WiFi密码），按耗时排序
- **工具链自检** — 自动检测所需工具是否安装并给出安装提示

## 注意事项

- macOS 需要授予终端位置权限才能获取SSID
- 握手包捕获模式（--capture）需要sudo权限
- bettercap反认证需要sudo权限
- 万能钥匙查询需要网络连接，爆破阶段会断网
- 操作结束后自动恢复原WiFi连接
- 建议在终端中运行（非IDE终端）

## License

MIT
