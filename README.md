# WiFi Cracker v3.0 (Go + CoreWLAN + hashcat)

macOS 专用 WiFi 安全测试工具，基于 Go + CGO + CoreWLAN + hashcat GPU加速 + 全球WiFi密码库。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 功能特性

- **全球WiFi密码库** — 对接 3wifi.dev 开放数据库（数千万条记录）+ wpa-sec全球社区破解字典
- **智能攻击编排** — 选择WiFi后自动分5阶段递进攻击，从秒级到分钟级逐步升级
- **握手包捕获** — tcpdump监控模式捕获EAPOL握手包/PMKID（适配macOS 26.3，airport已移除）
- **Deauth攻击** — 集成bettercap发送反认证帧，迫使客户端重连以捕获握手包
- **hashcat GPU破解** — Apple M1 Metal后端加速，WPA模式约52000 H/s（比在线爆破快1万倍）
- **交互式选择** — `--all`模式列出全部WiFi，支持单选/多选/范围选择
- **中国定制字典** — 内置数千条高命中率密码（生日、手机号后8位、吉利数字、键盘模式等）
- **掩码暴力攻击** — 8位纯数字约32分钟穷举，智能掩码按耗时排序
- **WiFi 自动恢复** — 操作前记录当前WiFi，完成后自动恢复原连接

## 双平台支持

| 功能 | macOS 版 (Go + CoreWLAN) | Windows 版 (Python + pywifi) |
|------|-------------------------|---------------------------|
| 入口 | `./wifi-crack` | `python wifi_crack.py` |
| WiFi扫描 | CoreWLAN (CGO) | pywifi + netsh 双引擎 |
| 握手包捕获 | bettercap（需外部网卡） | **netsh trace ETW（内置网卡即可）** |
| GPU破解 | hashcat Metal (~52K H/s) | hashcat CUDA (~12K+ H/s) |
| 全球密码库 | p3wifi (3wifi.dev) | p3wifi (3wifi.dev) |
| 系统已保存密码 | Keychain（未实现） | **netsh show profile（自动提取）** |
| 字典规模 | 中国定制5000条 + wpa-sec | **14万条 + wpa-sec** |
| 推荐场景 | 快速TOP密码验证 + 在线爆破 | **PMKID捕获 + GPU破解（更强大）** |

> Windows版在握手包捕获和GPU破解方面更强大，详见 `wifi-crack-windows/README.md`

## 智能攻击编排器（核心流程）

使用 `--all` 选择目标WiFi后，自动按效率从高到低依次执行5个阶段：

```
Phase 1（秒级）   全球WiFi密码库查询
                    ├─ [1a] p3wifi全球数据库（3wifi.dev API，数千万条记录）
                    ├─ [1a] 历史密码逐个验证（AP可能换过密码）
                    └─ [1b] 万能钥匙API备用（已废弃，优雅降级）
     ↓ 未命中
Phase 2（秒级）   CoreWLAN快速验证TOP密码
                    ├─ 路由器默认密码（根据SSID前缀生成）
                    └─ TOP50高频密码（约60条，10秒内完成）
     ↓ 未命中
Phase 3（分钟级） 握手包捕获 + hashcat GPU字典攻击
                    ├─ tcpdump -I 监控模式捕获beacon+EAPOL
                    ├─ bettercap wifi.deauth 迫使客户端重连
                    ├─ hcxpcapngtool 转换为hashcat 22000格式
                    └─ hashcat GPU字典攻击（5万条字典 < 1秒）
     ↓ 未命中
Phase 4（32分钟） hashcat GPU掩码暴力攻击
                    └─ 8位纯数字掩码（1亿组合，M1约32分钟）
     ↓ 未命中
Phase 5（兜底）   CoreWLAN在线完整字典爆破
                    └─ 排除Phase 2已试密码，逐个尝试完整字典
```

### 工具协作图

```
p3wifi(3wifi.dev API) ──→ CoreWLAN(验证连接)
万能钥匙(备用,已废弃) ─┘
                           ↓ 失败
CoreWLAN(TOP密码快速验证) ──→ 成功则结束
                           ↓ 失败
tcpdump -I(监控模式) ←─── bettercap(deauth迫使重连)
        ↓ 捕获握手包/PMKID
hcxpcapngtool(pcap→22000格式)
        ↓
hashcat -m 22000(Metal GPU加速)
  ├─ 字典攻击（秒级）
  └─ 掩码暴力（32分钟）
        ↓ 都未命中
CoreWLAN(在线逐个尝试，兜底)
```

## 四种运行模式

### 模式1: 智能攻击模式（--all，推荐）

列出全部WiFi → 交互选择目标 → 自动执行5阶段智能攻击

### 模式2: 默认自动模式

自动过滤目标 → 万能钥匙预查 → CoreWLAN在线字典爆破

### 模式3: 握手包捕获模式（--capture，需sudo）

扫描目标 → tcpdump监控捕获 → bettercap反认证 → hashcat GPU破解

### 模式4: hashcat独立模式（--hashcat --hash）

直接对.22000哈希文件执行GPU字典+掩码攻击

## 在线密码数据源

| 数据源 | 类型 | 状态 | 说明 |
|--------|------|------|------|
| 3wifi.dev API | BSSID查密码 | ✅ 可用 | 全球数千万条，无需认证，JSON响应 |
| wpa-sec字典 | 已破解密码下载 | ✅ 可用 | 全球社区GPU破解的真实WiFi密码 |
| 万能钥匙 | 中国密码库 | ❌ 已废弃 | appId封禁，保留优雅降级 |

## 技术栈

| 模块 | 技术 |
|------|------|
| WiFi 扫描 | CGO + CoreWLAN (Objective-C) |
| WiFi 连接 | CoreWLAN associateToNetwork + 缓存加速 |
| 全球密码库 | 3wifi.dev API + wpa-sec字典下载 |
| 握手包捕获 | tcpdump -I 监控模式 + EAPOL过滤 |
| 反认证攻击 | bettercap wifi.deauth |
| 格式转换 | hcxpcapngtool (pcap → hashcat 22000) |
| GPU破解 | hashcat -m 22000 (Metal后端) |
| 密码字典 | 中国定制(静态+动态) + wpa-sec全球字典 |
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

## 完整命令列表

### 扫描命令

```bash
# 扫描附近WiFi（自动过滤校园网/企业网/开放网络）
./wifi-crack --scan

# 扫描全部WiFi（不过滤，含校园网/企业网等）
./wifi-crack --all --scan

# 查看版本号
./wifi-crack --version
```

### 智能攻击模式（推荐，自动5阶段递进）

```bash
# 列出全部WiFi → 交互选择 → 自动执行5阶段攻击
./wifi-crack --all

# 交互选择 + 指定外部大字典
./wifi-crack --all -d /path/to/big_wordlist.txt

# 交互选择 + 调整在线爆破间隔为100ms
./wifi-crack --all --delay 100
```

> 注意：不要用sudo运行主程序！sudo下macOS位置权限不可用，WiFi扫描会失败。
> Phase 3握手捕获时，程序内部会自动调用sudo（tcpdump/bettercap需要root权限）。

### 默认自动模式（自动过滤 + 在线爆破）

```bash
# 自动扫描过滤 → 万能钥匙预查 → 在线字典爆破
./wifi-crack

# 指定目标SSID
./wifi-crack -t "TP-LINK_XXXX"

# 指定目标 + 外部字典
./wifi-crack -t "TP-LINK_XXXX" -d /path/to/dict.txt

# 调整爆破间隔
./wifi-crack --delay 100
```

### 握手包捕获模式（需sudo）

```bash
# 自动过滤目标 → tcpdump捕获 → bettercap deauth → hashcat GPU破解
sudo ./wifi-crack --capture

# 指定目标SSID
sudo ./wifi-crack --capture -t "目标SSID"

# 捕获 + 指定外部字典
sudo ./wifi-crack --capture -t "目标SSID" -d /path/to/dict.txt
```

### hashcat独立破解模式（已有.22000哈希文件）

```bash
# GPU字典攻击（内置中国定制字典 + 本地wifi_dict.txt）
./wifi-crack --hashcat --hash captures/xxxx_hash.22000

# GPU字典攻击 + 指定外部大字典
./wifi-crack --hashcat --hash captures/xxxx_hash.22000 -d rockyou.txt

# 仅GPU掩码暴力攻击（8位纯数字起步）
./wifi-crack --hashcat --hash captures/xxxx_hash.22000 --mask

# 字典 + 掩码全流程
./wifi-crack --hashcat --hash captures/xxxx_hash.22000 -d rockyou.txt
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
├── main.go                          # 主程序入口（智能攻击编排 + 三种模式）
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
│   ├── p3wifi/
│   │   └── p3wifi.go                # 全球WiFi密码库（3wifi.dev API + wpa-sec字典）
│   ├── dict/
│   │   └── dict.go                  # 中国定制字典（静态 + 动态生成器）
│   └── masterkey/
│       └── masterkey.go             # [已废弃] 万能钥匙API
├── wifi-crack-windows/              # Windows版（Python + pywifi + netsh + hashcat）
│   ├── wifi_crack.py                # 主程序（智能攻击编排 + PMKID模式）
│   ├── wifi_scanner.py              # WiFi扫描/连接（pywifi + netsh 双引擎）
│   ├── pmkid_capture.py             # 握手包/PMKID捕获（netsh trace ETW）
│   ├── p3wifi_client.py             # 全球WiFi密码库（3wifi.dev API）
│   ├── dict_generator.py            # 中国定制字典生成器（14万条）
│   ├── hashcat_crack.py             # hashcat GPU离线破解
│   └── hashcat-6.2.6/              # hashcat预置（用户自行下载）
├── tools-python/                    # 第三方Python WiFi安全测试工具（来源: baihengaead/wlan-sec-test-tool）
│   ├── wifi_macos.py                # macOS专用WiFi测试脚本
│   ├── wlan_sec_test_tool.py        # 跨平台WiFi安全测试主程序
│   └── wlan_sec_test_tool_gui.py    # GUI图形界面版本
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

- **智能攻击编排器** — 选择WiFi后自动分5阶段递进攻击（密码库→TOP验证→握手捕获→GPU破解→兜底）
- **全球WiFi密码库** — 对接3wifi.dev开放API（数千万条记录，BSSID直查密码）
- **wpa-sec字典下载** — 全球社区GPU破解的真实WiFi密码字典（约3.5MB）
- **交互式WiFi选择** — `--all`模式列出全部WiFi，支持单选(3)/多选(1,3,5)/范围(1-5)/全选(all)
- **握手包捕获模块** — tcpdump监控模式捕获EAPOL/PMKID，适配macOS 26.3（airport已移除）
- **bettercap Deauth** — 自动发送反认证帧迫使客户端重连
- **hashcat GPU破解** — Metal后端加速，字典攻击+掩码暴力，M1约52000 H/s
- **sudo权限预检测** — Phase 3前自动检测sudo权限，无权限时提示
- **WiFi接口自动恢复** — tcpdump监控模式结束后自动恢复接口到正常模式
- **万能钥匙已废弃** — 2026年3月确认appId封禁，保留作备用优雅降级
- **第三方Python工具** — 集成baihengaead/wlan-sec-test-tool（macOS/跨平台/GUI）

## 注意事项

- macOS 需要授予终端位置权限才能获取SSID
- `--all` 智能攻击模式为推荐使用方式
- **不要用sudo运行主程序**（sudo下macOS位置权限不可用，扫描会失败）
- Phase 3握手捕获时程序内部会自动调用sudo（可能需要输入密码）
- 全球密码库查询（Phase 1）需要网络连接
- 操作结束后自动恢复原WiFi连接
- 建议在终端中运行（非IDE终端）

## License

MIT
