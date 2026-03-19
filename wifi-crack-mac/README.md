# WiFi Cracker macOS 版 (Go + CoreWLAN + hashcat)

macOS 专用 WiFi 安全测试工具，基于 Go + CGO + CoreWLAN + hashcat GPU 加速 + 全球 WiFi 密码库。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 核心特性

- **全球 WiFi 密码库** — 对接 3wifi.dev 开放数据库（数千万条记录）
- **智能攻击编排** — 选择 WiFi 后自动分 5 阶段递进攻击，从秒级到分钟级逐步升级
- **握手包捕获** — tcpdump 监控模式捕获 EAPOL 握手包/PMKID
- **Deauth 攻击** — 集成 bettercap 发送反认证帧，迫使客户端重连
- **hashcat GPU 破解** — Apple M1 Metal 后端加速，约 52,000 H/s
- **交互式选择** — 列出全部 WiFi，支持单选/多选/范围选择
- **中国定制字典** — 内置数千条高命中率密码（生日、手机号后 8 位、吉利数字等）
- **掩码暴力攻击** — 8 位纯数字约 32 分钟穷举
- **WiFi 自动恢复** — 操作前记录当前 WiFi，完成后自动恢复

## 智能攻击流程

```
Phase 1（秒级）   全球WiFi密码库查询（p3wifi 3wifi.dev API）
     ↓ 未命中
Phase 2（秒级）   CoreWLAN快速验证TOP密码（路由器默认+TOP50高频）
     ↓ 未命中
Phase 3（分钟级） 握手包捕获 + hashcat GPU字典攻击
     ↓ 未命中
Phase 4（32分钟） hashcat GPU掩码暴力攻击（8位纯数字）
     ↓ 未命中
Phase 5（兜底）   CoreWLAN在线完整字典爆破
```

## 系统要求

| 要求 | 最低版本 |
|-----|---------|
| 操作系统 | macOS 12+ (Monterey 及以上) |
| 芯片 | Apple Silicon (M1/M2/M3/M4) 或 Intel |
| Go | 1.21+ |
| Xcode CLI | 必需（`xcode-select --install`） |

## 编译

```bash
# 进入 macOS 版目录
cd wifi-crack-mac

# 编译（需要 Go 1.21+ 和 Xcode Command Line Tools）
go build -o wifi-crack .
```

## 依赖安装

```bash
# 握手包捕获和GPU破解所需工具（可选）
brew install hashcat aircrack-ng bettercap hcxtools wireshark
```

## 使用方法

### 智能攻击模式（推荐）

```bash
# 列出全部WiFi → 交互选择 → 自动执行5阶段攻击
./wifi-crack

# 指定外部大字典
./wifi-crack -d /path/to/big_wordlist.txt

# 调整在线爆破间隔为100ms
./wifi-crack --delay 100
```

### 仅扫描模式

```bash
./wifi-crack --scan
```

### 握手包捕获模式（需 sudo）

```bash
sudo ./wifi-crack --capture
sudo ./wifi-crack --capture -t "目标SSID"
```

### hashcat 独立破解模式

```bash
# GPU字典攻击
./wifi-crack --hashcat --hash captures/xxxx_hash.22000

# 仅掩码暴力攻击
./wifi-crack --hashcat --hash captures/xxxx_hash.22000 --mask
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|-----|--------|-----|
| `-t` | 空 | 指定目标 SSID |
| `-d` | 空 | 外部字典文件路径 |
| `--delay` | 200 | 在线爆破间隔（毫秒） |
| `--scan` | false | 仅扫描不爆破 |
| `--capture` | false | 握手包捕获+GPU 离线破解模式 |
| `--hashcat` | false | hashcat GPU 独立破解模式 |
| `--hash` | 空 | hashcat 哈希文件路径（.22000） |
| `--mask` | false | 仅执行掩码暴力攻击 |
| `-v` | true | 显示详细日志 |
| `--version` | false | 显示版本号 |

## 项目结构

```
wifi-crack-mac/
├── main.go                    # 主程序入口（智能攻击编排）
├── go.mod                     # Go 模块定义
├── internal/
│   ├── scanner/               # WiFi扫描/连接（CGO + CoreWLAN）
│   ├── cracker/               # 在线爆破引擎
│   ├── capture/               # 握手包捕获（tcpdump + bettercap）
│   ├── hashcrack/             # hashcat GPU离线破解
│   ├── p3wifi/                # 全球WiFi密码库（3wifi.dev API）
│   ├── dict/                  # 中国定制字典生成器
│   └── masterkey/             # [已废弃] 万能钥匙API
├── HARDWARE_REPORT.md         # M1硬件能力评估报告
└── README.md                  # 本文件
```

## hashcat GPU 性能（Apple M1）

| 密码类型 | 组合数 | 预计耗时 |
|---------|-------|---------|
| 8 位纯数字 | 1 亿 | 约 32 分钟 |
| 9 位纯数字 | 10 亿 | 约 5.3 小时 |
| 10 位纯数字 | 100 亿 | 约 53 小时 |
| rockyou 字典 | 1430 万条 | 约 4.6 分钟 |
| 中国定制字典 | 约 5 万条 | 不到 1 秒 |

## 注意事项

- macOS 需要授予终端 **位置权限** 才能获取 SSID
- **不要用 sudo 运行主程序**（sudo 下位置权限不可用）
- Phase 3 握手捕获时程序内部会自动调用 sudo
- macOS 内置 WiFi 不支持帧注入（Apple 驱动限制），握手捕获依赖被动监听
- 建议在终端中运行（非 IDE 终端）

## License

MIT
