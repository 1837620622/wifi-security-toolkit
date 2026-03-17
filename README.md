# WiFi Cracker v1.0 (Go + CoreWLAN)

macOS 专用 WiFi 安全测试工具，基于 Go 语言 + CGO 调用 CoreWLAN 框架实现。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 功能

- **WiFi 扫描** — 通过 CoreWLAN 扫描附近所有 WiFi 网络
- **智能过滤** — 自动排除校园网、Portal 认证、企业网、开放网络、手机热点
- **SSID 去重** — 同名网络只保留信号最强的
- **字典爆破** — 内置 TOP500 高频密码 + 路由器默认密码生成
- **路由器识别** — 根据 SSID 前缀（TP-LINK/FAST/Tenda/MERCURY 等）生成默认密码
- **外部字典** — 支持加载自定义密码字典文件

## 技术栈

| 模块 | 技术 |
|------|------|
| WiFi 扫描 | CGO + CoreWLAN (Objective-C) |
| WiFi 连接 | CoreWLAN associateToNetwork |
| 位置权限 | CoreLocation + Python 回退 |
| 安全类型 | CWSecurity 枚举精确识别 |
| 爆破引擎 | Go 并发 + 可配置延迟 |

## 编译

```bash
# 需要 Go 1.21+ 和 Xcode Command Line Tools
go build -o wifi-crack .
```

## 使用

```bash
# 扫描附近可爆破的 WiFi（不执行爆破）
./wifi-crack --scan

# 自动扫描并爆破所有目标
./wifi-crack

# 指定目标 SSID
./wifi-crack -t "TP-LINK_XXXX"

# 使用外部字典
./wifi-crack -d /path/to/dict.txt

# 调整尝试间隔（毫秒）
./wifi-crack --delay 300
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-t` | 空 | 指定目标 SSID |
| `-d` | 空 | 外部字典文件路径 |
| `--delay` | 500 | 每次尝试间隔（毫秒） |
| `--scan` | false | 仅扫描不爆破 |
| `-v` | true | 显示详细日志 |
| `--version` | false | 显示版本号 |

## 过滤规则

自动排除以下类型的网络：

- **校园网** — eduroam, iXAUT, campus, university, edu 等
- **运营商热点** — CMCC, ChinaNet, ChinaUnicom 等
- **Portal 认证** — Starbucks, McDonald's, hotel, airport 等
- **企业认证** — WPA2/WPA3 Enterprise
- **开放网络** — 无密码（大概率 Portal 认证）
- **手机热点** — iPhone, Huawei, Xiaomi, OPPO 等

## 攻击流程

```
扫描 WiFi → 过滤目标 → 生成路由器默认密码 → 内置 TOP500 字典 → 外部字典 → 逐个爆破
```

## 项目结构

```
.
├── main.go                          # 主程序入口
├── go.mod                           # Go 模块定义
├── internal/
│   ├── scanner/
│   │   └── wifi_darwin.go           # WiFi 扫描（CGO + CoreWLAN）
│   ├── cracker/
│   │   └── cracker.go               # 爆破引擎
│   └── dict/
│       └── dict.go                  # 内置密码字典
└── README.md
```

## 注意事项

- macOS 需要授予终端位置权限才能获取 SSID
- 如位置权限未授予，程序会自动回退到 Python + CoreWLAN 扫描
- WiFi 连接测试需要 CoreWLAN 的 associate 权限
- 建议在终端中运行（非 IDE 终端）

## License

MIT
