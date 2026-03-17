# WiFi Cracker v2.0 (Go + CoreWLAN)

macOS 专用 WiFi 安全测试工具，基于 Go 语言 + CGO 调用 CoreWLAN 框架实现。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 功能特性

- **万能钥匙预查** — 自动查询WiFi万能钥匙密码库（多端点容错，API不可用自动降级）
- **中国定制字典** — 内置数千条高命中率密码（生日、手机号后8位、吉利数字、键盘模式等）
- **缓存加速** — 预缓存目标CWNetwork对象，爆破时跳过重复扫描，速度提升3-5倍
- **WiFi 自动恢复** — 爆破前记录当前WiFi，爆破后自动恢复原连接
- **智能过滤** — 自动排除校园网、Portal认证、企业网、开放网络、手机热点
- **路由器识别** — 根据SSID前缀（TP-LINK/FAST/Tenda/MERCURY等）生成默认密码
- **位置权限兼容** — CoreLocation授权 + Python CoreWLAN回退扫描
- **外部字典** — 支持加载自定义密码字典文件

## 攻击流程

```
扫描WiFi → 过滤目标 → 万能钥匙预查（联网） → 记录原WiFi → 构建密码列表 → 缓存目标 → 字典爆破 → 恢复原WiFi
```

密码优先级（从高到低）：

1. 万能钥匙查到的密码
2. 路由器默认密码（根据SSID生成）
3. 中国定制字典（静态高频 + 动态生成的生日/手机号/数字模式）
4. 外部字典文件

## 技术栈

| 模块 | 技术 |
|------|------|
| WiFi 扫描 | CGO + CoreWLAN (Objective-C) |
| WiFi 连接 | CoreWLAN associateToNetwork + 缓存加速 |
| 位置权限 | CoreLocation + Python 回退 |
| 万能钥匙 | 逆向API协议（AES/CBC + MD5签名 + 设备注册） |
| 密码字典 | 静态高频 + 动态生成器（生日/手机号/数字模式） |
| WiFi 恢复 | networksetup + keychain已保存凭证 |
| 爆破引擎 | Go + 可配置延迟 + 预缓存 |

## 编译

```bash
# 需要 Go 1.21+ 和 Xcode Command Line Tools
go build -o wifi-crack .
```

## 使用

```bash
# 扫描附近可爆破的WiFi（不执行爆破）
./wifi-crack --scan

# 自动扫描 + 万能钥匙查询 + 字典爆破
./wifi-crack

# 指定目标SSID
./wifi-crack -t "TP-LINK_XXXX"

# 使用外部字典
./wifi-crack -d /path/to/dict.txt

# 调整尝试间隔（毫秒，默认200）
./wifi-crack --delay 100
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-t` | 空 | 指定目标SSID |
| `-d` | 空 | 外部字典文件路径 |
| `--delay` | 200 | 每次尝试间隔（毫秒） |
| `--scan` | false | 仅扫描不爆破 |
| `-v` | true | 显示详细日志 |
| `--version` | false | 显示版本号 |

## 过滤规则

自动排除以下类型的网络：

- **校园网** — eduroam, iXAUT, campus, university, edu 等
- **运营商热点** — CMCC, ChinaNet, ChinaUnicom 等
- **Portal 认证** — Starbucks, McDonald's, hotel, airport 等
- **企业认证** — WPA2/WPA3 Enterprise
- **开放网络** — 无密码（大概率Portal认证）
- **手机热点** — iPhone, Huawei, Xiaomi, OPPO 等

## 项目结构

```
.
├── main.go                          # 主程序入口（5阶段流程编排）
├── go.mod                           # Go 模块定义
├── internal/
│   ├── scanner/
│   │   └── wifi_darwin.go           # WiFi 扫描/连接/缓存（CGO + CoreWLAN）
│   ├── cracker/
│   │   └── cracker.go               # 爆破引擎（预缓存 + 批量爆破）
│   ├── dict/
│   │   └── dict.go                  # 中国定制字典（静态 + 动态生成器）
│   └── masterkey/
│       └── masterkey.go             # 万能钥匙API（多端点 + 优雅降级）
├── scripts/                         # Python 版脚本（旧版兼容）
└── README.md
```

## v2.0 更新日志

- **修复断网问题** — 万能钥匙查询全部完成后再进行爆破，避免爆破过程中断网
- **WiFi自动恢复** — 爆破前记录当前WiFi，结束后通过networksetup自动恢复
- **中国定制字典** — 新增生日（1970-2010）、手机号后8位、数字重复模式等动态生成器
- **缓存加速** — 预缓存目标CWNetwork对象，后续连接跳过重复扫描
- **万能钥匙重写** — 基于逆向分析的正确两步协议（注册设备→查询密码），多端点容错
- **优雅降级** — API不可用时自动跳过，不阻塞字典爆破流程
- **默认延迟降低** — 从500ms降至200ms，配合缓存机制大幅提速

## 注意事项

- macOS 需要授予终端位置权限才能获取SSID
- 如位置权限未授予，程序会自动回退到 Python + CoreWLAN 扫描
- 万能钥匙查询需要网络连接，爆破阶段会断网
- 爆破结束后自动恢复原WiFi（需要系统keychain中有保存的密码）
- 建议在终端中运行（非IDE终端）

## License

MIT
