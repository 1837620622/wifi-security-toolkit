# Mac M1 Wi-Fi安全测试硬件能力评估报告

## 一、基础硬件信息

| 项目 | 详情 |
| --- | --- |
| 机型 | MacBook Pro 17,1 (MYDA2CH/A) |
| 芯片 | Apple M1 (8核: 4性能 + 4能效) |
| 内存 | 8 GB (统一内存架构) |
| GPU | Apple M1 8核GPU, Metal 4 支持 |
| 系统 | macOS 26.3.1 (Build 25D2128) |
| SIP状态 | 已启用 (System Integrity Protection) |

## 二、WiFi网卡详细信息

| 项目 | 详情 |
| --- | --- |
| 芯片 | Broadcom BCM4378 (0x14E4, 0x4378) |
| 接口 | en0 |
| 硬件MAC | c4:91:0c:b1:f9:69 |
| 随机MAC | 92:90:bf:19:7e:89 |
| 固件版本 | wl0: v18.20.480 (2025年12月编译) |
| 驱动版本 | IO80211_driverkit-1540.16 (2026年1月) |
| 协议支持 | 802.11 a/b/g/n/ac/ax (WiFi 6) |
| 频段 | 2.4GHz (Ch1-13) + 5GHz (Ch36-165) |
| 支持频道数 | 50个 |
| CoreWLAN版本 | 16.0 (1657) |
| 国家代码 | CN |

## 三、关键能力测试结果

### 已具备的能力

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| CoreWLAN扫描 | 可用 | 完整获取SSID/BSSID/信号/安全类型/信道 |
| CoreWLAN连接 | 可用 | associateToNetwork可尝试密码连接 |
| CoreWLAN断开 | 可用 | disassociate方法可用 |
| hashcat GPU破解 | 可用 | Metal 4后端, WPA模式51975 H/s |
| tcpdump | 可用 | v4.99.1系统自带 |
| wdutil | 可用 | Apple官方WiFi诊断工具 |
| monitorMode属性 | 存在 | CoreWLAN接口有monitorMode属性 |
| Python+CoreWLAN | 可用 | pyobjc绑定正常调用CoreWLAN |

### 受限的能力

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| airport命令行 | 已移除 | macOS 26.3删除了airport工具 |
| 监控模式(CLI) | **不可用** | tcpdump -I 可声明监控模式(link-type=802.11_RADIO)，但驱动不交付任何帧，实测10秒抓0个包 |
| 数据包注入 | 不可用 | 内置网卡不支持原生注入 |
| SIP保护 | 已启用 | 限制了底层网卡操作 |

## 四、hashcat GPU性能评估

```
设备: Apple M1 GPU (8核)
Metal版本: 371.5
显存: 5461 MB (统一内存)
WPA破解速度: 51,975 H/s (Hash-Mode 22000)
```

### 性能换算

| 密码类型 | 组合数 | 预计耗时 |
| --- | --- | --- |
| 8位纯数字 | 1亿 | 约32分钟 |
| 8位小写字母 | 2080亿 | 约46天 |
| rockyou.txt字典 | 1430万条 | 约4.6分钟 |
| 中国定制字典 | 约5万条 | 不到1秒 |

对比CoreWLAN在线爆破(约5次/秒), hashcat离线破解快约10000倍

## 五、2026年Wi-Fi攻击方法综述

### 方法1: CoreWLAN在线字典爆破 (现有方案)

通过CoreWLAN的associateToNetwork逐个尝试密码, 无需额外硬件

- 优点: 零外部硬件, 纯原生macOS, M1完美兼容
- 缺点: 速度慢(每次200ms+), 受AP限流
- 适合: 弱密码(8位纯数字, 常见密码)

### 方法2: PMKID攻击 (2026年最推荐)

Hashcat团队发现的方法, 无需任何客户端连接, 直接从AP提取PMKID哈希后离线破解

- 公式: `PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)`
- 优点: 只需一个数据包, 无需等待客户端连接, 被动攻击
- 工具链: hcxdumptool -> hcxpcapngtool -> hashcat -m 22000
- M1兼容性: hashcat通过Metal支持M1 GPU加速

### 方法3: 四次握手捕获 + 反认证攻击

发送deauth帧踢人, 客户端重连时捕获握手包, 再离线破解

- 工具: tcpdump(监控) + bettercap(deauth) + hashcat(破解)
- 优点: M1原生支持tcpdump监控模式
- 流程: 扫描目标 -> 捕获beacon -> 发deauth -> 捕获handshake -> hashcat破解

### 方法4: Evil Twin社会工程攻击

创建同名假AP, 伪造登录页面, 用户输入密码

- 工具: Fluxion 2026, Wifipumpkin3 v4
- 优点: 不需要暴力破解, WPA3也有效
- 缺点: 需要额外USB WiFi适配器

### 方法5: WPA3降级攻击 (Dragonblood)

利用WPA2/WPA3过渡模式漏洞, 强制客户端回退WPA2后传统破解

- 工具: Dragonblood工具集
- 限制: 仅对WPA3过渡模式有效

## 六、macOS 26.3重要变化

1. **airport命令已移除**: Apple在macOS 26.x中彻底删除了airport命令行工具, 旧SDK(15.4)有手册但新SDK(26.2)已无
2. **替代方案**: 使用wdutil进行WiFi诊断, 使用tcpdump -I进入监控模式, 或通过Wireless Diagnostics的Sniffer功能
3. **CoreWLAN增强**: CoreWLAN 16.0版本提供了更丰富的扫描接口, 包含隐藏网络扫描等高级功能
4. **Metal 4**: GPU计算性能进一步提升, hashcat运行效率更高

## 七、推荐攻击路线

```
万能钥匙预查(API) -> tcpdump捕获握手包/PMKID -> hashcat GPU离线破解 -> CoreWLAN在线字典爆破(兜底)
```

### 工具链安装清单

| 工具 | 用途 | 安装命令 |
| --- | --- | --- |
| hashcat | GPU加速密码破解 | 已安装 v7.1.2 |
| aircrack-ng | 握手包验证/传统破解 | brew install aircrack-ng |
| bettercap | Deauth攻击/网络监控 | brew install bettercap |
| hcxtools | PMKID/握手包格式转换 | brew install hcxtools |
| wireshark | 数据包分析/mergecap | brew install wireshark |
| tcpdump | 数据包捕获/监控模式 | 系统自带 v4.99.1 |
