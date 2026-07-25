# WiFi Security Toolkit

<div align="center">

**WPA / WPA2 全链路安全测试与算力破解工作台**

`抓包` · `字典` · `规则` · `掩码` · `混合` · `组合` · `云端 GPU`

专为中国 WiFi 密码习惯深度优化 · 支持 **Mac 本地 Metal** / **AutoDL** / **Kaggle**

[功能矩阵](#核心能力) · [服务与交付](#专业服务与交付) · [快速开始](#快速开始) · [免责声明](#免责声明)

</div>

---

## 这是什么

一套面向**授权渗透与安全研究**的 WiFi 攻防工具包：

| 模块 | 能力 |
|------|------|
| **Kali 抓包链路** | Scapy 原始帧注入 · Deauth/Disassoc · EAPOL 四次握手自动识别 |
| **本地 / 云端爆破** | hashcat 10 阶段递进 · 中国规则 + 掩码 + 混合/组合攻击 |
| **中国密码优化** | 拼音姓名 · 生日 · 运营商/校园 · 弱口令 · CERNET 样本习惯 |

开源仓库交付的是**可运行的工具与规则骨架**。  
完整商业级字典包、经过筛选的监听网卡、以及一对一部署方案，请走下方服务通道。

---

## 核心能力

```text
┌─────────────┐    ┌──────────────┐    ┌──────────────────┐
│  Monitor    │───▶│  Handshake   │───▶│  GPU Crack       │
│  + Deauth   │    │  .cap/.22000 │    │  dict+rule+mask  │
└─────────────┘    └──────────────┘    └──────────────────┘
     Kali / Scapy         hcx tools         hashcat 22000
```

- **Scapy 帧注入** — 绕过部分网卡在 aireplay-ng 上的注入失败问题  
- **爆发 + 静默节奏** — 先踢客户端，再纯监听等重连，提高 M1–M4 捕获率  
- **10 阶段递进攻击** — 从 SSID 定向到大字典、规则、掩码、hybrid、combinator  
- **中国场景规则库** — `china-wifi.rule` + 中国专用 hcmask（年份 / 手机号 / 键盘走位 / `.` `@` 等）  
- **三端算力** — Mac Metal · AutoDL CUDA · Kaggle 免费 GPU Notebook  

---

## 专业服务与交付

> 开源 ≠ 完整弹药库。  
> 本仓库**不附带全量商业字典**（体积过大，且持续更新）。  
> 需要**专业网卡 / 完整爆破包 / 工具部署**，请加微信获取。

<div align="center">

### 微信：`1837620622`

### 添加时备注（必填）

# `wifi破解（github）`

未备注可能无法通过 · 备注后说明你需要的是 **网卡 / 字典包 / 工具 / 定制**

</div>

### 三大交付方向

| 交付 | 你得到什么 | 适合谁 |
|------|------------|--------|
| **专业 WiFi 网卡** | 支持 Monitor + Injection 的 USB 网卡选型与适配建议；芯片/驱动/虚拟机透传经验；可代购与验货指引 | 新人搭环境、Mac/Windows 虚拟机、稳定抓包 |
| **WiFi 爆破包** | 中国 WiFi 高命中字典体系（弱口令 · 拼音 · 生日 · 运营商/校园 · 大词库分层）；规则/掩码配套；持续更新说明 | 已有握手包，要拉高命中率 |
| **WiFi 工具** | 本仓库脚本部署、hashcat 本地/云端跑通、AutoDL 一键流程、问题排查 | 想少踩坑，直接能跑 |

### 为什么加我，而不是只 clone

| 你的目标 | 开源仓库 | 加微信后 |
|----------|----------|----------|
| 看懂流程、学习脚本 | 足够 | — |
| 完整中国密码弹药（多 GB 分层包） | **不全量公开** | **按需交付最新包** |
| 监听网卡买什么、是否注入成功 | 文档建议 | **按机型/系统定制推荐** |
| 虚拟机透传、Metal/CUDA、跑挂排查 | 自行摸索 | **远程协助 / 部署指导** |
| SSID/场景定制字典（校园、运营商、品牌路由） | 基础生成器 | **定制生成与策略** |

### 定制服务示例

- 指定 SSID / 地区 / 运营商习惯的字典与掩码策略  
- Mac + Parallels Kali / Windows + VMware 环境一条龙跑通  
- AutoDL / 本地 GPU 任务编排与进度监控  
- 握手包有效性复核（是否完整 EAPOL / 是否可 hashcat）  
- 网卡驱动、Monitor 模式、注入失败专项排查  

咸鱼 / B站：**万能程序员** · 邮箱：`2040168455@qq.com`（非 Git 事务）

---

## 仓库结构

```text
wifi-security-toolkit/
├── wifi-crack-kali/                 # Kali：扫描 / 抓包 / Scapy 攻击 / 字典生成
│   ├── 扫描抓包/                    # 1_scan · 2_capture · 3_deauth
│   ├── 自动攻击/auto_attack.py      # 单终端全自动
│   └── 字典工具/generate_cn_dict.py
├── wifi-crack-notebook/             # 本地 / 云端 GPU 爆破
│   ├── crack_local.sh               # Mac Metal 主脚本
│   ├── crack_cloud.sh               # AutoDL 云端主脚本
│   ├── cloud_start|monitor|stop.sh  # 云端运维
│   ├── kaggle-hashcat-wifi-crack.ipynb
│   ├── dicts/                       # 规则 · 掩码 · 示例小字典（非全量包）
│   ├── captures/                    # 放入 .22000 / .cap
│   └── work/                        # hashcat 工作区（本地生成，不入库）
├── README.md
└── .gitignore
```

**关于字典：**  
仓库内保留规则、掩码与**示例级**词表，便于跑通流程。  
**完整中国 WiFi 爆破包（含大词库 / 持续更新包）请加微信购买获取，备注：`wifi破解（github）`。**

---

## 攻击流程（10 阶段）

`crack_local.sh` / `crack_cloud.sh` 采用从快到慢的递进策略：

| 阶段 | 方式 | 说明 |
|:----:|------|------|
| 1 | SSID 定向 | 目标名 leet / 年份 / 反转等专属候选 |
| 2 | 高命中字典 | WPA TOP · 中国弱口令分层 |
| 3 | 规则变换 | `china-wifi.rule` / best64 |
| 4 | 大字典 | 全球高频 → 更大词库（完整包另取） |
| 5 | 掩码 | 中国专用 hcmask（数字/字母/特殊字符区） |
| 6 | Hybrid | 字典+掩码 / 掩码+字典 |
| 7 | Combinator | 双字典拼接 |
| 8 | 多规则堆叠 | 规则文件叠加 |
| 9 | 随机规则 | 覆盖未知变换 |
| 10 | 统计清理 | 结果汇总 · 临时文件清理 |

---

## 快速开始

### 环境

- Kali Linux（推荐 2024+）  
- **支持 Monitor + Injection 的 USB 无线网卡**（不确定买什么 → 微信备注获取推荐）  
- Python3 + Scapy · hashcat 6.2+/7.x  
- Mac：`brew install hashcat`（Metal/OpenCL）

### 1）Kali 抓包（示意）

```bash
# 扫描
sudo bash 1_scan.sh

# Monitor
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# 全自动（Scapy 收发 + EAPOL 检测）
sudo python3 auto_attack.py wlan0mon <BSSID> <频道> [客户端MAC]
```

### 2）本地 GPU 爆破

```bash
cd wifi-crack-notebook
# 将 .22000 或 .cap 放入 captures/
bash crack_local.sh
```

### 3）AutoDL 云端

```bash
# 上传 crack_cloud.sh + 握手包后
nohup bash crack_cloud.sh > crack.log 2>&1 &
bash cloud_monitor.sh -f
```

### 4）Kaggle 免费 GPU

上传 `.22000` + `kaggle-hashcat-wifi-crack.ipynb`，开启 GPU 后跑通 Notebook。

---

## 技术要点

### 为何用 Scapy

部分 USB 网卡在 aireplay-ng 下注入失败，Scapy raw socket 往往仍可注入。

### EAPOL 消息位

| 消息 | 方向 | ACK | MIC | Install |
|------|------|:---:|:---:|:-------:|
| M1 | AP → STA | 1 | 0 | 0 |
| M2 | STA → AP | 0 | 1 | 0 |
| M3 | AP → STA | 1 | 1 | 1 |
| M4 | STA → AP | 0 | 1 | 0 |

### 密码研究参考（策略来源）

- CERNET 类样本：8–11 位占比高，`.` / `@` 等特殊字符习惯  
- 国内弱口令与拼音+生日、运营商默认模式  
- 规则与掩码据此分层，而不是盲目全表扫描  

---

## 获取完整资源

```text
┌──────────────────────────────────────────────────────────┐
│  微信  1837620622                                        │
│  备注  wifi破解（github）                                 │
│                                                          │
│  可咨询 / 购买：                                           │
│    · 专业 WiFi 监听网卡（Monitor + 注入）                  │
│    · 中国 WiFi 爆破字典包（分层 · 更新 · 场景定制）        │
│    · WiFi 工具部署与定制（本地 / 云端 / 虚拟机）           │
└──────────────────────────────────────────────────────────┘
```

咸鱼 / B站搜索：**万能程序员**

---

## 免责声明

本项目仅供**安全研究、教学演示与已获授权的渗透测试**使用。  
未经授权扫描、攻击、破解他人网络属于违法行为。  
使用者须自行确保合法合规，并承担全部法律责任。  
作者不对任何滥用行为负责。

---

## 作者

| | |
|--|--|
| 作者 | 传康Kk（万能程序员） |
| 微信 | **1837620622**（备注：`wifi破解（github）`） |
| 咸鱼 / B站 | 万能程序员 |
| 邮箱 | 2040168455@qq.com |
| GitHub | [@1837620622](https://github.com/1837620622) |

---

<div align="center">

**先跑通工具链，再上专业弹药与网卡。**

加微信备注 → `wifi破解（github）` → 说明需求（网卡 / 爆破包 / 工具 / 定制）

</div>
