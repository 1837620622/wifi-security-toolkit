# WiFi Cracker Notebook v2.0 - Kaggle 免费 GPU 加速破解

直接粘贴 hashline → 自动识别分割 → 300万+ 条字典 → 9轮递进攻击 → 批量 GPU 破解

> 仅限授权安全测试使用，请遵守当地法律法规。

## 适用场景

- 本地没有高性能 GPU（如集显笔记本）
- 需要一次破解多个握手包（支持批量粘贴几十上百条）
- 利用 Kaggle 免费 GPU 算力（T4/P100）

## GPU 性能对比

| GPU | WPA 速度 | 8位数字耗时 | 9位数字耗时 |
|-----|---------|-----------|-----------|
| Kaggle P100 | ~120,000 H/s | ~14 分钟 | ~2.3 小时 |
| Kaggle T4 | ~80,000 H/s | ~20 分钟 | ~3.5 小时 |
| Mac M1 Metal | ~52,000 H/s | ~32 分钟 | ~5.3 小时 |

## 使用方法

### 第 1 步：获取握手包 hashline

使用 `wifi-crack-mac`（macOS）或 `wifi-crack-windows`（Windows）捕获握手包，生成 `.22000` 格式文件。用文本编辑器打开，里面的每行 `WPA*...` 就是 hashline。

### 第 2 步：上传 Notebook 到 Kaggle

1. 登录 [Kaggle](https://www.kaggle.com/)
2. 创建新 Notebook，上传 `kaggle-hashcat-wifi-crack.ipynb`
3. 在 Settings 中开启 **GPU 加速器**（T4 或 P100）

### 第 3 步：粘贴 hashline

在 Notebook 的 Cell 3 中，将所有 hashline 直接粘贴到 `RAW_PASTE` 变量中。支持一次粘贴多条，自动分割识别、去重、过滤无效行。

### 第 4 步：运行全部 Cell

点击 **Run All**，自动下载 300万+ 条字典并依次执行 9 轮攻击。

## 字典规模（300万+ 条）

| 字典来源 | 条数 | 说明 |
|---------|------|------|
| wpa-sec 全球已破解 | ~75万 | 全球社区 GPU 破解的真实 WiFi 密码 |
| Probable-Wordlists WPA | ~20万 | 按概率排序的真实泄露密码（≥8位） |
| SecLists Top10K | ~1万 | 全球最常用密码 |
| SecLists xato 10M | ~1000万 | 大规模密码集合 |
| 中国定制生成 | ~150万+ | 手机号/生日/拼音/吉利数字/键盘模式/强混合 |
| hashcat best64 规则变异 | ×64倍 | 对字典进行智能变异扩展 |

## 攻击策略（9轮递进）

```
攻击1: wpa-sec 全球字典（~75万条）
攻击2: 中国定制强密码字典（~150万条）
攻击3: Probable + SecLists + xato 合并字典
攻击4: 全部字典 + best64规则变异（×64倍扩展）
攻击5: 8位纯数字掩码（1亿组合）
攻击6: 常见字母前缀+7位数字（中国常见模式）
攻击7: 9位纯数字掩码（10亿组合）
攻击8: 手机号模式（1开头+10位数字）
攻击9: 10位纯数字掩码（100亿组合）
```

## 中国定制字典覆盖范围

- **生日全格式** — YYYYMMDD / MMDDYYYY / DDMMYYYY / YYMMDD00 等（1960-2011年）
- **手机号** — 49个号段 × 20种高频尾号
- **情感数字** — 520xxxx / 1314xxxx / 吉利组合
- **拼音+数字** — 40+常用拼音 × 40+数字后缀（含大写/全大写变体）
- **字母+数字混合** — a12345678 / ab123456 等中国人常用模式
- **键盘模式** — qwertyui / 1qaz2wsx / q1w2e3r4 等
- **路由器默认** — tplink1234 / huawei123 / admin888 等
- **4位模式组合** — 1234+5678 / 8888+6666 等
- **弱密码变体** — password123! / wifi12345@ 等

## 文件说明

```
wifi-crack-notebook/
├── kaggle-hashcat-wifi-crack.ipynb   # Kaggle GPU破解笔记本 v2.0
└── README.md                         # 本文件
```

## 注意事项

- Kaggle 每周提供 **30 小时**免费 GPU 配额
- hashline 中包含 BSSID 等信息，注意隐私保护
- 字典和中国定制密码在首次运行时自动下载/生成
- 9轮攻击中每轮会自动跳过已破解的 hash（通过 potfile）
- 如果所有 hash 已破解，后续攻击自动跳过

## License

MIT
