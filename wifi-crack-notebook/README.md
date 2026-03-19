# WiFi Cracker Notebook 版 - Kaggle 免费 GPU 加速破解

利用 Kaggle 免费 GPU（T4/P100）运行 hashcat 离线破解 WiFi 握手包，无需本地 GPU。

> 仅限授权安全测试使用，请遵守当地法律法规。

## 适用场景

- 本地没有高性能 GPU（如集显笔记本）
- 需要破解多个握手包，利用云端免费算力
- 学习 hashcat 离线破解原理

## GPU 性能对比

| GPU | WPA 破解速度 | 8位纯数字耗时 |
|-----|-------------|-------------|
| Kaggle T4 | ~80,000 H/s | ~20 分钟 |
| Kaggle P100 | ~120,000 H/s | ~14 分钟 |
| Mac M1 | ~52,000 H/s | ~32 分钟 |

## 使用方法

### 第 1 步：捕获握手包

使用 `wifi-crack-mac`（macOS）或 `wifi-crack-windows`（Windows）捕获目标 WiFi 的握手包，生成 `.22000` 格式的哈希文件。

### 第 2 步：上传到 Kaggle

1. 登录 [Kaggle](https://www.kaggle.com/)
2. 创建一个新的 Dataset，命名为 `wifi-handshakes`
3. 将 `.22000` 文件上传到该 Dataset

### 第 3 步：运行 Notebook

1. 在 Kaggle 中创建新 Notebook
2. 上传本目录的 `kaggle-hashcat-wifi-crack.ipynb`
3. 在 Settings 中开启 **GPU 加速器**（T4 或 P100）
4. 添加你的 `wifi-handshakes` Dataset
5. 点击 **Run All** 运行全部 Cell

### 第 4 步：查看结果

最后一个 Cell 会显示破解结果，包括 SSID 和对应密码。

## 攻击策略（自动依次执行）

```
攻击1: wpa-sec 全球已破解密码字典（~75万条，约15秒）
   ↓ 未命中
攻击2: 8位纯数字掩码（1亿组合，T4 约20分钟）
   ↓ 未命中
攻击3: 9位纯数字掩码（10亿组合，T4 约3.5小时）
   ↓ 未命中
攻击4: 手机号模式（1开头+10位数字）
```

## 文件说明

```
wifi-crack-notebook/
├── kaggle-hashcat-wifi-crack.ipynb   # Kaggle GPU破解笔记本
└── README.md                         # 本文件
```

## 注意事项

- Kaggle 每周提供 30 小时免费 GPU 配额
- 上传握手包时注意隐私保护
- Notebook 会自动下载 wpa-sec 字典，无需手动准备
- 如需使用自定义字典，可在 Cell 中修改 `DICT_FILE` 路径

## License

MIT
