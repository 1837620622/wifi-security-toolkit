# WiFi Cracker 云服务器版 - 腾讯云/阿里云 GPU 破解

一键脚本：环境安装 → 字典下载 → 粘贴hashline → 9轮GPU破解

> 仅限授权安全测试使用，请遵守当地法律法规。

## 适用环境

- 腾讯云 GPU 服务器（GN7/GN10X 等带 NVIDIA GPU 的实例）
- 阿里云 GPU 服务器（ecs.gn6i/gn7i 等）
- 华为云 GPU 服务器
- 任意带 NVIDIA GPU 的 Linux 服务器（Ubuntu 20.04/22.04/24.04）

## 快速开始

### 第 1 步：上传脚本到服务器

```bash
# 方式A：git clone整个项目
git clone https://github.com/1837620622/wifi-security-toolkit.git
cd wifi-security-toolkit/wifi-crack-cloud

# 方式B：只上传crack.sh
scp crack.sh root@你的服务器IP:/root/
ssh root@你的服务器IP
```

### 第 2 步：准备握手包

将 `.22000` 格式的握手包文件上传到服务器，或者准备好 hashline 文本。

### 第 3 步：运行

```bash
# 方式A：指定.22000文件
bash crack.sh /path/to/handshake.22000

# 方式B：交互式粘贴hashline
bash crack.sh
# 选择1，粘贴hashline后按Ctrl+D

# 方式C：先写入hashline再运行
echo "WPA*02*..." > hashes.22000
bash crack.sh
```

## 脚本自动执行的操作

1. **GPU 检测** — 自动检测 NVIDIA GPU
2. **hashcat 安装** — 自动检测/apt安装/源码编译（3种方式回退）
3. **字典下载** — wpa-sec(75万) + Probable(20万) + SecLists(1万)
4. **中国定制字典** — 本地生成（生日/手机号/拼音/字母数字混合等）
5. **9轮递进攻击** — 字典→规则变异→掩码暴力

## 攻击策略

```
攻击1: wpa-sec 全球字典（~75万条）
攻击2: 中国定制强密码字典
攻击3: Probable + SecLists 合并字典
攻击4: 全部字典 + best64规则变异（×64倍）
攻击5: 8位纯数字掩码（1亿组合）
攻击6: 字母前缀+7位数字（中国常见模式）
攻击7: 9位纯数字掩码（10亿组合）
攻击8: 手机号模式（1+10位数字）
攻击9: 10位纯数字掩码（100亿组合）
```

## 腾讯云推荐配置

| 实例类型 | GPU | WPA速度(估算) | 8位数字耗时 | 费用参考 |
|---------|-----|-------------|-----------|---------|
| GN7.2XLARGE32 | T4 | ~80K H/s | ~20分钟 | ~5元/小时 |
| GN10X.2XLARGE40 | V100 | ~400K H/s | ~4分钟 | ~15元/小时 |
| GN10X.4XLARGE80 | V100×2 | ~800K H/s | ~2分钟 | ~30元/小时 |

**省钱建议**：使用竞价实例（Spot Instance），费用约正价的 20%

## 文件说明

```
wifi-crack-cloud/
├── crack.sh          # 一键破解脚本
├── hashes.22000      # 握手包文件（运行时创建）
├── dicts/            # 字典目录（自动下载）
├── hashcat.potfile   # hashcat结果文件
├── cracked.txt       # 破解的密码
└── README.md         # 本文件
```

## 手动操作

如果脚本某步失败，可以手动执行：

```bash
# 安装hashcat
apt-get update && apt-get install -y hashcat

# 或从源码编译
git clone --depth=1 https://github.com/hashcat/hashcat.git
cd hashcat && make -j$(nproc)

# 手动破解
hashcat -m 22000 hashes.22000 -a 0 dicts/wpa-sec-cracked.txt -w 3 -O
hashcat -m 22000 hashes.22000 -a 3 '?d?d?d?d?d?d?d?d' -w 3 -O

# 查看结果
hashcat -m 22000 hashes.22000 --show
```

## License

MIT
