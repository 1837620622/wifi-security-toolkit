# wifi-crack-kali — 空口抓包与攻击（Kali）

本目录名称与 GitHub 发布一致：**`wifi-crack-kali`**。

## 子目录命名（勿改）

| 文件夹 | 内容 |
|--------|------|
| `扫描抓包/` | `1_scan.sh` · `2_capture.sh` · `3_deauth.sh` |
| `自动攻击/` | `auto_attack.py`（推荐单终端全自动） |
| `字典工具/` | `generate_cn_dict.py` · 生成 `cn_wifi_dict.txt` |
| `结果/` | **仅本地**运行输出（不入 Git） |

## 快速入口

```bash
cd 扫描抓包 && sudo bash 1_scan.sh
cd ../自动攻击 && sudo python3 auto_attack.py <BSSID> <频道> [SSID]
```

抓到的包建议再拷到仓库根 `shared/captures/`，供 `mac/` / `win/` 破解使用。

详见：`docs/01-抓包教程.md`
