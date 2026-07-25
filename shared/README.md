# shared — 跨平台共享资源

| 路径 | 说明 |
|------|------|
| `dicts/` | **字典与规则**（符号链接到 `wifi-crack-notebook/dicts`） |
| `captures/` | **默认握手包目录**（.cap / .pcap / .22000 / .hc22000） |
| `captures_legacy/` | 兼容旧路径 `wifi-crack-notebook/captures` 的链接 |

## 字典位置（重要）

完整路径（本机）：

```text
shared/dicts/
  ├── china-wifi.rule              # 中国规则
  ├── 00-china-wifi-masks.hcmask   # 掩码
  ├── wpa-top4800.txt / probable-wpa.txt / cn-top100w.txt ...
  └── cn-sources/latest/           # 新下载源与合并快打包（本地，不入 Git）
        └── merged/cn-wifi-quickhit-8plus.txt
```

Mac / Windows 破解脚本**默认自动读取**本目录。  
也可用参数覆盖，例如：

- Mac: `bash mac/crack.sh --dict-dir /path/to/dicts --hash /path/to/a.hc22000`
- Windows: `.\windows\crack.ps1 -DictDir D:\dicts -Hash D:\hs\a.hc22000`

## 握手包放哪里

1. 推荐：`shared/captures/`  
2. 或运行时指定：`--hash` / `--cap` / `-Hash` / `-Cap`  
3. 兼容旧位置：`wifi-crack-notebook/captures/`

**勿把真实握手包提交到 Git。**
