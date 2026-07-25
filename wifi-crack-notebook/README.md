# wifi-crack-notebook — 破解引擎与字典实体

本目录名称与 GitHub 发布一致：**`wifi-crack-notebook`**。

## 已发布脚本

| 文件 | 平台 |
|------|------|
| `crack_local.sh` | Mac Metal 引擎（被 `mac/crack.sh` 调用） |
| `crack_cloud.sh` + `cloud_*.sh` | 算力云 CUDA |
| `monitor.sh` | 本地 potfile 监控 |
| `gen_isp_dict.py` / `gen_xiaomi_a380.py` | 定向字典生成 |
| `crack_xiaomi_a380*.sh` | 专项目标（可选） |

## 字典实体 `dicts/`

- 规则：`china-wifi.rule`
- 掩码：`00-china-wifi-masks.hcmask` 等
- 分层 `*.txt` 词表  
- 跨平台通过 **`../shared/dicts` 符号链接** 访问，勿另建 `windows/dicts` 之类目录

## 仅本地（gitignore）

| 路径 | 说明 |
|------|------|
| `work/` | 运行时 |
| `captures/` | 历史握手（`shared/captures_legacy` 指向此处） |
| `hashes/` | 可选 |
| `dicts/cn-sources/` | 新下载源，文件名需与现有去重 |

推荐用户入口：

- Mac → `../mac/crack.sh`
- Windows → `../win/crack.ps1`
