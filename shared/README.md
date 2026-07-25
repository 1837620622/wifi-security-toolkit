# shared — 跨平台共享（与 GitHub 同名）

| 名称 | 类型 | 说明 |
|------|------|------|
| `dicts` | 符号链接 | → `../wifi-crack-notebook/dicts`（字典实体） |
| `captures/` | 目录 | 默认握手包（.hc22000 / .cap） |
| `captures_legacy` | 符号链接 | → `../wifi-crack-notebook/captures` |
| `README.md` | 文件 | 本说明 |

## 入口脚本如何读这里

| 平台 | 命令 |
|------|------|
| Mac | `bash mac/crack.sh`（默认 `--dict-dir shared/dicts`） |
| Windows | `.\win\crack.ps1`（默认 `shared\dicts`） |

自定义：

```bash
bash mac/crack.sh --dict-dir /path/to/dicts --hash /path/to/a.hc22000
```

```powershell
.\win\crack.ps1 -DictDir D:\dicts -Hash D:\hs\a.hc22000
```

## 注意

- 勿创建 `windows/` 目录；Windows 侧固定为 **`win/`**。  
- 大字典新下载放在 `wifi-crack-notebook/dicts/cn-sources/latest/`，**文件名勿与现有 dicts 重复**。  
- 真实握手包不要提交 Git。  
