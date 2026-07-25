# win — Windows 专用（CUDA / OpenCL）

目录名：**`win`**（不是 windows）

## 本目录

| 文件 | 说明 |
|------|------|
| `crack.ps1` | 主入口（推荐） |
| `crack.bat` | cmd / 双击包装，控制台 **GBK(936)** |
| `work\` | 运行产物（勿提交 Git） |

字典与握手包与 Mac 共用：

- `shared\dicts\`
- `shared\captures\`

## 编码说明（GBK）

- `crack.bat` 会执行 `chcp 936`，适配中文 Windows 默认代码页。
- `crack.ps1` 启动时将控制台设为 **GBK(936)**；读字典时优先 UTF-8，失败则回退系统默认（GBK）。
- 哈希文件（`WPA*...`）按 ASCII/UTF-8 无 BOM 写出。
- 若在编辑器中保存 `crack.ps1`，建议：**UTF-8 带 BOM** 或 **GBK**，避免 PS 5.1 中文乱码。

## 环境

1. Windows 10/11 x64  
2. NVIDIA 驱动（推荐）或 AMD OpenCL  
3. [hashcat](https://hashcat.net/hashcat/) 官方包，加入 PATH，或：

```powershell
.\crack.ps1 -Hashcat C:\hashcat\hashcat.exe
```

```powershell
hashcat -I
```

## 快速开始

```powershell
cd win

copy D:\handshakes\*.hc22000 ..\shared\captures\

.\crack.ps1
REM 或双击 crack.bat
```

## 参数

```powershell
.\crack.ps1 -Hash D:\a.hc22000
.\crack.ps1 -DictDir D:\wifi-dicts -CaptureDir D:\hs
.\crack.ps1 -Workload 4
.\crack.ps1 -SkipMasks
```

## 注意

- 执行策略：`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`  
- WPA 密码长度 **8–63**；脚本自动过滤短词  
- 抓包请用 Kali + 专业网卡，见 `docs/01-抓包教程.md`  
