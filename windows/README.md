# Windows 专用（CUDA / OpenCL）

## 目录

| 路径 | 说明 |
|------|------|
| `crack.ps1` | **主入口**（推荐） |
| `crack.bat` | 双击/cmd 包装 |
| `work\` | 运行产物（不入 Git） |

**字典与握手包**与 Mac 共用仓库根目录 **`shared\`**：

- `shared\dicts\` → 字典、规则、掩码  
- `shared\captures\` → 默认握手包  

## 环境要求

1. **Windows 10/11 64-bit**
2. **NVIDIA 驱动**（推荐）或 AMD 对应 OpenCL 运行时  
3. [hashcat](https://hashcat.net/hashcat/) 官方 Windows 包，解压后将目录加入 `PATH`，或：

```powershell
.\crack.ps1 -Hashcat C:\hashcat\hashcat.exe
```

4. （可选）[hcxtools](https://github.com/ZerBea/hcxtools) Windows 构建 / WSL，用于 `.cap` → `.22000`  
   更省事：在 **Kali** 抓包并转好 `.hc22000` 再拷到 Windows。

验证：

```powershell
hashcat -I
# 应看到 CUDA 或 OpenCL GPU
```

## 快速开始

```powershell
# 管理员 PowerShell 可选；一般用户权限即可
cd windows

# 握手包放到共享目录
copy D:\handshakes\*.hc22000 ..\shared\captures\

# 自动读 shared\dicts，扫描 shared\captures
.\crack.ps1

# 或双击 crack.bat
```

## 自定义

```powershell
# 指定单个哈希
.\crack.ps1 -Hash D:\a.hc22000

# 指定字典目录 + 捕获目录
.\crack.ps1 -DictDir D:\wifi-dicts -CaptureDir D:\hs

# 高负载（台式机/云主机）
.\crack.ps1 -Workload 4

# 先跳过掩码，只跑字典+规则
.\crack.ps1 -SkipMasks
```

## 与 Mac / 云端分工建议

| 阶段 | 建议平台 |
|------|----------|
| 抓包 Monitor + 注入 | Kali + 专业 USB 网卡（见 `docs/01-抓包教程.md`） |
| 日常字典打击 | **Windows 独显** 或 **Mac Metal** |
| 超大字典长时间 | 算力云 CUDA（`wifi-crack-notebook/crack_cloud.sh`） |

## 注意

- 勿将 `work\`、真实握手包提交 Git。  
- 首次运行若提示执行策略：`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`  
- WPA 候选长度必须 8–63；脚本会自动过滤字典短词。
