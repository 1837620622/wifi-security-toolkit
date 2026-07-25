#Requires -Version 5.1
<#
.SYNOPSIS
  Windows 专用 WiFi 握手包 hashcat 破解入口（CUDA / OpenCL）

.DESCRIPTION
  - 默认自动读取仓库 shared\dicts 字典目录
  - 默认扫描 shared\captures 与 wifi-crack-notebook\captures
  - 支持 -Hash / -Cap / -DictDir / -CaptureDir 自定义

.EXAMPLE
  .\crack.ps1
  .\crack.ps1 -Hash D:\hs\a.hc22000
  .\crack.ps1 -DictDir D:\dicts -CaptureDir D:\handshakes -Workload 4
#>

param(
    [string]$DictDir = "",
    [string]$WorkDir = "",
    [string[]]$CaptureDir = @(),
    [string[]]$Hash = @(),
    [string[]]$Cap = @(),
    [string]$Hashcat = "",
    [int]$Workload = 3,
    [switch]$SkipMasks,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$WinDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $WinDir "..")

if ($Help) {
    Write-Host @"
Windows CUDA/OpenCL 破解

  -DictDir PATH        字典目录（默认 shared\dicts）
  -WorkDir PATH        工作目录（默认 windows\work）
  -CaptureDir PATH     握手扫描目录（可重复）
  -Hash FILE           .22000 / .hc22000（可重复）
  -Cap FILE            .cap/.pcap（需 hcxpcapngtool 在 PATH）
  -Hashcat PATH        hashcat.exe 路径
  -Workload N          hashcat -w（默认 3，云上可 4）
  -SkipMasks           跳过掩码阶段（加快试跑）
"@
    exit 0
}

function Resolve-DefaultDictDir {
    $cands = @(
        (Join-Path $RepoRoot "shared\dicts"),
        (Join-Path $RepoRoot "wifi-crack-notebook\dicts")
    )
    foreach ($c in $cands) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    return $null
}

if (-not $DictDir) { $DictDir = Resolve-DefaultDictDir }
if (-not $DictDir -or -not (Test-Path $DictDir)) {
    Write-Error "字典目录不存在。请用 -DictDir 指定，或确保 shared\dicts 可用。"
}
if (-not $WorkDir) { $WorkDir = Join-Path $WinDir "work" }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

if (-not $Hashcat) {
    $cmd = Get-Command hashcat.exe -ErrorAction SilentlyContinue
    if ($cmd) { $Hashcat = $cmd.Source }
    else {
        foreach ($p in @(
            "C:\hashcat\hashcat.exe",
            "C:\Tools\hashcat\hashcat.exe",
            "$env:USERPROFILE\hashcat\hashcat.exe"
        )) {
            if (Test-Path $p) { $Hashcat = $p; break }
        }
    }
}
if (-not $Hashcat -or -not (Test-Path $Hashcat)) {
    Write-Error "未找到 hashcat.exe。请从 https://hashcat.net/hashcat/ 下载并加入 PATH，或 -Hashcat 指定。"
}

# 默认捕获目录
if ($CaptureDir.Count -eq 0 -and $Hash.Count -eq 0 -and $Cap.Count -eq 0) {
    foreach ($c in @(
        (Join-Path $RepoRoot "shared\captures"),
        (Join-Path $RepoRoot "shared\captures_legacy"),
        (Join-Path $RepoRoot "wifi-crack-notebook\captures")
    )) {
        if (Test-Path $c) { $CaptureDir += $c }
    }
}

Write-Host "============================================"
Write-Host "  WiFi 中国密码破解  [Windows GPU]"
Write-Host "  hashcat CUDA/OpenCL"
Write-Host "============================================"
Write-Host "  字典: $DictDir"
Write-Host "  工作: $WorkDir"
Write-Host "  引擎: $Hashcat"
Write-Host ""

# 合并哈希
$Merged = Join-Path $WorkDir "all_merged.22000"
$Hashes = Join-Path $WorkDir "hashes_deduped.22000"
$Potfile = Join-Path $WorkDir "hashcat.potfile"
$Outfile = Join-Path $WorkDir "cracked.txt"
$ResultFile = Join-Path $WorkDir "result.txt"
"" | Set-Content -Encoding ascii $Merged

function Add-HashFile([string]$Path) {
    if (-not (Test-Path $Path)) { return }
    Write-Host "  + hash $(Split-Path $Path -Leaf)"
    Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^WPA\*' } |
        Add-Content -LiteralPath $Merged -Encoding ascii
}

function Add-CapFile([string]$Path) {
    if (-not (Test-Path $Path)) { return }
    $hcx = Get-Command hcxpcapngtool.exe -ErrorAction SilentlyContinue
    if (-not $hcx) {
        Write-Host "  ! 跳过 cap（无 hcxpcapngtool）: $(Split-Path $Path -Leaf)"
        return
    }
    Write-Host "  + 转换 $(Split-Path $Path -Leaf)"
    $tmp = Join-Path $WorkDir "tmp_cap.22000"
    & $hcx.Source -o $tmp $Path 2>$null | Out-Null
    if (Test-Path $tmp) { Add-HashFile $tmp; Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

foreach ($h in $Hash) { Add-HashFile $h }
foreach ($c in $Cap) { Add-CapFile $c }

foreach ($dir in $CaptureDir) {
    if (-not (Test-Path $dir)) { continue }
    Write-Host "  目录: $dir"
    Get-ChildItem -LiteralPath $dir -Recurse -File -Include *.22000,*.hc22000 -ErrorAction SilentlyContinue |
        ForEach-Object { Add-HashFile $_.FullName }
    Get-ChildItem -LiteralPath $dir -Recurse -File -Include *.cap,*.pcap,*.pcapng -ErrorAction SilentlyContinue |
        ForEach-Object { Add-CapFile $_.FullName }
}

if (-not (Test-Path $Merged) -or (Get-Item $Merged).Length -eq 0) {
    Write-Error "未发现有效 hashline。请放入 shared\captures 或使用 -Hash / -Cap"
}

Get-Content $Merged | Sort-Object -Unique | Set-Content -Encoding ascii $Hashes
$Total = (Get-Content $Hashes | Measure-Object -Line).Lines
Write-Host ""
Write-Host "  合计 hashline: $Total"
Write-Host ""

# hashcat 基参
$HcBase = @(
    "-m", "22000", $Hashes,
    "--potfile-path", $Potfile,
    "--outfile", $Outfile,
    "--outfile-format", "2",
    "-w", "$Workload",
    "--status", "--status-timer", "15"
)

function Test-AllDone {
    if (-not (Test-Path $Potfile)) { return $false }
    $shown = & $Hashcat -m 22000 $Hashes --potfile-path $Potfile --show 2>$null
    $n = ($shown | Where-Object { $_ -match 'WPA\*' }).Count
    return ($n -ge $Total -and $Total -gt 0)
}

function Invoke-DictAttack([string]$Name, [string]$DictPath) {
    if (Test-AllDone) { return }
    if (-not (Test-Path $DictPath)) { return }
    $filtered = Join-Path $WorkDir ("filtered_" + [IO.Path]::GetFileName($DictPath))
    Get-Content -LiteralPath $DictPath -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -ge 8 -and $_.Length -le 63 } |
        Set-Content -LiteralPath $filtered -Encoding ascii
    $n = (Get-Content $filtered | Measure-Object -Line).Lines
    if ($n -lt 10) { return }
    Write-Host "----------------------------------------"
    Write-Host "  $Name ($n 条)"
    Write-Host "----------------------------------------"
    & $Hashcat @HcBase -a 0 $filtered
}

function Invoke-RuleAttack([string]$Name, [string]$DictPath, [string]$RulePath) {
    if (Test-AllDone) { return }
    if (-not (Test-Path $DictPath) -or -not (Test-Path $RulePath)) { return }
    Write-Host "----------------------------------------"
    Write-Host "  $Name"
    Write-Host "----------------------------------------"
    & $Hashcat @HcBase -a 0 $DictPath -r $RulePath
}

function Invoke-MaskAttack([string]$Name, [string[]]$MaskArgs) {
    if (Test-AllDone) { return }
    Write-Host "----------------------------------------"
    Write-Host "  $Name"
    Write-Host "----------------------------------------"
    & $Hashcat @HcBase -a 3 @MaskArgs
}

# 规则路径
$RuleChina = Join-Path $DictDir "china-wifi.rule"
$MaskChina = Join-Path $DictDir "00-china-wifi-masks.hcmask"
$QuickHit = Join-Path $DictDir "cn-sources\latest\merged\cn-wifi-quickhit-8plus.txt"

Write-Host ">>>>>> 阶段0: 精华字典 <<<<<<"
Invoke-DictAttack "WPA Top4800" (Join-Path $DictDir "wpa-top4800.txt")
Invoke-DictAttack "probable-wpa" (Join-Path $DictDir "probable-wpa.txt")
if (Test-Path $QuickHit) { Invoke-DictAttack "CN 快打包 8-63" $QuickHit }
Invoke-DictAttack "cn-top100w" (Join-Path $DictDir "cn-top100w.txt")
Invoke-DictAttack "01-top500k" (Join-Path $DictDir "01-top500k.txt")

Write-Host ""
Write-Host ">>>>>> 阶段1: 中国结构字典 <<<<<<"
foreach ($name in @(
    "05-chinese-full-410w.txt",
    "07-birthdays.txt",
    "08-names-pinyin.txt",
    "11-wpa-sec.txt",
    "12-pwdb-top1m.txt"
)) {
    Invoke-DictAttack $name (Join-Path $DictDir $name)
}

Write-Host ""
Write-Host ">>>>>> 阶段2: 规则变换 <<<<<<"
if (Test-Path $RuleChina) {
    foreach ($name in @("wpa-top4800.txt", "probable-wpa.txt", "cn-top100w.txt", "01-top500k.txt", "07-birthdays.txt")) {
        $p = Join-Path $DictDir $name
        if (Test-Path $p) {
            $sz = (Get-Item $p).Length
            if ($sz -lt 50MB) { Invoke-RuleAttack "$name + china-wifi.rule" $p $RuleChina }
        }
    }
}

if (-not $SkipMasks -and (Test-Path $MaskChina)) {
    Write-Host ""
    Write-Host ">>>>>> 阶段3: 掩码（中国 hcmask，可能较久）<<<<<<"
    # 仅跑文件中非注释行的前若干条，避免一次卡死；完整可自行 hashcat -a 3 ...
    $masks = Get-Content $MaskChina | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' } | Select-Object -First 40
    $i = 0
    foreach ($m in $masks) {
        $i++
        # hcmask 行格式可能含自定义字符集，原样交给 hashcat
        if (Test-AllDone) { break }
        Write-Host "  mask [$i] $m"
        & $Hashcat @HcBase -a 3 $m
    }
}

Write-Host ""
Write-Host ">>>>>> 完成 <<<<<<"
if (Test-Path $Potfile) {
    & $Hashcat -m 22000 $Hashes --potfile-path $Potfile --show 2>$null |
        Tee-Object -FilePath $ResultFile
    Write-Host "结果: $ResultFile"
} else {
    Write-Host "未产生 potfile（可能未命中）"
}
