#Requires -Version 5.1
# win/crack.ps1 - Windows GPU hashcat entry (CUDA/OpenCL)
# Encoding: save as UTF-8 with BOM recommended; runtime uses system default (GBK on CN Windows)
#
# Usage:
#   .\crack.ps1
#   .\crack.ps1 -Hash D:\hs\a.hc22000
#   .\crack.ps1 -DictDir D:\dicts -CaptureDir D:\handshakes -Workload 4

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

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# GBK / system code page console (Chinese Windows = 936)
# ---------------------------------------------------------------------------
function Initialize-ConsoleGbk {
    try {
        $gbk = [System.Text.Encoding]::GetEncoding(936)
        try { cmd /c "chcp 936 >nul" | Out-Null } catch { }
        try {
            [Console]::OutputEncoding = $gbk
            [Console]::InputEncoding = $gbk
        } catch { }
        $script:OutputEncoding = $gbk
        $script:GbkEncoding = $gbk
        $script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false
    } catch {
        $script:GbkEncoding = [System.Text.Encoding]::Default
        $script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false
    }
}
Initialize-ConsoleGbk

function Write-Info([string]$Msg) {
    Write-Host $Msg
}

function Read-TextLines([string]$Path) {
    # Wordlists: try UTF-8, fallback system default (GBK on CN Windows)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            return [System.IO.File]::ReadAllLines($Path, $script:Utf8NoBom)
        }
        # Prefer UTF-8 if valid; else Default/GBK
        try {
            $utf8 = $script:Utf8NoBom.GetString($bytes)
            if ($utf8.Contains([char]0xFFFD) -eq $false) {
                return ($utf8 -split "`r?`n")
            }
        } catch { }
        return [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::Default)
    } catch {
        return Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
    }
}

function Write-AsciiFile([string]$Path, [string[]]$Lines) {
    # Hash files are ASCII-only (WPA*...)
    $text = if ($null -eq $Lines -or $Lines.Count -eq 0) { "" } else { ($Lines -join "`n") + "`n" }
    [System.IO.File]::WriteAllText($Path, $text, $script:Utf8NoBom)
}

function Append-AsciiLine([string]$Path, [string]$Line) {
    [System.IO.File]::AppendAllText($Path, ($Line + "`n"), $script:Utf8NoBom)
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$WinDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($WinDir)) { $WinDir = (Get-Location).Path }
$RepoRoot = (Resolve-Path (Join-Path $WinDir "..")).Path

if ($Help) {
    Write-Info @"
win crack.ps1 - Windows CUDA/OpenCL

  -DictDir PATH        dict dir (default shared\dicts)
  -WorkDir PATH        work dir (default win\work)
  -CaptureDir PATH     capture scan dir (repeatable)
  -Hash FILE           .22000 / .hc22000 (repeatable)
  -Cap FILE            .cap/.pcap (needs hcxpcapngtool)
  -Hashcat PATH        hashcat.exe path
  -Workload N          hashcat -w (default 3)
  -SkipMasks           skip mask stage
"@
    exit 0
}

function Resolve-DefaultDictDir {
    $cands = @(
        (Join-Path $RepoRoot "shared\dicts"),
        (Join-Path $RepoRoot "wifi-crack-notebook\dicts")
    )
    foreach ($c in $cands) {
        if (Test-Path -LiteralPath $c) {
            return (Resolve-Path -LiteralPath $c).Path
        }
    }
    return $null
}

if ([string]::IsNullOrEmpty($DictDir)) {
    $DictDir = Resolve-DefaultDictDir
}
if ([string]::IsNullOrEmpty($DictDir) -or -not (Test-Path -LiteralPath $DictDir)) {
    Write-Info "[!] dict dir missing. Use -DictDir or create shared\dicts"
    exit 1
}
$DictDir = (Resolve-Path -LiteralPath $DictDir).Path

if ([string]::IsNullOrEmpty($WorkDir)) {
    $WorkDir = Join-Path $WinDir "work"
}
if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
}
$WorkDir = (Resolve-Path -LiteralPath $WorkDir).Path

if ([string]::IsNullOrEmpty($Hashcat)) {
    $cmd = Get-Command "hashcat.exe" -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        $Hashcat = $cmd.Source
    } else {
        $tryPaths = @(
            "C:\hashcat\hashcat.exe",
            "C:\Tools\hashcat\hashcat.exe",
            (Join-Path $env:USERPROFILE "hashcat\hashcat.exe")
        )
        foreach ($p in $tryPaths) {
            if (Test-Path -LiteralPath $p) { $Hashcat = $p; break }
        }
    }
}
if ([string]::IsNullOrEmpty($Hashcat) -or -not (Test-Path -LiteralPath $Hashcat)) {
    Write-Info "[!] hashcat.exe not found. Download from hashcat.net or use -Hashcat"
    exit 1
}

# Default capture dirs
if ($CaptureDir.Count -eq 0 -and $Hash.Count -eq 0 -and $Cap.Count -eq 0) {
    $capList = New-Object System.Collections.Generic.List[string]
    foreach ($c in @(
        (Join-Path $RepoRoot "shared\captures"),
        (Join-Path $RepoRoot "shared\captures_legacy"),
        (Join-Path $RepoRoot "wifi-crack-notebook\captures")
    )) {
        if (Test-Path -LiteralPath $c) { [void]$capList.Add($c) }
    }
    $CaptureDir = $capList.ToArray()
}

Write-Info "============================================"
Write-Info "  WiFi CN crack  [win GPU]"
Write-Info "  hashcat CUDA/OpenCL"
Write-Info "============================================"
Write-Info ("  dict: " + $DictDir)
Write-Info ("  work: " + $WorkDir)
Write-Info ("  engine: " + $Hashcat)
Write-Info ""

$Merged = Join-Path $WorkDir "all_merged.22000"
$Hashes = Join-Path $WorkDir "hashes_deduped.22000"
$Potfile = Join-Path $WorkDir "hashcat.potfile"
$Outfile = Join-Path $WorkDir "cracked.txt"
$ResultFile = Join-Path $WorkDir "result.txt"
Write-AsciiFile $Merged @()

function Add-HashFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Write-Info ("  + hash " + (Split-Path -Leaf $Path))
    $lines = Read-TextLines $Path
    foreach ($line in $lines) {
        if ($null -eq $line) { continue }
        $t = $line.Trim()
        if ($t.StartsWith("WPA*")) {
            Append-AsciiLine $Merged $t
        }
    }
}

function Add-CapFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $hcx = Get-Command "hcxpcapngtool.exe" -ErrorAction SilentlyContinue
    if ($null -eq $hcx) {
        Write-Info ("  ! skip cap (no hcxpcapngtool): " + (Split-Path -Leaf $Path))
        return
    }
    Write-Info ("  + convert " + (Split-Path -Leaf $Path))
    $tmp = Join-Path $WorkDir "tmp_cap.22000"
    & $hcx.Source -o $tmp $Path 2>$null | Out-Null
    if (Test-Path -LiteralPath $tmp) {
        Add-HashFile $tmp
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

foreach ($h in $Hash) { Add-HashFile $h }
foreach ($c in $Cap) { Add-CapFile $c }

foreach ($dir in $CaptureDir) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    Write-Info ("  dir: " + $dir)
    $hashFiles = Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '\.(22000|hc22000)$' -or $_.Name -match '\.(22000|hc22000)$' }
    foreach ($f in $hashFiles) { Add-HashFile $f.FullName }

    $capFiles = Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '\.(cap|pcap|pcapng)$' }
    foreach ($f in $capFiles) { Add-CapFile $f.FullName }
}

if (-not (Test-Path -LiteralPath $Merged) -or ((Get-Item -LiteralPath $Merged).Length -eq 0)) {
    Write-Info "[!] no valid hashline. Put files in shared\captures or use -Hash / -Cap"
    exit 1
}

$allLines = Read-TextLines $Merged | Where-Object { $_ -and $_.Trim().StartsWith("WPA*") } | ForEach-Object { $_.Trim() } | Sort-Object -Unique
Write-AsciiFile $Hashes $allLines
$Total = $allLines.Count
Write-Info ""
Write-Info ("  total hashline: " + $Total)
Write-Info ""

$HcBase = @(
    "-m", "22000", $Hashes,
    "--potfile-path", $Potfile,
    "--outfile", $Outfile,
    "--outfile-format", "2",
    "-w", ("{0}" -f $Workload),
    "--status", "--status-timer", "15"
)

function Test-AllDone {
    if (-not (Test-Path -LiteralPath $Potfile)) { return $false }
    if ($Total -le 0) { return $false }
    $shown = & $Hashcat -m 22000 $Hashes --potfile-path $Potfile --show 2>$null
    if ($null -eq $shown) { return $false }
    $n = 0
    foreach ($line in $shown) {
        if ($line -match 'WPA\*') { $n++ }
    }
    return ($n -ge $Total)
}

function Invoke-DictAttack([string]$Name, [string]$DictPath) {
    if (Test-AllDone) { return }
    if (-not (Test-Path -LiteralPath $DictPath)) { return }

    $baseName = [System.IO.Path]::GetFileName($DictPath)
    $filtered = Join-Path $WorkDir ("filtered_" + $baseName)
    $src = Read-TextLines $DictPath
    $kept = New-Object System.Collections.Generic.List[string]
    foreach ($line in $src) {
        if ($null -eq $line) { continue }
        $w = $line.Trim()
        if ($w.Length -ge 8 -and $w.Length -le 63) {
            [void]$kept.Add($w)
        }
    }
    if ($kept.Count -lt 10) { return }
    Write-AsciiFile $filtered $kept.ToArray()

    Write-Info "----------------------------------------"
    Write-Info ("  " + $Name + " (" + $kept.Count + ")")
    Write-Info "----------------------------------------"
    & $Hashcat @HcBase -a 0 $filtered
}

function Invoke-RuleAttack([string]$Name, [string]$DictPath, [string]$RulePath) {
    if (Test-AllDone) { return }
    if (-not (Test-Path -LiteralPath $DictPath)) { return }
    if (-not (Test-Path -LiteralPath $RulePath)) { return }
    Write-Info "----------------------------------------"
    Write-Info ("  " + $Name)
    Write-Info "----------------------------------------"
    & $Hashcat @HcBase -a 0 $DictPath -r $RulePath
}

$RuleChina = Join-Path $DictDir "china-wifi.rule"
$MaskChina = Join-Path $DictDir "00-china-wifi-masks.hcmask"
$QuickHit = Join-Path $DictDir "cn-sources\latest\merged\cn-wifi-quickhit-8plus.txt"

Write-Info ">>>>>> stage0: top dicts <<<<<<"
Invoke-DictAttack "WPA Top4800" (Join-Path $DictDir "wpa-top4800.txt")
Invoke-DictAttack "probable-wpa" (Join-Path $DictDir "probable-wpa.txt")
if (Test-Path -LiteralPath $QuickHit) {
    Invoke-DictAttack "CN quickhit 8-63" $QuickHit
}
Invoke-DictAttack "cn-top100w" (Join-Path $DictDir "cn-top100w.txt")
Invoke-DictAttack "01-top500k" (Join-Path $DictDir "01-top500k.txt")

Write-Info ""
Write-Info ">>>>>> stage1: CN structure dicts <<<<<<"
foreach ($name in @(
    "05-chinese-full-410w.txt",
    "07-birthdays.txt",
    "08-names-pinyin.txt",
    "11-wpa-sec.txt",
    "12-pwdb-top1m.txt"
)) {
    Invoke-DictAttack $name (Join-Path $DictDir $name)
}

Write-Info ""
Write-Info ">>>>>> stage2: rules <<<<<<"
if (Test-Path -LiteralPath $RuleChina) {
    foreach ($name in @("wpa-top4800.txt", "probable-wpa.txt", "cn-top100w.txt", "01-top500k.txt", "07-birthdays.txt")) {
        $p = Join-Path $DictDir $name
        if (Test-Path -LiteralPath $p) {
            $sz = (Get-Item -LiteralPath $p).Length
            if ($sz -lt 52428800) {
                Invoke-RuleAttack ($name + " + china-wifi.rule") $p $RuleChina
            }
        }
    }
}

if (-not $SkipMasks -and (Test-Path -LiteralPath $MaskChina)) {
    Write-Info ""
    Write-Info ">>>>>> stage3: masks (first 40 lines) <<<<<<"
    $maskLines = Read-TextLines $MaskChina |
        Where-Object { $_ -and ($_.Trim().Length -gt 0) -and ($_ -notmatch '^\s*#') } |
        Select-Object -First 40
    $i = 0
    foreach ($m in $maskLines) {
        if (Test-AllDone) { break }
        $i++
        $mask = $m.Trim()
        Write-Info ("  mask [" + $i + "] " + $mask)
        & $Hashcat @HcBase -a 3 $mask
    }
}

Write-Info ""
Write-Info ">>>>>> done <<<<<<"
if (Test-Path -LiteralPath $Potfile) {
    $showOut = & $Hashcat -m 22000 $Hashes --potfile-path $Potfile --show 2>$null
    if ($null -ne $showOut) {
        $showOut | Out-File -FilePath $ResultFile -Encoding Default
        $showOut | ForEach-Object { Write-Info $_ }
    }
    Write-Info ("result: " + $ResultFile)
} else {
    Write-Info "no potfile (no hit yet)"
}

exit 0
