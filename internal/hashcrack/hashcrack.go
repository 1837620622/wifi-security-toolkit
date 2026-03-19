package hashcrack

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ============================================================
// hashcat离线破解模块
// 利用Apple M1 GPU（Metal后端）加速WPA/WPA2密码破解
// 支持: 字典攻击、掩码攻击、混合攻击、规则攻击
// ============================================================

// ============================================================
// HashcatResult 破解结果
// ============================================================
type HashcatResult struct {
	SSID      string        // 网络名称
	BSSID     string        // MAC地址
	Password  string        // 破解到的密码
	HashFile  string        // 使用的哈希文件
	Attack    string        // 攻击类型描述
	Speed     string        // 破解速度
	Duration  time.Duration // 耗时
	Success   bool          // 是否成功
	Error     string        // 错误信息
}

// ============================================================
// HashcatConfig 破解配置
// ============================================================
type HashcatConfig struct {
	HashFile    string        // 哈希文件路径（22000格式）
	Wordlists   []string      // 字典文件列表
	Rules       []string      // 规则文件列表
	MaskAttacks []string      // 掩码攻击列表
	Timeout     time.Duration // 总超时时间
	Workload    int           // 工作负载（1-4，默认3）
	Optimized   bool          // 使用优化内核
	Verbose     bool          // 详细日志
	PotFile     string        // 已破解密码存储文件
}

// ============================================================
// DefaultHashcatConfig 默认配置
// ============================================================
func DefaultHashcatConfig() HashcatConfig {
	return HashcatConfig{
		Workload:  3,
		Optimized: true,
		Verbose:   true,
		Timeout:   30 * time.Minute,
	}
}

// ============================================================
// CheckHashcat 检查hashcat是否可用及GPU信息
// ============================================================
func CheckHashcat() (bool, string) {
	path, err := exec.LookPath("hashcat")
	if err != nil {
		return false, "hashcat未安装，请执行: brew install hashcat"
	}

	// 获取版本
	cmd := exec.Command(path, "--version")
	out, err := cmd.Output()
	if err != nil {
		return false, "hashcat执行失败"
	}
	version := strings.TrimSpace(string(out))

	// 获取GPU信息
	cmd2 := exec.Command(path, "-I")
	out2, _ := cmd2.CombinedOutput()
	gpuInfo := ""
	for _, line := range strings.Split(string(out2), "\n") {
		if strings.Contains(line, "Name") && strings.Contains(line, "Apple") {
			gpuInfo = strings.TrimSpace(line)
			break
		}
	}

	info := fmt.Sprintf("hashcat %s", version)
	if gpuInfo != "" {
		info += fmt.Sprintf(" | GPU: %s", gpuInfo)
	}
	return true, info
}

// ============================================================
// Benchmark 运行WPA破解基准测试
// 返回: 速度（H/s）
// ============================================================
func Benchmark() (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "hashcat",
		"-b",
		"-m", "22000",
		"--machine-readable",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("基准测试失败: %w", err)
	}

	// 解析机器可读输出，格式: device:hashmode:...:speed
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "22000") && !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, ":")
			if len(parts) >= 6 {
				speed, _ := strconv.ParseFloat(parts[5], 64)
				return int64(speed), nil
			}
		}
	}

	return 0, fmt.Errorf("无法解析基准测试结果")
}

// ============================================================
// CrackWithDict 字典攻击
// hashcat -m 22000 -a 0 hash.22000 wordlist.txt
// ============================================================
func CrackWithDict(cfg HashcatConfig) HashcatResult {
	result := HashcatResult{
		HashFile: cfg.HashFile,
		Attack:   "字典攻击",
	}
	start := time.Now()

	if !fileExists(cfg.HashFile) {
		result.Error = "哈希文件不存在: " + cfg.HashFile
		return result
	}

	// 逐个字典尝试
	for _, wordlist := range cfg.Wordlists {
		if !fileExists(wordlist) {
			if cfg.Verbose {
				fmt.Printf("    ⚠ 字典不存在，跳过: %s\n", wordlist)
			}
			continue
		}

		if cfg.Verbose {
			wc := countLines(wordlist)
			fmt.Printf("    [*] 字典攻击: %s (%d条)\n", filepath.Base(wordlist), wc)
		}

		args := buildBaseArgs(cfg)
		args = append(args, "-a", "0") // 字典模式
		args = append(args, cfg.HashFile, wordlist)

		// 附加规则文件
		for _, rule := range cfg.Rules {
			if fileExists(rule) {
				args = append(args, "-r", rule)
			}
		}

		pwd, speed, err := runHashcat(args, cfg.Timeout)
		if err == nil && pwd != "" {
			result.Password = pwd
			result.Speed = speed
			result.Success = true
			result.Duration = time.Since(start)
			return result
		}

		if cfg.Verbose && speed != "" {
			fmt.Printf("      速度: %s | 未命中\n", speed)
		}
	}

	result.Duration = time.Since(start)
	result.Error = "字典攻击未命中"
	return result
}

// ============================================================
// CrackWithMask 掩码攻击（智能暴力破解）
// hashcat -m 22000 -a 3 hash.22000 ?d?d?d?d?d?d?d?d
// ============================================================
func CrackWithMask(cfg HashcatConfig) HashcatResult {
	result := HashcatResult{
		HashFile: cfg.HashFile,
		Attack:   "掩码攻击",
	}
	start := time.Now()

	if !fileExists(cfg.HashFile) {
		result.Error = "哈希文件不存在: " + cfg.HashFile
		return result
	}

	// 默认掩码列表（按耗时从短到长排列）
	masks := cfg.MaskAttacks
	if len(masks) == 0 {
		masks = DefaultMasks()
	}

	for _, mask := range masks {
		if cfg.Verbose {
			combos := estimateMaskCombinations(mask)
			fmt.Printf("    [*] 掩码攻击: %s (约%s组合)\n", mask, formatNumber(combos))
		}

		args := buildBaseArgs(cfg)
		args = append(args, "-a", "3") // 掩码模式
		args = append(args, cfg.HashFile, mask)

		pwd, speed, err := runHashcat(args, cfg.Timeout)
		if err == nil && pwd != "" {
			result.Password = pwd
			result.Speed = speed
			result.Success = true
			result.Duration = time.Since(start)
			return result
		}

		if cfg.Verbose && speed != "" {
			fmt.Printf("      速度: %s | 未命中\n", speed)
		}
	}

	result.Duration = time.Since(start)
	result.Error = "掩码攻击未命中"
	return result
}

// ============================================================
// CrackAll 综合攻击（字典 → 掩码，按优先级执行）
// ============================================================
func CrackAll(cfg HashcatConfig) HashcatResult {
	if cfg.Verbose {
		fmt.Println("\n  ╔══════════════════════════════════════════╗")
		fmt.Println("  ║   hashcat GPU离线破解引擎 (Metal)        ║")
		fmt.Println("  ╚══════════════════════════════════════════╝")
	}

	// 解析哈希文件中的SSID信息
	ssids := parseSSIDsFromHash(cfg.HashFile)
	ssidStr := "未知"
	if len(ssids) > 0 {
		ssidStr = strings.Join(ssids, ", ")
	}

	if cfg.Verbose {
		fmt.Printf("  [*] 哈希文件: %s\n", cfg.HashFile)
		fmt.Printf("  [*] 目标SSID: %s\n", ssidStr)
		hashCount := countLines(cfg.HashFile)
		fmt.Printf("  [*] 哈希数量: %d\n", hashCount)
	}

	// 阶段1: 字典攻击
	if len(cfg.Wordlists) > 0 {
		if cfg.Verbose {
			fmt.Println("\n  ── 阶段1: 字典攻击 ──")
		}
		result := CrackWithDict(cfg)
		if result.Success {
			result.SSID = ssidStr
			return result
		}
	}

	// 阶段2: 掩码攻击
	if cfg.Verbose {
		fmt.Println("\n  ── 阶段2: 掩码攻击（智能暴力） ──")
	}
	result := CrackWithMask(cfg)
	result.SSID = ssidStr
	return result
}

// ============================================================
// DefaultMasks 中国WiFi常用密码掩码（按耗时排序）
// M1 GPU约52000 H/s，每种掩码的预计耗时已标注
// ============================================================
func DefaultMasks() []string {
	return []string{
		// 8位纯数字（1亿组合，约32分钟）— 最常见的中国WiFi密码
		"?d?d?d?d?d?d?d?d",
		// 9位纯数字（10亿，约5.3小时）
		"?d?d?d?d?d?d?d?d?d",
		// 10位纯数字（100亿，约53小时）— 手机号
		"?d?d?d?d?d?d?d?d?d?d",
		// 11位纯数字（1000亿，约22天）— 完整手机号
		"?d?d?d?d?d?d?d?d?d?d?d",
		// 常见手机号前缀 + 8位数字
		"1?d?d?d?d?d?d?d?d?d?d",
	}
}

// ============================================================
// GenerateWordlist 从内存密码列表生成临时字典文件
// ============================================================
func GenerateWordlist(passwords []string, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}

	path := filepath.Join(outputDir, "wifi_wordlist.txt")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, pwd := range passwords {
		if len(pwd) >= 8 { // WPA最少8位
			w.WriteString(pwd + "\n")
		}
	}
	w.Flush()
	return path, nil
}

// ============================================================
// 内部辅助函数
// ============================================================

// buildBaseArgs 构建hashcat基础参数
func buildBaseArgs(cfg HashcatConfig) []string {
	args := []string{
		"-m", "22000",       // WPA-PBKDF2-PMKID+EAPOL模式
		"--potfile-disable", // 不使用potfile缓存（避免跳过已破解的哈希）
		"-w", strconv.Itoa(cfg.Workload),
	}

	if cfg.Optimized {
		args = append(args, "-O") // 使用优化内核（密码长度限制为32字符，WPA密码最长63足够）
	}

	// 如果指定了potfile路径，替换为自定义路径
	if cfg.PotFile != "" {
		newArgs := make([]string, 0, len(args))
		for _, a := range args {
			if a != "--potfile-disable" {
				newArgs = append(newArgs, a)
			}
		}
		newArgs = append(newArgs, "--potfile-path="+cfg.PotFile)
		args = newArgs
	}

	return args
}

// runHashcat 执行hashcat并解析结果
// 返回: (密码, 速度字符串, 错误)
func runHashcat(args []string, timeout time.Duration) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 创建临时输出文件用于获取破解结果
	tmpOut := filepath.Join(os.TempDir(), fmt.Sprintf("hashcat_out_%d.txt", time.Now().UnixNano()))
	defer os.Remove(tmpOut)

	// 安全拷贝参数并追加outfile（避免修改原始slice）
	fullArgs := make([]string, len(args))
	copy(fullArgs, args)
	fullArgs = append(fullArgs,
		"--outfile="+tmpOut,
		"--outfile-format=2", // 输出格式：仅密码
	)

	cmd := exec.CommandContext(ctx, "hashcat", fullArgs...)
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	// 提取速度信息
	speed := ""
	speedRe := regexp.MustCompile(`Speed\.#\d+.*?:\s+(\d+\.?\d*\s*\w?H/s)`)
	if m := speedRe.FindStringSubmatch(outStr); len(m) > 1 {
		speed = m[1]
	}

	// 方式1：从outfile读取密码（最可靠）
	if data, readErr := os.ReadFile(tmpOut); readErr == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			pwd := strings.TrimSpace(line)
			if pwd != "" && len(pwd) >= 8 {
				return pwd, speed, nil
			}
		}
	}

	// 方式2：检查输出中是否包含Cracked状态
	if strings.Contains(outStr, "Cracked") {
		// 用--show回查已破解密码
		// 注意: --show需要potfile才能工作，所以必须移除--potfile-disable
		// 同时--show不需要-w/-O等运行时参数
		showArgs := []string{"-m", "22000"}
		// 从原始参数中提取hash文件和字典/掩码（最后几个位置参数）
		for _, a := range args {
			// 保留hash文件路径（包含.22000的参数）
			if strings.HasSuffix(a, ".22000") || strings.HasSuffix(a, ".hc22000") {
				showArgs = append(showArgs, a)
			}
		}
		showArgs = append(showArgs, "--show")
		showCmd := exec.Command("hashcat", showArgs...)
		showOut, showErr := showCmd.CombinedOutput()
		if showErr == nil {
			for _, line := range strings.Split(string(showOut), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				// hashcat --show输出格式: hash:password
				if idx := strings.LastIndex(line, ":"); idx > 0 {
					pwd := line[idx+1:]
					if len(pwd) >= 8 {
						return pwd, speed, nil
					}
				}
			}
		}
	}

	// 检查是否是因为超时
	if ctx.Err() == context.DeadlineExceeded {
		return "", speed, fmt.Errorf("超时")
	}

	// hashcat退出码: 0=Cracked, 1=Exhausted, 其他=错误
	if err != nil && !strings.Contains(outStr, "Exhausted") {
		return "", speed, fmt.Errorf("hashcat执行错误: %w", err)
	}

	return "", speed, fmt.Errorf("未命中")
}

// parseSSIDsFromHash 从22000格式哈希文件中提取SSID
func parseSSIDsFromHash(hashFile string) []string {
	f, err := os.Open(hashFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ssids []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, "*")
		if len(parts) >= 6 {
			essidHex := parts[5]
			essid := hexToASCII(essidHex)
			if essid != "" && !seen[essid] {
				seen[essid] = true
				ssids = append(ssids, essid)
			}
		}
	}
	return ssids
}

// hexToASCII 将hex编码转为ASCII字符串
func hexToASCII(hexStr string) string {
	if len(hexStr)%2 != 0 {
		return ""
	}
	var result []byte
	for i := 0; i < len(hexStr); i += 2 {
		hi := hexVal(hexStr[i])
		lo := hexVal(hexStr[i+1])
		if hi < 0 || lo < 0 {
			return ""
		}
		b := byte(hi<<4 | lo)
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// fileExists 检查文件是否存在
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// countLines 统计文件行数
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		count++
	}
	return count
}

// estimateMaskCombinations 估算掩码组合数
func estimateMaskCombinations(mask string) int64 {
	var total int64 = 1
	i := 0
	for i < len(mask) {
		if mask[i] == '?' && i+1 < len(mask) {
			switch mask[i+1] {
			case 'd': // 0-9
				total *= 10
			case 'l': // a-z
				total *= 26
			case 'u': // A-Z
				total *= 26
			case 's': // 特殊字符
				total *= 33
			case 'a': // 所有可打印
				total *= 95
			default:
				total *= 95
			}
			i += 2
		} else {
			i++
		}
	}
	return total
}

// formatNumber 格式化大数字
func formatNumber(n int64) string {
	switch {
	case n >= 1e12:
		return fmt.Sprintf("%.1f万亿", float64(n)/1e12)
	case n >= 1e8:
		return fmt.Sprintf("%.1f亿", float64(n)/1e8)
	case n >= 1e4:
		return fmt.Sprintf("%.1f万", float64(n)/1e4)
	default:
		return fmt.Sprintf("%d", n)
	}
}
