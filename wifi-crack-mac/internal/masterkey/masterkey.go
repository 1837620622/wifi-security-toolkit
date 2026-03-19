package masterkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================
// [已废弃] WiFi万能钥匙API客户端
// 状态：2026年3月确认API已完全失效（返回appId不存在）
// 原因：连尚网络封禁了旧版逆向API协议（appId=0008）
// 保留此模块作为备用，新的在线密码查询已迁移到 p3wifi 模块
// ============================================================

// ============================================================
// 常量定义
// ============================================================
const (
	// AES密钥和IV（从逆向APK获取）
	mAesKey = "k%7Ve#8Ie!5Fb&8E"
	mAesIV  = "y!0Oe#2Wj#6Pw!3V"
	// 注册设备时的签名salt
	regSalt = "1Hf%5Yh&7Og$1Wh!6Vr&7Rs!3Nj#1Aa$"
	// User-Agent
	userAgent = "WiFiMasterKey/1.1.0 (Mac OS X Version 10.15.7 (Build 19H2))"
)

// ============================================================
// API端点列表（按优先级排列，自动尝试下一个）
// ============================================================
var apiEndpoints = []string{
	"http://wifiapi02.51y5.net/wifiapi/fa.cmd",
	"http://wifiapi01.51y5.net/wifiapi/fa.cmd",
	"http://ap.51y5.net/wifiapi/fa.cmd",
	"http://ap.51y5.net/ap/fa.sec",
}

// ============================================================
// Client 万能钥匙API客户端
// ============================================================
type Client struct {
	dhid      string // 设备ID（从服务器获取）
	salt      string // 签名salt（随服务器响应更新）
	ii        string // 设备标识
	mac       string // 虚拟MAC
	apiURL    string // 当前可用的API地址
	http      *http.Client
	mu        sync.Mutex
	inited    bool
	available bool // API是否可用
}

// ============================================================
// QueryResult 查询结果
// ============================================================
type QueryResult struct {
	SSID     string
	BSSID    string
	Password string
	Source   string
}

// ============================================================
// 全局客户端实例（懒初始化）
// ============================================================
var (
	globalClient *Client
	clientOnce   sync.Once
)

func getClient() *Client {
	clientOnce.Do(func() {
		globalClient = &Client{
			http: &http.Client{Timeout: 15 * time.Second},
		}
	})
	return globalClient
}

// ============================================================
// Available 检查万能钥匙API是否可用
// ============================================================
func Available() bool {
	c := getClient()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.available
}

// ============================================================
// Query 查询单个WiFi的万能钥匙密码（对外接口）
// API不可用时返回空字符串和nil（优雅降级，不阻塞流程）
// ============================================================
func Query(ssid, bssid string) (string, error) {
	if ssid == "" || bssid == "" {
		return "", fmt.Errorf("SSID和BSSID不能为空")
	}

	c := getClient()
	c.mu.Lock()
	defer c.mu.Unlock()

	// 确保已注册设备
	if !c.inited {
		err := c.registerDevice()
		c.inited = true // 标记已尝试，即使失败也不重复
		if err != nil {
			c.available = false
			return "", fmt.Errorf("API不可用: %w", err)
		}
		c.available = true
	}

	// API不可用时直接返回空（优雅降级）
	if !c.available {
		return "", nil
	}

	return c.requestPassword(ssid, normalizeBSSID(bssid))
}

// ============================================================
// registerDevice 注册虚拟设备，获取dhid
// ============================================================
func (c *Client) registerDevice() error {
	c.ii = mMd5(fmt.Sprintf("%d", rand.Intn(100000)))
	c.mac = c.ii[:12]

	data := map[string]string{
		"appid":   "0008",
		"chanid":  "gw",
		"ii":      c.ii,
		"imei":    c.ii,
		"lang":    "cn",
		"mac":     c.mac,
		"manuf":   "Apple",
		"method":  "getTouristSwitch",
		"misc":    "Mac OS",
		"model":   "10.15.7",
		"os":      "Mac OS",
		"osver":   "10.15.7",
		"osvercd": "10.15.7",
		"pid":     "initdev:commonswitch",
		"scrl":    "900",
		"scrs":    "1440",
		"wkver":   "324",
		"st":      "m",
		"v":       "324",
	}
	data["sign"] = signData(data, regSalt)

	// 逐个尝试API端点
	var result map[string]interface{}
	var lastErr error
	for _, endpoint := range apiEndpoints {
		c.apiURL = endpoint
		result, lastErr = c.doPost(data)
		if lastErr == nil && result != nil {
			break
		}
	}
	if lastErr != nil || result == nil {
		if lastErr != nil {
			return fmt.Errorf("所有API端点均不可用: %w", lastErr)
		}
		return fmt.Errorf("所有API端点均返回空响应")
	}

	retCd, _ := result["retCd"].(string)
	if retCd != "0" {
		retMsg, _ := result["retMsg"].(string)
		return fmt.Errorf("注册返回错误: %s - %s", retCd, retMsg)
	}

	// 提取dhid
	initdev, ok := result["initdev"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("响应中缺少initdev字段")
	}

	devRetCd, _ := initdev["retCd"].(string)
	if devRetCd != "0" {
		return fmt.Errorf("设备注册子错误: %s", devRetCd)
	}

	dhid, ok := initdev["dhid"].(string)
	if !ok || dhid == "" {
		return fmt.Errorf("响应中缺少dhid")
	}

	c.dhid = dhid
	c.salt = regSalt

	// 更新salt（如果服务器返回了retSn）
	if retSn, ok := result["retSn"].(string); ok && retSn != "" {
		c.salt = retSn
	}

	return nil
}

// ============================================================
// requestPassword 查询WiFi密码
// ============================================================
func (c *Client) requestPassword(ssid, bssid string) (string, error) {
	data := map[string]string{
		"appid":  "0008",
		"bssid":  bssid,
		"chanid": "gw",
		"dhid":   c.dhid,
		"ii":     c.ii,
		"lang":   "cn",
		"mac":    c.mac,
		"method": "getDeepSecChkSwitch",
		"pid":    "qryapwd:commonswitch",
		"ssid":   ssid,
		"st":     "m",
		"uhid":   "a0000000000000000000000000000001",
		"v":      "324",
	}
	data["sign"] = signData(data, c.salt)

	result, err := c.doPost(data)
	if err != nil {
		return "", err
	}

	// 更新salt
	if retSn, ok := result["retSn"].(string); ok && retSn != "" {
		c.salt = retSn
	}

	retCd, _ := result["retCd"].(string)

	// -1111 表示需要重试
	if retCd == "-1111" {
		return "", fmt.Errorf("服务器繁忙，需重试")
	}

	if retCd != "0" {
		retMsg, _ := result["retMsg"].(string)
		return "", fmt.Errorf("查询错误: %s - %s", retCd, retMsg)
	}

	// 提取密码
	qryapwd, ok := result["qryapwd"].(map[string]interface{})
	if !ok {
		return "", nil // 未收录
	}

	qryCd, _ := qryapwd["retCd"].(string)
	if qryCd != "0" {
		return "", nil // 未收录
	}

	psws, ok := qryapwd["psws"].(map[string]interface{})
	if !ok {
		return "", nil
	}

	// 遍历结果查找密码
	for _, v := range psws {
		wifi, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		pwdHex, _ := wifi["pwd"].(string)
		if pwdHex == "" {
			continue
		}
		// AES解密密码字段
		// 格式：[3字节长度][密码][13字节时间戳]
		decrypted := decryptPwd(pwdHex)
		if decrypted != "" {
			return decrypted, nil
		}
	}

	return "", nil
}

// ============================================================
// doPost 发送HTTP POST请求并解析JSON
// ============================================================
func (c *Client) doPost(data map[string]string) (map[string]interface{}, error) {
	formData := url.Values{}
	for k, v := range data {
		formData.Set(k, v)
	}

	req, err := http.NewRequest("POST", c.apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w, 响应: %s", err, string(body[:min(200, len(body))]))
	}

	return result, nil
}

// ============================================================
// 签名计算：所有value按key排序拼接 + salt → MD5
// ============================================================
func signData(data map[string]string, salt string) string {
	var keys []string
	for k := range data {
		if k != "sign" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(data[k])
	}
	sb.WriteString(salt)
	return strings.ToUpper(mMd5(sb.String()))
}

// ============================================================
// AES CBC解密（NoPadding模式）
// ============================================================
func aesDecryptNoPad(cipherHex string) (string, error) {
	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(mAesKey))
	if err != nil {
		return "", err
	}

	if len(cipherBytes)%aes.BlockSize != 0 {
		return "", fmt.Errorf("密文长度错误")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(mAesIV))
	mode.CryptBlocks(cipherBytes, cipherBytes)

	// NoPadding: 去除尾部空白
	return strings.TrimSpace(string(cipherBytes)), nil
}

// ============================================================
// 解密密码字段：[3字节长度][密码][13字节时间戳]
// ============================================================
func decryptPwd(pwdHex string) string {
	decrypted, err := aesDecryptNoPad(pwdHex)
	if err != nil || len(decrypted) < 17 {
		return ""
	}
	// 前3字节是长度，后13字节是时间戳，中间是密码
	pwd := decrypted[3 : len(decrypted)-13]
	pwd = strings.TrimSpace(pwd)
	// URL解码
	decoded, err := url.QueryUnescape(pwd)
	if err != nil {
		return pwd
	}
	return decoded
}

// ============================================================
// MD5哈希
// ============================================================
func mMd5(s string) string {
	h := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}

// ============================================================
// 标准化BSSID格式（小写，冒号分隔）
// ============================================================
func normalizeBSSID(bssid string) string {
	bssid = strings.ReplaceAll(bssid, ":", "")
	bssid = strings.ReplaceAll(bssid, "-", "")
	bssid = strings.ToLower(bssid)
	if len(bssid) == 12 {
		parts := make([]string, 6)
		for i := 0; i < 6; i++ {
			parts[i] = bssid[i*2 : i*2+2]
		}
		return strings.Join(parts, ":")
	}
	return bssid
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
