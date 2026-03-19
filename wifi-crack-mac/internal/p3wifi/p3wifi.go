package p3wifi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ============================================================
// p3wifi 全球WiFi密码共享库客户端
// 基于 3wifi.dev 开放API（原3WiFi项目的公共镜像）
// 数据库包含全球数千万条WiFi密码记录，支持BSSID/ESSID查询
// API无需认证，直接GET请求即可
// ============================================================

// ============================================================
// API端点配置
// ============================================================
const (
	// 主API端点
	apiBaseURL = "https://3wifi.dev/api/apiquery"
	// 请求超时
	apiTimeout = 15 * time.Second
	// User-Agent
	userAgent = "WiFiCracker/3.0 (macOS; Security-Audit)"
)

// ============================================================
// APIResponse p3wifi API响应结构
// ============================================================
type APIResponse struct {
	Result bool                       `json:"result"`
	Data   map[string][]WiFiRecord    `json:"data"`
	Error  string                     `json:"error,omitempty"`
}

// ============================================================
// WiFiRecord 单条WiFi密码记录
// ============================================================
type WiFiRecord struct {
	ID    int     `json:"id"`
	BSSID string  `json:"bssid"`
	ESSID string  `json:"essid"`
	Time  string  `json:"time"`
	Key   string  `json:"key"`   // WiFi密码
	WPS   any     `json:"wps"`   // WPS PIN（可能是int或null）
	Sec   string  `json:"sec"`   // 安全类型
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
}

// ============================================================
// QueryResult 查询结果（对外返回的简化结构）
// ============================================================
type QueryResult struct {
	BSSID    string // 目标MAC
	ESSID    string // 网络名称
	Password string // WiFi密码
	WPS      string // WPS PIN
	Security string // 安全类型
	Source   string // 数据来源描述
}

// ============================================================
// 全局HTTP客户端（复用连接）
// ============================================================
var (
	httpClient *http.Client
	clientOnce sync.Once
	available  = true
	mu         sync.Mutex
)

func getHTTPClient() *http.Client {
	clientOnce.Do(func() {
		httpClient = &http.Client{
			Timeout: apiTimeout,
		}
	})
	return httpClient
}

// ============================================================
// Available 检查API是否可用
// ============================================================
func Available() bool {
	mu.Lock()
	defer mu.Unlock()
	return available
}

// ============================================================
// QueryByBSSID 通过BSSID查询WiFi密码
// 返回: 密码字符串（空=未收录），错误
// ============================================================
func QueryByBSSID(bssid string) (string, error) {
	if bssid == "" {
		return "", fmt.Errorf("BSSID不能为空")
	}

	// 标准化BSSID格式（大写，冒号分隔）
	bssid = normalizeBSSID(bssid)

	results, err := apiQuery("bssid", bssid)
	if err != nil {
		mu.Lock()
		available = false
		mu.Unlock()
		return "", err
	}

	mu.Lock()
	available = true
	mu.Unlock()

	// 从结果中提取有效密码
	for _, records := range results {
		for _, r := range records {
			pwd := strings.TrimSpace(r.Key)
			// 过滤无效密码
			if pwd != "" && pwd != "<empty>" && pwd != "<none>" && len(pwd) >= 8 {
				return pwd, nil
			}
		}
	}

	return "", nil
}

// ============================================================
// QueryFull 完整查询，返回所有匹配记录
// 支持按BSSID或ESSID查询
// ============================================================
func QueryFull(bssid, essid string) ([]QueryResult, error) {
	var queryType, queryValue string
	if bssid != "" {
		queryType = "bssid"
		queryValue = normalizeBSSID(bssid)
	} else if essid != "" {
		queryType = "essid"
		queryValue = essid
	} else {
		return nil, fmt.Errorf("BSSID和ESSID不能同时为空")
	}

	data, err := apiQuery(queryType, queryValue)
	if err != nil {
		return nil, err
	}

	var results []QueryResult
	seen := make(map[string]bool)
	for _, records := range data {
		for _, r := range records {
			pwd := strings.TrimSpace(r.Key)
			if pwd == "" || pwd == "<empty>" || pwd == "<none>" {
				continue
			}
			// 用密码去重（同一个AP可能有多条历史记录）
			if seen[pwd] {
				continue
			}
			seen[pwd] = true

			wpsStr := ""
			if r.WPS != nil {
				wpsStr = fmt.Sprintf("%v", r.WPS)
			}

			results = append(results, QueryResult{
				BSSID:    r.BSSID,
				ESSID:    r.ESSID,
				Password: pwd,
				WPS:      wpsStr,
				Security: r.Sec,
				Source:    fmt.Sprintf("3wifi.dev (记录时间: %s)", r.Time),
			})
		}
	}

	return results, nil
}

// ============================================================
// apiQuery 执行API查询
// ============================================================
func apiQuery(queryType, queryValue string) (map[string][]WiFiRecord, error) {
	// 构建URL
	reqURL := fmt.Sprintf("%s?%s=%s", apiBaseURL, queryType, url.QueryEscape(queryValue))

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("API请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API返回HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w", err)
	}

	if !apiResp.Result {
		errMsg := apiResp.Error
		if errMsg == "" {
			errMsg = "未知错误"
		}
		return nil, fmt.Errorf("API错误: %s", errMsg)
	}

	return apiResp.Data, nil
}

// ============================================================
// DownloadWPASecDict 下载wpa-sec.stanev.org已破解密码字典
// 这是全球社区分布式破解的真实WiFi密码，按频率排序
// 文件大小约3.5MB（gzip压缩），解压后约20MB
// ============================================================
func DownloadWPASecDict(outputPath string) (int, error) {
	dictURL := "https://wpa-sec.stanev.org/dict/cracked.txt.gz"

	req, err := http.NewRequest("GET", dictURL, nil)
	if err != nil {
		return 0, fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// 读取gzip压缩的内容
	compressed, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("读取失败: %w", err)
	}

	// 解压gzip
	gzReader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return 0, fmt.Errorf("gzip解压失败: %w", err)
	}
	defer gzReader.Close()

	data, err := io.ReadAll(gzReader)
	if err != nil {
		return 0, fmt.Errorf("解压读取失败: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("创建文件失败: %w", err)
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return 0, fmt.Errorf("写入失败: %w", err)
	}

	// 统计行数
	lineCount := 0
	for _, b := range data {
		if b == '\n' {
			lineCount++
		}
	}

	return lineCount, nil
}

// ============================================================
// normalizeBSSID 标准化BSSID格式（大写，冒号分隔）
// ============================================================
func normalizeBSSID(bssid string) string {
	bssid = strings.ReplaceAll(bssid, "-", ":")
	bssid = strings.ToUpper(bssid)
	// 如果没有冒号分隔，插入冒号
	clean := strings.ReplaceAll(bssid, ":", "")
	if len(clean) == 12 && !strings.Contains(bssid, ":") {
		parts := make([]string, 6)
		for i := 0; i < 6; i++ {
			parts[i] = clean[i*2 : i*2+2]
		}
		return strings.Join(parts, ":")
	}
	return bssid
}
