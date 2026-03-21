package dict

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ============================================================
// TopPasswords 中国WiFi高频密码（静态部分）
// 数据来源：公开泄露的WiFi密码统计+中国用户习惯
// ============================================================
var TopPasswords = []string{
	// ── 第1梯队：超高频纯数字（命中率最高）──
	"12345678", "88888888", "00000000", "11111111", "66666666",
	"123456789", "1234567890", "0123456789", "87654321", "12341234",
	"11112222", "12121212", "99999999", "22222222", "33333333",
	"44444444", "55555555", "77777777", "98765432", "11223344",
	"13579246", "24681357", "01234567", "10203040", "56785678",
	"78907890", "43214321", "32103210", "11235813",

	// ── 第2梯队：情感/吉利数字 ──
	"52013141", "13145200", "52005200", "13141314", "52025202",
	"52145214", "52013520", "52101314", "05200520", "13140520",
	"15201314", "52001314", "13145201", "01314520", "51413141",
	"14725836", "15935728", "13572468", "15975328", "52052052",
	"13131313", "14141414", "10101010", "16881688", "18881888",
	"68886888", "11118888", "88881111", "66668888", "88886666",
	"11116666", "95279527", "95889588", "10086100", "10010100",
	"520131400", "131452000", "520520520",

	// ── 第3梯队：年份数字 ──
	"19801980", "19811981", "19821982", "19831983", "19841984",
	"19851985", "19861986", "19871987", "19881988", "19891989",
	"19901990", "19911991", "19921992", "19931993", "19941994",
	"19951995", "19961996", "19971997", "19981998", "19991999",
	"20002000", "20012001", "20022002", "20032003", "20042004",
	"20052005", "20062006", "20072007", "20082008", "20092009",
	"20102010", "20112011", "20122012", "20132013", "20142014",
	"20152015", "20162016", "20172017", "20182018", "20192019",
	"20202020", "20212021", "20222022", "20232023", "20242024",
	"20252025", "20262026", "19491949", "19491001", "19001900",

	// ── 第4梯队：字母+数字（常见弱口令）──
	"password", "admin123", "admin888", "password1", "abc12345",
	"abc123456", "a1234567", "a12345678", "aa123456", "asd12345",
	"asd123456", "qwe12345", "qwer1234", "asdf1234", "zxcv1234",
	"q1w2e3r4", "a1b2c3d4", "abcd1234", "1q2w3e4r", "1234abcd",
	"1234qwer", "wifi1234", "wifi12345", "wifi123456", "wlan1234",
	"net12345", "test1234", "pass1234", "pp123456", "aa112233",
	"zz123456", "qq123456", "ww123456", "ss123456", "dd123456",
	"ff123456", "gg123456", "hh123456", "jj123456", "kk123456",
	"ll123456", "mm123456", "nn123456", "bb123456", "cc123456",
	"xx123456", "vv123456",

	// ── 第5梯队：情感类字母密码 ──
	"iloveyou", "woaini52", "woaini520", "woaini1314", "5201314a",
	"aini1314", "love1314", "521woaini", "woaini00", "woaini01",
	"woaini11", "woaini12", "woaini88", "woaini99", "loveyou1",
	"iloveu88", "loveu520", "forever1", "happy123", "lucky888",

	// ── 第6梯队：键盘模式 ──
	"qwertyui", "asdfghjk", "zxcvbnm1", "1qaz2wsx", "qazwsxed",
	"qweasdzx", "zaqwsxcd", "1q2w3e4r5t", "q1w2e3r4t5", "poiuytre",
	"lkjhgfds", "mnbvcxza", "qwerty12", "qwerty123", "asdfgh12",
	"zxcvbn12", "1qazxsw2", "2wsxzaq1", "qwertyu1", "asdfghj1",
	"1234qwer", "qwer1234", "asdf1234", "zxcv1234",

	// ── 第7梯队：拼音类 ──
	"woshishui", "nihao123", "wodemima", "mima1234", "mima12345",
	"mimamima", "zhangsan", "wangwu12", "aaaaaa11", "aaaaaa88",
	"aabbccdd", "abcabc12", "abc12abc",
}

// ============================================================
// GenerateBirthdayPasswords 生成生日格式密码
// 全覆盖：1960-2010年 × 1-12月 × 1-31日
// 格式：YYYYMMDD / MMDDYYYY / DDMMYYYY
// ============================================================
func GenerateBirthdayPasswords() []string {
	var passwords []string
	daysInMonth := [13]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

	for year := 1960; year <= 2010; year++ {
		ys := fmt.Sprintf("%04d", year)
		yy := fmt.Sprintf("%02d", year%100)
		for month := 1; month <= 12; month++ {
			ms := fmt.Sprintf("%02d", month)
			for day := 1; day <= daysInMonth[month]; day++ {
				ds := fmt.Sprintf("%02d", day)
				// YYYYMMDD（最常见：19900520）
				passwords = append(passwords, ys+ms+ds)
				// MMDDYYYY（05201990）
				passwords = append(passwords, ms+ds+ys)
				// DDMMYYYY（20051990）
				passwords = append(passwords, ds+ms+ys)
				// YYMMDD + 两位后缀（9005200x）
				passwords = append(passwords, yy+ms+ds+"00")
				passwords = append(passwords, yy+ms+ds+"01")
			}
		}
	}
	return passwords
}

// ============================================================
// GeneratePhonePasswords 生成手机号相关密码
// 中国手机号格式：1xx-xxxx-xxxx（后8位是常见WiFi密码）
// ============================================================
func GeneratePhonePasswords() []string {
	var passwords []string

	// 中国手机号段前3位（2026年最新号段）
	prefixes := []string{
		"130", "131", "132", "133", "134", "135", "136", "137",
		"138", "139", "147", "148", "149",
		"150", "151", "152", "153", "155", "156", "157", "158", "159",
		"162", "165", "166", "167",
		"170", "171", "172", "173", "175", "176", "177", "178",
		"180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
		"190", "191", "192", "193", "195", "196", "197", "198", "199",
	}

	// 高频尾号（后8位 = 手机号去掉前3位）
	hotTails := []string{
		"00000000", "11111111", "22222222", "33333333",
		"44444444", "55555555", "66666666", "77777777",
		"88888888", "99999999", "12345678", "87654321",
		"11223344", "12341234", "00001234", "88886666",
		"66668888", "13141314", "52015201", "00008888",
	}
	passwords = append(passwords, hotTails...)

	// 完整11位手机号（运营商装机默认密码常为手机号）
	// 前缀 + 高频中间4位 + 高频尾4位
	midParts := []string{"0000", "1111", "1234", "5678", "8888", "6666", "9999"}
	endParts := []string{"0000", "1111", "1234", "5678", "6666", "8888", "9999", "6789"}
	for _, pf := range prefixes {
		for _, mid := range midParts {
			for _, end := range endParts {
				phone := pf + mid + end
				if len(phone) == 11 {
					passwords = append(passwords, phone)       // 完整11位
					passwords = append(passwords, phone[3:])   // 后8位
				}
			}
		}
	}

	// 运营商宽带默认密码格式：手机号后8位
	// 电信/移动/联通装机时常用手机号后8位作为WiFi默认密码
	for _, pf := range prefixes[:10] { // 取前10个高频号段
		// 后8位为连续数字
		for i := 0; i <= 99; i++ {
			tail := fmt.Sprintf("%04d%04d", i, i)
			passwords = append(passwords, pf+tail)    // 完整11位
			passwords = append(passwords, tail)         // 后8位
		}
	}

	return passwords
}

// ============================================================
// GenerateRepeatPatterns 生成重复模式密码
// 如：aabbccdd, 12312312, abcabc12 等
// ============================================================
func GenerateRepeatPatterns() []string {
	var passwords []string

	// AABBCCDD格式（10^4=10000种）
	for a := 0; a <= 9; a++ {
		for b := 0; b <= 9; b++ {
			for c := 0; c <= 9; c++ {
				for d := 0; d <= 9; d++ {
					passwords = append(passwords, fmt.Sprintf("%d%d%d%d%d%d%d%d", a, a, b, b, c, c, d, d))
				}
			}
		}
	}

	// ABCDABCD格式（4位重复）
	for n := 0; n <= 9999; n++ {
		s := fmt.Sprintf("%04d", n)
		passwords = append(passwords, s+s)
	}

	// ABABABAB格式（2位重复4次）
	for n := 0; n <= 99; n++ {
		s := fmt.Sprintf("%02d", n)
		passwords = append(passwords, s+s+s+s)
	}

	// 回文数字 ABCDDCBA
	for n := 0; n <= 9999; n++ {
		s := fmt.Sprintf("%04d", n)
		rev := string([]byte{s[3], s[2], s[1], s[0]})
		passwords = append(passwords, s+rev)
	}

	// 递增递减（全部起始点）
	for start := 0; start <= 9; start++ {
		up := ""
		down := ""
		for i := 0; i < 8; i++ {
			up += fmt.Sprintf("%d", (start+i)%10)
			down += fmt.Sprintf("%d", (start-i+10)%10)
		}
		passwords = append(passwords, up)
		passwords = append(passwords, down)
	}

	// 4位常见模式组合成8位
	patterns4 := []string{
		"0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777",
		"8888", "9999", "1234", "5678", "9012", "1314", "0520", "5201",
	}
	for _, p1 := range patterns4 {
		for _, p2 := range patterns4 {
			passwords = append(passwords, p1+p2)
		}
	}

	return passwords
}

// ============================================================
// GenerateRouterMAC 根据BSSID生成路由器MAC后缀密码
// 很多路由器默认密码是MAC地址后6位或后8位
// ============================================================
func GenerateRouterMAC(bssid string) []string {
	var passwords []string
	mac := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(bssid), ":", ""), "-", "")
	if len(mac) < 8 {
		return nil
	}
	// 后8位
	passwords = append(passwords, mac[len(mac)-8:])
	// 后6位补00
	if len(mac) >= 6 {
		passwords = append(passwords, mac[len(mac)-6:]+"00")
		passwords = append(passwords, "00"+mac[len(mac)-6:])
	}
	// 全12位MAC作密码
	if len(mac) == 12 {
		passwords = append(passwords, mac)
	}
	return passwords
}

// ============================================================
// GenerateISPDefaults 运营商装机默认密码
// 电信/移动/联通宽带装机时的常见默认WiFi密码格式
// ============================================================
func GenerateISPDefaults() []string {
	return []string{
		// 中国电信常见默认
		"telecomwifi", "chinanet1", "chinatel1",
		// 中国移动常见默认
		"cmcc12345", "cmcc123456", "10086wifi",
		// 中国联通常见默认
		"chinaunicom", "cucc12345",
		// 运营商8位数字默认（通常是装机工号或序列号后8位）
		"20230101", "20240101", "20250101", "20260101",
	}
}

// ============================================================
// GenerateCoreChinese 核心中国定制密码（仅内置生成，不含外部大字典）
// 用于 Phase 5a 在线爆破层，约10万条，预计30分钟内完成
// ============================================================
func GenerateCoreChinese() []string {
	var all []string
	// 按命中率排序：高频静态 → 运营商默认 → 生日 → 手机号 → 重复模式 → wpa-sec高频
	all = append(all, TopPasswords...)
	all = append(all, GenerateISPDefaults()...)
	all = append(all, GenerateBirthdayPasswords()...)
	all = append(all, GeneratePhonePasswords()...)
	all = append(all, GenerateRepeatPatterns()...)
	// 追加wpa-sec全球已破解密码字典（取前2万条高频，真实破解数据命中率高）
	if wpaSec := loadWPASecDict(); len(wpaSec) > 0 {
		all = append(all, wpaSec...)
	}
	return MergeAndDedup(all)
}

// ============================================================
// GenerateAllChinese 合并所有中国定制密码（含外部大字典）
// 用于 hashcat GPU 离线破解和 Phase 5b 兜底
// ============================================================
func GenerateAllChinese() []string {
	all := GenerateCoreChinese()
	// 追加本地 wifi_dict.txt 大字典（仅用于GPU离线破解或兜底层）
	if local := LoadLocalDict(); len(local) > 0 {
		all = append(all, local...)
	}
	return MergeAndDedup(all)
}

// ============================================================
// GenerateAllForTarget 针对特定目标生成在线爆破密码列表
// 只含核心内置密码 + MAC后缀，不含 wifi_dict.txt 大字典
// 用于 Phase 5a 在线爆破，控制在10万条以内
// ============================================================
func GenerateAllForTarget(ssid, bssid string) []string {
	var all []string
	// MAC地址后缀密码（排最前，因为很多路由器默认就是这个）
	all = append(all, GenerateRouterMAC(bssid)...)
	// 核心中国字典（不含外部大字典，约10万条）
	all = append(all, GenerateCoreChinese()...)
	return MergeAndDedup(all)
}

// ============================================================
// loadWPASecDict 加载wpa-sec全球已破解密码字典
// 文件名: wpa-sec-cracked.txt（来源: wpa-sec.stanev.org）
// 取前2万条高频密码（完整75万条用于在线爆破不现实，2万条已覆盖绝大部分真实WiFi密码）
// ============================================================
func loadWPASecDict() []string {
	const dictName = "wpa-sec-cracked.txt"
	const maxLines = 20000

	// 候选路径
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(real), dictName))
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), dictName))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, dictName))
	}

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()

		var passwords []string
		sc := bufio.NewScanner(f)
		for sc.Scan() && len(passwords) < maxLines {
			line := strings.TrimSpace(sc.Text())
			if line != "" && len(line) >= 8 {
				passwords = append(passwords, line)
			}
		}
		if len(passwords) > 0 {
			return passwords
		}
	}
	return nil
}

// ============================================================
// LoadDictFile 从文件加载额外密码字典
// 每行一个密码，自动去除空行和空格
// ============================================================
func LoadDictFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var passwords []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// WiFi密码最少8位（WPA/WPA2要求）
		if len(line) >= 8 {
			passwords = append(passwords, line)
		}
	}

	return passwords, sc.Err()
}

// ============================================================
// LoadLocalDict 自动检测并加载本地字典文件
// 检测顺序：
//  1. 可执行文件所在目录下的 wifi_dict.txt
//  2. 当前工作目录下的 wifi_dict.txt
//
// 如果文件不存在则静默返回 nil（不报错）
// ============================================================
func LoadLocalDict() []string {
	const dictName = "wifi_dict.txt"

	// 候选路径列表
	candidates := []string{}

	// 1. 可执行文件所在目录
	if exePath, err := exec.LookPath(os.Args[0]); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), dictName))
	}
	// os.Executable() 更可靠（已处理符号链接）
	if exe, err := os.Executable(); err == nil {
		// Eval symlinks 获取真实路径
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(real), dictName))
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), dictName))
	}

	// 2. 当前工作目录
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, dictName))
	}

	// 逐个尝试，找到第一个存在的文件
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			// 文件存在，尝试加载
			passwords, err := LoadDictFile(path)
			if err == nil && len(passwords) > 0 {
				return passwords
			}
		}
	}

	// 未找到本地字典，静默返回 nil
	return nil
}

// ============================================================
// MergeAndDedup 合并多个密码列表并去重（保持顺序）
// ============================================================
func MergeAndDedup(lists ...[]string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, list := range lists {
		for _, pwd := range list {
			if !seen[pwd] {
				seen[pwd] = true
				result = append(result, pwd)
			}
		}
	}

	return result
}
