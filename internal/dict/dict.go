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
// 覆盖：19700101-20101231 中常见月日组合
// ============================================================
func GenerateBirthdayPasswords() []string {
	var passwords []string

	// 常见月日（高频日期优先）
	hotDates := []string{
		"0101", "0214", "0314", "0401", "0404", "0501", "0520",
		"0601", "0606", "0701", "0707", "0801", "0815", "0910",
		"1001", "1010", "1111", "1212", "1224", "1225", "1231",
	}

	// 年份范围：1970-2010（WiFi设置者的生日年份范围）
	for year := 1970; year <= 2010; year++ {
		ys := fmt.Sprintf("%d", year)
		for _, md := range hotDates {
			passwords = append(passwords, ys+md) // 19900520
		}
	}

	// 月日+年份 反向格式（如 05201990）
	for _, md := range hotDates {
		for _, year := range []int{1985, 1990, 1995, 2000, 2005} {
			passwords = append(passwords, md+fmt.Sprintf("%d", year))
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

	// 中国手机号段前3位
	prefixes := []string{
		"130", "131", "132", "133", "134", "135", "136", "137",
		"138", "139", "150", "151", "152", "153", "155", "156",
		"157", "158", "159", "166", "170", "171", "172", "175",
		"176", "177", "178", "180", "181", "182", "183", "184",
		"185", "186", "187", "188", "189", "191", "193", "195",
		"196", "197", "198", "199",
	}

	// 高频尾号模式（后8位 = 手机号去掉前3位）
	hotTails := []string{
		"00000000", "11111111", "22222222", "33333333",
		"44444444", "55555555", "66666666", "77777777",
		"88888888", "99999999", "12345678", "87654321",
	}
	passwords = append(passwords, hotTails...)

	// 前缀+常见4位尾号 → 截取后8位作为密码
	commonEnds := []string{"0000", "1111", "1234", "5678", "6666", "8888", "9999", "6789"}
	for _, pf := range prefixes {
		for _, end := range commonEnds {
			phone := pf + "0000" + end // 模拟11位手机号
			// 取后8位
			if len(phone) >= 8 {
				passwords = append(passwords, phone[len(phone)-8:])
			}
			// 也加入完整11位作为密码（部分路由器密码设为手机号）
			full := pf + "0000" + end
			if len(full) == 11 {
				passwords = append(passwords, full)
			}
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

	// 数字重复：AABBCCDD格式
	for a := 0; a <= 9; a++ {
		for b := 0; b <= 9; b++ {
			if a == b {
				continue
			}
			s := fmt.Sprintf("%d%d%d%d%d%d%d%d", a, a, b, b, a, a, b, b)
			passwords = append(passwords, s)
			// AAAABBBB格式
			s2 := fmt.Sprintf("%d%d%d%d%d%d%d%d", a, a, a, a, b, b, b, b)
			passwords = append(passwords, s2)
		}
	}

	// 数字递增递减模式
	for start := 0; start <= 2; start++ {
		s := ""
		for i := 0; i < 8; i++ {
			s += fmt.Sprintf("%d", (start+i)%10)
		}
		passwords = append(passwords, s)
	}

	return passwords
}

// ============================================================
// GenerateAllChinese 合并所有中国定制密码
// 按优先级排列，高命中率优先
// 同时自动加载本地 wifi_dict.txt（如果存在）
// ============================================================
func GenerateAllChinese() []string {
	var all []string
	all = append(all, TopPasswords...)
	all = append(all, GenerateBirthdayPasswords()...)
	all = append(all, GeneratePhonePasswords()...)
	all = append(all, GenerateRepeatPatterns()...)
	// 追加本地字典（如果存在）
	if local := LoadLocalDict(); len(local) > 0 {
		all = append(all, local...)
	}
	return MergeAndDedup(all)
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
