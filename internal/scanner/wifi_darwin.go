package scanner

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation -framework CoreLocation

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>

// ============================================================
// WiFi网络信息结构体（C桥接）
// ============================================================
typedef struct {
    const char *ssid;
    const char *bssid;
    int         rssi;
    const char *security;
    int         channel;
} CWifiNetwork;

// ============================================================
// 扫描结果容器
// ============================================================
typedef struct {
    CWifiNetwork *networks;
    int           count;
} CScanResult;

// ============================================================
// CoreLocation代理（用于触发位置权限弹窗）
// ============================================================
@interface LocationDelegate : NSObject <CLLocationManagerDelegate>
@property (nonatomic, assign) BOOL authorized;
@end

@implementation LocationDelegate
- (void)locationManager:(CLLocationManager *)manager
    didChangeAuthorizationStatus:(CLAuthorizationStatus)status {
    if (status == kCLAuthorizationStatusAuthorizedAlways ||
        status == kCLAuthorizationStatusAuthorized) {
        self.authorized = YES;
    }
}
@end

// ============================================================
// 确保位置权限已授予（SSID可见的前提条件）
// 返回: 1=已授权, 0=未授权
// ============================================================
int ensure_location_authorized() {
    @autoreleasepool {
        CLAuthorizationStatus status = [CLLocationManager authorizationStatus];
        if (status == kCLAuthorizationStatusAuthorizedAlways ||
            status == kCLAuthorizationStatusAuthorized) {
            return 1;
        }

        // 尝试触发位置权限请求
        CLLocationManager *mgr = [[CLLocationManager alloc] init];
        LocationDelegate *delegate = [[LocationDelegate alloc] init];
        mgr.delegate = delegate;
        [mgr startUpdatingLocation];

        // 等待最多3秒
        for (int i = 0; i < 30; i++) {
            [[NSRunLoop currentRunLoop] runUntilDate:
                [NSDate dateWithTimeIntervalSinceNow:0.1]];
            if (delegate.authorized) {
                [mgr stopUpdatingLocation];
                return 1;
            }
        }
        [mgr stopUpdatingLocation];

        // 再检查一次
        status = [CLLocationManager authorizationStatus];
        return (status == kCLAuthorizationStatusAuthorizedAlways ||
                status == kCLAuthorizationStatusAuthorized) ? 1 : 0;
    }
}

// ============================================================
// 获取位置权限状态描述
// ============================================================
const char* location_status() {
    @autoreleasepool {
        CLAuthorizationStatus s = [CLLocationManager authorizationStatus];
        if (s == kCLAuthorizationStatusNotDetermined) {
            return strdup("未决定");
        } else if (s == kCLAuthorizationStatusRestricted) {
            return strdup("受限");
        } else if (s == kCLAuthorizationStatusDenied) {
            return strdup("已拒绝");
        } else if (s == kCLAuthorizationStatusAuthorizedAlways) {
            return strdup("已授权");
        } else {
            return strdup("未知");
        }
    }
}

// ============================================================
// 获取当前连接的WiFi SSID
// ============================================================
const char* current_ssid() {
    @autoreleasepool {
        CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
        NSString *ssid = [iface ssid];
        if (ssid) {
            return strdup([ssid UTF8String]);
        }
        return strdup("");
    }
}

// ============================================================
// 扫描周围WiFi网络
// ============================================================
CScanResult scan_wifi() {
    CScanResult result = {NULL, 0};

    @autoreleasepool {
        CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
        if (!iface) {
            return result;
        }

        NSError *error = nil;
        NSSet<CWNetwork *> *networks = [iface scanForNetworksWithName:nil error:&error];
        if (error || !networks || [networks count] == 0) {
            return result;
        }

        int count = (int)[networks count];
        result.networks = (CWifiNetwork *)calloc(count, sizeof(CWifiNetwork));
        result.count = count;

        int i = 0;
        for (CWNetwork *net in networks) {
            NSString *ssid  = [net ssid] ?: @"";
            NSString *bssid = [net bssid] ?: @"";

            // 安全类型字符串（Enterprise优先判断，避免被Personal覆盖）
            NSString *secStr = @"Open";
            if ([net supportsSecurity:kCWSecurityWPA2Enterprise] ||
                [net supportsSecurity:kCWSecurityWPA3Enterprise]) {
                secStr = @"Enterprise";
            } else if ([net supportsSecurity:kCWSecurityWPA2Personal] ||
                [net supportsSecurity:kCWSecurityWPA3Personal]) {
                secStr = @"WPA2/WPA3";
            } else if ([net supportsSecurity:kCWSecurityWPAPersonal]) {
                secStr = @"WPA";
            } else if ([net supportsSecurity:kCWSecurityWEP]) {
                secStr = @"WEP";
            }

            result.networks[i].ssid     = strdup([ssid UTF8String]);
            result.networks[i].bssid    = strdup([bssid UTF8String]);
            result.networks[i].rssi     = (int)[net rssiValue];
            result.networks[i].security = strdup([secStr UTF8String]);
            result.networks[i].channel  = (int)[[net wlanChannel] channelNumber];
            i++;
        }
        result.count = i;
    }

    return result;
}

// ============================================================
// 释放扫描结果内存
// ============================================================
void free_scan_result(CScanResult *r) {
    if (!r || !r->networks) return;
    for (int i = 0; i < r->count; i++) {
        free((void *)r->networks[i].ssid);
        free((void *)r->networks[i].bssid);
        free((void *)r->networks[i].security);
    }
    free(r->networks);
    r->networks = NULL;
    r->count = 0;
}

// ============================================================
// 断开当前WiFi连接
// ============================================================
void disconnect_wifi() {
    @autoreleasepool {
        CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
        [iface disassociate];
    }
}

// ============================================================
// 连接到指定WiFi（用密码尝试）
// 返回: 0=成功, -1=失败
// ============================================================
int connect_wifi(const char *ssid, const char *password) {
    @autoreleasepool {
        CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
        if (!iface) return -1;

        NSError *error = nil;
        NSSet<CWNetwork *> *networks = [iface scanForNetworksWithName:
            [NSString stringWithUTF8String:ssid] error:&error];
        if (error || !networks || [networks count] == 0) {
            return -1;
        }

        CWNetwork *target = [networks anyObject];
        error = nil;
        BOOL ok = [iface associateToNetwork:target
                   password:[NSString stringWithUTF8String:password]
                   error:&error];
        return ok ? 0 : -1;
    }
}
*/
import "C"

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"unsafe"
)

// ============================================================
// WiFiNetwork WiFi网络信息
// ============================================================
type WiFiNetwork struct {
	SSID     string // 网络名称
	BSSID    string // MAC地址
	RSSI     int    // 信号强度
	Security string // 安全类型
	Channel  int    // 频道
}

// ============================================================
// EnsureLocation 确保位置权限已授予
// 返回: true=已授权
// ============================================================
func EnsureLocation() bool {
	return C.ensure_location_authorized() == 1
}

// ============================================================
// LocationStatus 获取当前位置权限状态描述
// ============================================================
func LocationStatus() string {
	cs := C.location_status()
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}

// ============================================================
// ScanWiFi 扫描周围WiFi网络
// 优先用CGO CoreWLAN扫描；若SSID为空则回退Python扫描
// ============================================================
func ScanWiFi() ([]WiFiNetwork, error) {
	// 先确保位置权限
	EnsureLocation()

	result := C.scan_wifi()
	defer C.free_scan_result(&result)

	if result.count == 0 {
		// CGO扫描无结果，直接回退Python
		return scanViaPython()
	}

	// 将C结构体数组转为Go切片
	cNets := unsafe.Slice(result.networks, result.count)
	nets := make([]WiFiNetwork, 0, result.count)
	hasSSID := false

	for _, cn := range cNets {
		ssid := C.GoString(cn.ssid)
		if ssid != "" {
			hasSSID = true
		}
		nets = append(nets, WiFiNetwork{
			SSID:     ssid,
			BSSID:    C.GoString(cn.bssid),
			RSSI:     int(cn.rssi),
			Security: C.GoString(cn.security),
			Channel:  int(cn.channel),
		})
	}

	// 如果SSID全部为空（位置权限问题），回退Python扫描
	if !hasSSID {
		pyNets, err := scanViaPython()
		if err == nil && len(pyNets) > 0 {
			return pyNets, nil
		}
		// Python也失败了，返回CGO结果（虽然SSID为空）
	}

	return nets, nil
}

// ============================================================
// scanViaPython 通过Python+CoreWLAN扫描（回退方案）
// Python通常已有位置权限，可以获取完整SSID
// ============================================================
func scanViaPython() ([]WiFiNetwork, error) {
	// Python脚本：用CoreWLAN扫描并输出JSON
	pyCode := `
import json, sys
try:
    import CoreWLAN
    client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
    iface = client.interface()
    nets, _ = iface.scanForNetworksWithName_error_(None, None)
    result = []
    for n in nets:
        sec = "Open"
        # CWSecurity枚举: 0=None, 1=WEP, 2=WPAPersonal, 3=WPA2Personal
        # 4=WPA2PersonalMixed, 5=WPA3Personal, 6=DynamicWEP, 7=WPAEnterprise
        # 8=WPA2Enterprise, 9=WPA2EnterpriseMixed, 10=WPA3Enterprise
        # 11=WPA3EnterpriseMixed, 13=WPA3Transition, 15=OWE
        if n.supportsSecurity_(8) or n.supportsSecurity_(9) or \
           n.supportsSecurity_(10) or n.supportsSecurity_(11):
            sec = "Enterprise"
        elif n.supportsSecurity_(3) or n.supportsSecurity_(4) or \
             n.supportsSecurity_(5) or n.supportsSecurity_(13):
            sec = "WPA2/WPA3"
        elif n.supportsSecurity_(2):
            sec = "WPA"
        elif n.supportsSecurity_(1):
            sec = "WEP"
        elif n.supportsSecurity_(15):
            sec = "OWE"
        result.append({
            "ssid": n.ssid() or "",
            "bssid": n.bssid() or "",
            "rssi": int(n.rssiValue()),
            "security": sec,
            "channel": int(n.wlanChannel().channelNumber()),
        })
    json.dump(result, sys.stdout, ensure_ascii=False)
except Exception as e:
    json.dump([], sys.stdout)
`
	// 按优先级尝试多个Python路径（需要有pyobjc/CoreWLAN模块）
	pythonPaths := []string{
		"/opt/miniconda3/bin/python3",
		"/opt/homebrew/bin/python3",
		"/usr/local/bin/python3",
		"/usr/bin/python3",
	}

	// 也尝试 PATH 中的 python3
	if p, err := exec.LookPath("python3"); err == nil {
		// 去重：放到最前面
		found := false
		for _, pp := range pythonPaths {
			if pp == p {
				found = true
				break
			}
		}
		if !found {
			pythonPaths = append([]string{p}, pythonPaths...)
		}
	}

	var lastErr error
	for _, pyPath := range pythonPaths {
		cmd := exec.Command(pyPath, "-c", pyCode)
		out, err := cmd.Output()
		if err != nil {
			lastErr = err
			continue
		}

		var pyNets []struct {
			SSID     string `json:"ssid"`
			BSSID    string `json:"bssid"`
			RSSI     int    `json:"rssi"`
			Security string `json:"security"`
			Channel  int    `json:"channel"`
		}

		if err := json.Unmarshal(out, &pyNets); err != nil {
			lastErr = err
			continue
		}

		// 检查是否有有效SSID
		hasSSID := false
		for _, pn := range pyNets {
			if pn.SSID != "" {
				hasSSID = true
				break
			}
		}
		if !hasSSID {
			continue
		}

		nets := make([]WiFiNetwork, 0, len(pyNets))
		for _, pn := range pyNets {
			nets = append(nets, WiFiNetwork{
				SSID:     pn.SSID,
				BSSID:    pn.BSSID,
				RSSI:     pn.RSSI,
				Security: pn.Security,
				Channel:  pn.Channel,
			})
		}
		return nets, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

// ============================================================
// CurrentSSID 获取当前连接的WiFi名称
// ============================================================
func CurrentSSID() string {
	cs := C.current_ssid()
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs)
}

// ============================================================
// TryConnect 尝试用密码连接WiFi
// 返回: true=连接成功
// ============================================================
func TryConnect(ssid, password string) bool {
	cs := C.CString(ssid)
	cp := C.CString(password)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(cp))
	return C.connect_wifi(cs, cp) == 0
}

// ============================================================
// DisconnectWiFi 断开当前WiFi
// ============================================================
func DisconnectWiFi() {
	C.disconnect_wifi()
}

// ============================================================
// FilterAndSort 过滤并排序WiFi列表
// 过滤规则：去掉校园网、Portal认证、企业网、开放网络、重复SSID
// 排序规则：信号强度从强到弱
// ============================================================
func FilterAndSort(nets []WiFiNetwork) []WiFiNetwork {
	// 校园网/Portal/热点关键词（全小写匹配）
	skipKeywords := []string{
		// 校园网
		"eduroam", "ixaut", "snut", "campus", "university",
		"school", "college", "edu", "student",
		"cmcc-edu", "chinanet-edu",
		// Portal认证热点
		"cmcc", "chinanet", "chinaunicom", "ct-wifi",
		"china-mobile", "china-telecom", "china-unicom",
		"starbucks", "mcdonald", "kfc",
		"free", "guest", "public", "hotel", "airport",
		"hospital", "library", "museum",
		// 手机热点（通常有密码但不值得爆破）
		"iphone", "android", "huawei", "xiaomi", "oppo",
		"vivo", "redmi", "iqoo", "realme", "oneplus",
		"galaxy", "pixel",
	}

	// SSID去重（保留信号最强的那个）
	bestBySSID := make(map[string]WiFiNetwork)
	for _, n := range nets {
		if n.SSID == "" {
			continue
		}

		// 跳过企业认证网络
		if n.Security == "Enterprise" {
			continue
		}

		// 跳过开放网络（大概率是Portal认证）
		if n.Security == "Open" {
			continue
		}

		// 关键词过滤
		lower := strings.ToLower(n.SSID)
		skip := false
		for _, kw := range skipKeywords {
			if strings.Contains(lower, kw) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// 去重：保留信号最强的
		if existing, ok := bestBySSID[n.SSID]; ok {
			if n.RSSI > existing.RSSI {
				bestBySSID[n.SSID] = n
			}
		} else {
			bestBySSID[n.SSID] = n
		}
	}

	// 转为切片并按信号排序
	filtered := make([]WiFiNetwork, 0, len(bestBySSID))
	for _, n := range bestBySSID {
		filtered = append(filtered, n)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].RSSI > filtered[j].RSSI
	})

	return filtered
}
