package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type WifiNetwork struct {
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	RSSI     int    `json:"rssi"`
	Channel  int    `json:"channel"`
	Band     string `json:"band"`
	Security string `json:"security"`
}

type ScanResult struct {
	ScanTime string        `json:"scan_time"`
	Total    int           `json:"total"`
	Networks []WifiNetwork `json:"networks"`
}

func scanWithSystemProfiler() ([]WifiNetwork, error) {
	cmd := exec.Command("system_profiler", "SPAirPortDataType")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler failed: %w", err)
	}
	return parseSystemProfiler(string(output)), nil
}

func parseSystemProfiler(output string) []WifiNetwork {
	var networks []WifiNetwork
	lines := strings.Split(output, "\n")
	inOtherNetworks := false
	var currentSSID string
	currentNet := WifiNetwork{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "Other Local Wi-Fi Networks") || strings.Contains(trimmed, "Other Wi-Fi Networks") {
			inOtherNetworks = true
			continue
		}
		if !inOtherNetworks {
			continue
		}
		if !strings.Contains(trimmed, ":") && trimmed != "" && !strings.HasPrefix(trimmed, "PHY") && !strings.HasPrefix(trimmed, "Channel") && !strings.HasPrefix(trimmed, "Security") && !strings.HasPrefix(trimmed, "Signal") {
			if currentSSID != "" {
				networks = append(networks, currentNet)
			}
			currentSSID = trimmed
			currentNet = WifiNetwork{SSID: currentSSID}
			continue
		}
		if currentSSID == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Channel:") {
			chStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "Channel:"))
			parts := strings.Fields(chStr)
			if len(parts) > 0 {
				ch, _ := strconv.Atoi(strings.TrimRight(parts[0], ","))
				currentNet.Channel = ch
				if ch > 14 {
					currentNet.Band = "5GHz"
				} else {
					currentNet.Band = "2.4GHz"
				}
			}
		}
		if strings.HasPrefix(trimmed, "Security:") {
			currentNet.Security = strings.TrimSpace(strings.TrimPrefix(trimmed, "Security:"))
		}
		if strings.HasPrefix(trimmed, "Signal / Noise:") {
			re := regexp.MustCompile(`(-?\d+)\s*dBm`)
			matches := re.FindStringSubmatch(trimmed)
			if len(matches) > 1 {
				rssi, _ := strconv.Atoi(matches[1])
				currentNet.RSSI = rssi
			}
		}
	}
	if currentSSID != "" {
		networks = append(networks, currentNet)
	}
	return networks
}

func getCurrentConnection() string {
	cmd := exec.Command("networksetup", "-getairportnetwork", "en0")
	output, err := cmd.Output()
	if err != nil {
		return "(not connected)"
	}
	result := strings.TrimSpace(string(output))
	result = strings.Replace(result, "Current Wi-Fi Network: ", "", 1)
	if strings.Contains(result, "not associated") {
		return "(not connected)"
	}
	return result
}

func signalBar(rssi int) string {
	switch {
	case rssi > -50:
		return "======"
	case rssi > -60:
		return "====-"
	case rssi > -70:
		return "==--"
	case rssi > -80:
		return "=---"
	default:
		return "----"
	}
}

func main() {
	jsonMode := false
	for _, arg := range os.Args[1:] {
		if arg == "--json" || arg == "-j" {
			jsonMode = true
		}
	}

	if !jsonMode {
		fmt.Println("==================================================")
		fmt.Println("  WiFi Scanner v1.0 (Go)")
		fmt.Println("==================================================")
	}

	currentSSID := getCurrentConnection()
	if !jsonMode {
		fmt.Printf("[*] Current: %s\n\n", currentSSID)
		fmt.Println("[*] Scanning...")
	}

	networks, err := scanWithSystemProfiler()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Scan failed: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(networks, func(i, j int) bool {
		return networks[i].RSSI > networks[j].RSSI
	})

	if jsonMode {
		result := ScanResult{
			ScanTime: time.Now().Format("2006-01-02 15:04:05"),
			Total:    len(networks),
			Networks: networks,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("\n%-4s %-26s %6s %4s %6s  %-22s %s\n", "#", "SSID", "RSSI", "CH", "Band", "Security", "Signal")
		fmt.Println(strings.Repeat("-", 90))
		for i, net := range networks {
			ssid := net.SSID
			if ssid == "" {
				ssid = "(hidden)"
			}
			mark := ""
			if ssid == currentSSID {
				mark = " *"
			}
			fmt.Printf("%-4d %-26s %4d  %4d %6s  %-22s %s%s\n", i+1, ssid, net.RSSI, net.Channel, net.Band, net.Security, signalBar(net.RSSI), mark)
		}
		fmt.Printf("\n[*] Total: %d networks (* = current)\n", len(networks))
	}
}
