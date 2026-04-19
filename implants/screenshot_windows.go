//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"syscall"
	"unsafe"
)

var (
	modUser32 = syscall.NewLazyDLL("user32.dll")
	modGdi32  = syscall.NewLazyDLL("gdi32.dll")
	modShcore = syscall.NewLazyDLL("shcore.dll")

	procGetDesktopWindow             = modUser32.NewProc("GetDesktopWindow")
	procGetDC                        = modUser32.NewProc("GetDC")
	procReleaseDC                    = modUser32.NewProc("ReleaseDC")
	procGetSystemMetrics             = modUser32.NewProc("GetSystemMetrics")
	procSetProcessDPIAware           = modUser32.NewProc("SetProcessDPIAware")
	procSetProcessDpiAwarenessCtx    = modUser32.NewProc("SetProcessDpiAwarenessContext")
	procSetProcessDpiAwarenessShcore = modShcore.NewProc("SetProcessDpiAwareness")

	procCreateCompatibleDC     = modGdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = modGdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = modGdi32.NewProc("SelectObject")
	procBitBlt                 = modGdi32.NewProc("BitBlt")
	procDeleteDC               = modGdi32.NewProc("DeleteDC")
	procDeleteObject           = modGdi32.NewProc("DeleteObject")
	procGetDIBits              = modGdi32.NewProc("GetDIBits")
)

const (
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79
	srccopy           = 0x00CC0020
	captureBlt        = 0x40000000
	biRGB             = 0
	dibRGBColors      = 0

	processPerMonitorDPIAware     = 2
	eAccessDenied                 = 0x80070005
	dpiAwarenessPerMonitorAwareV2 = ^uintptr(3) // -4
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]uint32
}

func enableHighDPIAwareness() {
	if err := procSetProcessDpiAwarenessCtx.Find(); err == nil {
		ret, _, _ := procSetProcessDpiAwarenessCtx.Call(dpiAwarenessPerMonitorAwareV2)
		if ret != 0 {
			return
		}
	}

	if err := procSetProcessDpiAwarenessShcore.Find(); err == nil {
		hr, _, _ := procSetProcessDpiAwarenessShcore.Call(processPerMonitorDPIAware)
		if hr == 0 || hr == eAccessDenied {
			return
		}
	}

	if err := procSetProcessDPIAware.Find(); err == nil {
		procSetProcessDPIAware.Call()
	}
}

func captureScreenshot() string {
	enableHighDPIAwareness()

	hwnd, _, _ := procGetDesktopWindow.Call()
	hdc, _, _ := procGetDC.Call(0) // NULL = entire virtual screen DC
	if hdc == 0 {
		return "Error: failed to get device context"
	}
	defer procReleaseDC.Call(hwnd, hdc)

	// Virtual screen = all monitors combined
	x, _, _ := procGetSystemMetrics.Call(smXVirtualScreen)
	y, _, _ := procGetSystemMetrics.Call(smYVirtualScreen)
	w, _, _ := procGetSystemMetrics.Call(smCXVirtualScreen)
	h, _, _ := procGetSystemMetrics.Call(smCYVirtualScreen)
	if w == 0 || h == 0 {
		return "Error: failed to get screen dimensions"
	}

	srcX := int(x)
	srcY := int(y)
	width := int(w)
	height := int(h)

	memDC, _, _ := procCreateCompatibleDC.Call(hdc)
	if memDC == 0 {
		return "Error: failed to create compatible DC"
	}
	defer procDeleteDC.Call(memDC)

	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdc, w, h)
	if hBitmap == 0 {
		return "Error: failed to create compatible bitmap"
	}
	defer procDeleteObject.Call(hBitmap)

	old, _, _ := procSelectObject.Call(memDC, hBitmap)

	// BitBlt from virtual screen origin (may be negative for left-of-primary monitors)
	ret, _, _ := procBitBlt.Call(memDC, 0, 0, w, h, hdc, uintptr(srcX), uintptr(srcY), srccopy|captureBlt)
	if ret == 0 {
		procSelectObject.Call(memDC, old)
		return "Error: BitBlt failed"
	}

	// Deselect hBitmap from memDC before calling GetDIBits
	// MSDN: "The bitmap must not be selected into a device context when GetDIBits is called"
	procSelectObject.Call(memDC, old)

	bmi := bitmapInfo{}
	bmi.Header.Size = uint32(unsafe.Sizeof(bmi.Header))
	bmi.Header.Width = int32(width)
	bmi.Header.Height = -int32(height) // negative = top-down DIB
	bmi.Header.Planes = 1
	bmi.Header.BitCount = 32
	bmi.Header.Compression = biRGB

	pixels := make([]byte, width*height*4)
	r, _, _ := procGetDIBits.Call(
		memDC, hBitmap, 0, uintptr(height),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bmi)),
		dibRGBColors,
	)
	if r == 0 {
		return "Error: GetDIBits failed"
	}

	// Encode as BMP directly — avoids importing image/png (~1.5MB savings)
	// BMP with BITMAPINFOHEADER, 24-bit RGB, no compression
	rowSize := (width*3 + 3) & ^3 // rows padded to 4-byte boundary
	imgSize := rowSize * height
	fileSize := 54 + imgSize // 14 (file header) + 40 (info header) + pixel data

	bmp := make([]byte, fileSize)
	// -- File Header (14 bytes) --
	bmp[0], bmp[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(bmp[2:], uint32(fileSize))
	binary.LittleEndian.PutUint32(bmp[10:], 54) // pixel data offset
	// -- Info Header (40 bytes) --
	binary.LittleEndian.PutUint32(bmp[14:], 40)              // header size
	binary.LittleEndian.PutUint32(bmp[18:], uint32(width))   // width
	binary.LittleEndian.PutUint32(bmp[22:], uint32(height))  // height (positive = bottom-up)
	binary.LittleEndian.PutUint16(bmp[26:], 1)               // planes
	binary.LittleEndian.PutUint16(bmp[28:], 24)              // bits per pixel
	binary.LittleEndian.PutUint32(bmp[34:], uint32(imgSize)) // image size

	// Write pixel data (BGRA source -> BGR BMP, bottom-up row order)
	for y := 0; y < height; y++ {
		srcRow := y * width * 4             // source is top-down (negative height DIB)
		dstRow := 54 + (height-1-y)*rowSize // BMP is bottom-up
		for x := 0; x < width; x++ {
			sOff := srcRow + x*4
			dOff := dstRow + x*3
			bmp[dOff] = pixels[sOff]     // B
			bmp[dOff+1] = pixels[sOff+1] // G
			bmp[dOff+2] = pixels[sOff+2] // R
		}
	}

	return "SCREENSHOT:" + base64.StdEncoding.EncodeToString(bmp)
}
