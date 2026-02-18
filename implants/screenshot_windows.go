//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"syscall"
	"unsafe"
)

var (
	modUser32 = syscall.NewLazyDLL("user32.dll")
	modGdi32  = syscall.NewLazyDLL("gdi32.dll")

	procGetDesktopWindow  = modUser32.NewProc("GetDesktopWindow")
	procGetDC             = modUser32.NewProc("GetDC")
	procReleaseDC         = modUser32.NewProc("ReleaseDC")
	procGetSystemMetrics  = modUser32.NewProc("GetSystemMetrics")

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
	biRGB             = 0
	dibRGBColors      = 0
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

func captureScreenshot() string {
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
	ret, _, _ := procBitBlt.Call(memDC, 0, 0, w, h, hdc, uintptr(srcX), uintptr(srcY), srccopy)
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
		hdc, hBitmap, 0, uintptr(height),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bmi)),
		dibRGBColors,
	)
	if r == 0 {
		return "Error: GetDIBits failed"
	}

	// Convert BGRA pixel data to Go RGBA image
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			off := (y*width + x) * 4
			img.SetRGBA(x, y, color.RGBA{
				R: pixels[off+2],
				G: pixels[off+1],
				B: pixels[off],
				A: 255,
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "Error: PNG encode failed: " + err.Error()
	}

	return "SCREENSHOT:" + base64.StdEncoding.EncodeToString(buf.Bytes())
}
