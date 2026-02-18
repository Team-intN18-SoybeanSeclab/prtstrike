//go:build !windows

package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
)

func captureScreenshot() string {
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, ".prts_ss.png")
	defer os.Remove(tmpFile)

	// Try multiple screenshot tools in order of preference
	tools := []struct {
		name string
		args []string
	}{
		{"import", []string{"-window", "root", tmpFile}},                    // ImageMagick
		{"scrot", []string{tmpFile}},                                        // scrot
		{"gnome-screenshot", []string{"-f", tmpFile}},                       // GNOME
		{"xfce4-screenshooter", []string{"--fullscreen", "--save", tmpFile}}, // XFCE
		{"maim", []string{tmpFile}},                                         // maim
	}

	captured := false
	for _, tool := range tools {
		path, err := exec.LookPath(tool.name)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, tool.args...)
		cmd.SysProcAttr = getSysProcAttr()
		if err := cmd.Run(); err != nil {
			continue
		}
		if info, err := os.Stat(tmpFile); err == nil && info.Size() > 0 {
			captured = true
			break
		}
	}

	if !captured {
		return "Error: no screenshot tool available (tried: import, scrot, gnome-screenshot, xfce4-screenshooter, maim)"
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return "Error: failed to read screenshot file: " + err.Error()
	}

	return "SCREENSHOT:" + base64.StdEncoding.EncodeToString(data)
}
