//go:build windows

package main

import (
	"os/exec"
	"path/filepath"
)

func openDir(dir string) error {
	// Use the absolute path for explorer
	absPath, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	// Use "start" which is more reliable than calling explorer.exe directly
	cmd := exec.Command("cmd", "/C", "start", absPath)
	return cmd.Run()
}
