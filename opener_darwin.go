//go:build darwin

package main

import "os/exec"

// openDir opens a directory in Finder on macOS.
func openDir(dir string) error {
	return exec.Command("open", dir).Run()
}
