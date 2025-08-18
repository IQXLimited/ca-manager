//go:build linux

package main

import "os/exec"

// openDir opens a directory in the default file manager on Linux.
func openDir(dir string) error {
	return exec.Command("xdg-open", dir).Run()
}
