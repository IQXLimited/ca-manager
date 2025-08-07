//go:build !windows

package main

// IsAdmin provides a default for non-windows systems.
func (a *App) IsAdmin() bool {
	// On non-windows systems, we can't easily check, so we assume not admin.
	// The install button will be hidden anyway by the frontend logic.
	return false
}
