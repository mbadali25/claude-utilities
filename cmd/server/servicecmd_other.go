//go:build !windows

package main

import "errors"

// errServiceUnsupported is what every seam returns on an OS with no service control manager.
var errServiceUnsupported = errors.New("`server service` manages a Windows service and is not supported on this OS")

// The service seams off Windows. `server service` manages a Windows service; the systemd half is a
// unit file and a `systemctl` call, which land with the unit renderer in the next slice.
//
// Every one of these refuses with one clear sentence rather than returning a nil handle. The
// failure this avoids is the obvious one: a nil scm handed back to serviceCmd would panic on the
// first Open, so `server service install` on Linux would be a stack trace instead of an answer.

// platformNewSCM has no service control manager to connect to.
func platformNewSCM() (scm, error) { return nil, errServiceUnsupported }

// platformInstallEventSource has no Windows event log.
func platformInstallEventSource(string) error { return errServiceUnsupported }

// platformRemoveEventSource has no Windows event log.
func platformRemoveEventSource(string) error { return errServiceUnsupported }

// platformRunICacls has no icacls: unix permissions are modes, which credfile sets directly.
func platformRunICacls([]string) ([]byte, error) { return nil, errServiceUnsupported }

// platformRunFirewall has no netsh.
func platformRunFirewall([]string) ([]byte, error) { return nil, errServiceUnsupported }

// runAsWindowsService is never the case here, so main takes the console path.
func runAsWindowsService() (int, bool) { return 0, false }
