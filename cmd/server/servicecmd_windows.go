package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/service"
)

// This file is the Windows adapter: it maps the portable types in servicecmd.go onto the SCM, the
// event log, icacls and netsh, and it hosts the service when the SCM started this process. It holds
// no decisions - every value it writes comes from servicecmd.go, which is tested on every OS.

// stopPollInterval and stopDeadline bound the wait after a stop control. The service's own drain is
// 5 s; the deadline leaves room for it plus the SCM's own handling.
const (
	stopPollInterval = 200 * time.Millisecond
	stopDeadline     = 30 * time.Second
)

// eventIDs for the Application log. The source is registered with EventCreate.exe as its message
// file, which renders the text as given, so the ids only have to be stable and distinct.
const (
	eventIDInfo  = 1
	eventIDWarn  = 2
	eventIDError = 3
)

// winSCM is the service control manager.
type winSCM struct{ m *mgr.Mgr }

// platformNewSCM connects to the SCM with the access an install needs. `mgr.Connect` asks for
// SC_MANAGER_ALL_ACCESS, which needs elevation; that is correct for install and uninstall, and the
// read-only paths (`status`, and the registered-data-dir lookup every console run makes) fall back
// to SC_MANAGER_CONNECT so they work unelevated.
func platformNewSCM() (scm, error) {
	if m, err := mgr.Connect(); err == nil {
		return &winSCM{m: m}, nil
	}
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, fmt.Errorf("connect to the service control manager: %w", err)
	}
	return &winSCM{m: &mgr.Mgr{Handle: h}}, nil
}

// Open opens the service, translating "no such service" into errServiceNotRegistered.
func (w *winSCM) Open(name string) (scmService, error) {
	s, err := w.m.OpenService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, errServiceNotRegistered
		}
		return nil, fmt.Errorf("open the %s service: %w", name, err)
	}
	return &winService{s: s}, nil
}

// Create registers the service, translating a lost race into errServiceExists.
func (w *winSCM) Create(name string, cfg serviceConfig) (scmService, error) {
	exe, args := splitExeAndArgs(cfg.BinaryPathName)
	s, err := w.m.CreateService(name, exe, toMgrConfig(cfg), args...)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_EXISTS) || errors.Is(err, windows.ERROR_DUPLICATE_SERVICE_NAME) {
			return nil, errServiceExists
		}
		return nil, fmt.Errorf("register the %s service: %w", name, err)
	}
	return &winService{s: s}, nil
}

// Close disconnects from the SCM.
func (w *winSCM) Close() error { return w.m.Disconnect() }

// winService is one registered service.
type winService struct{ s *mgr.Service }

// Config reads the registration back.
func (v *winService) Config() (serviceConfig, error) {
	c, err := v.s.Config()
	if err != nil {
		return serviceConfig{}, err
	}
	return serviceConfig{
		BinaryPathName:      c.BinaryPathName,
		DisplayName:         c.DisplayName,
		Description:         c.Description,
		ServiceStartName:    c.ServiceStartName,
		AutoStart:           c.StartType == mgr.StartAutomatic,
		DelayedAutoStart:    c.DelayedAutoStart,
		UnrestrictedSidType: c.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, nil
}

// UpdateConfig rewrites the registration, which is what a second install does.
func (v *winService) UpdateConfig(cfg serviceConfig) error { return v.s.UpdateConfig(toMgrConfig(cfg)) }

// SetRecovery writes the failure-action chain and makes a non-zero exit count as a failure.
func (v *winService) SetRecovery(actions []recoveryAction, resetPeriodSeconds uint32, onNonCrashFailures bool) error {
	ra := make([]mgr.RecoveryAction, 0, len(actions))
	for _, a := range actions {
		t := mgr.NoAction
		if a.Kind == recoveryRestart {
			t = mgr.ServiceRestart
		}
		ra = append(ra, mgr.RecoveryAction{Type: t, Delay: a.Delay})
	}
	if err := v.s.SetRecoveryActions(ra, resetPeriodSeconds); err != nil {
		return fmt.Errorf("set the recovery actions: %w", err)
	}
	if err := v.s.SetRecoveryActionsOnNonCrashFailures(onNonCrashFailures); err != nil {
		return fmt.Errorf("include non-crash failures in the recovery actions: %w", err)
	}
	return nil
}

// Start starts the service with no extra arguments: everything it needs is baked into the
// registration, so a start can never hand it different flags from the ones an operator installed.
func (v *winService) Start() error { return v.s.Start() }

// Stop sends the stop control and waits for the drain. An already-stopped service is not an error.
func (v *winService) Stop() error {
	st, err := v.s.Control(svc.Stop)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return fmt.Errorf("stop the service: %w", err)
	}
	deadline := time.Now().Add(stopDeadline)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("the service was still %d after %s", st.State, stopDeadline)
		}
		time.Sleep(stopPollInterval)
		if st, err = v.s.Query(); err != nil {
			return fmt.Errorf("query the service while stopping: %w", err)
		}
	}
	return nil
}

// Query reports the state and the last exit code.
func (v *winService) Query() (serviceStatus, error) {
	st, err := v.s.Query()
	if err != nil {
		return serviceStatus{}, err
	}
	return serviceStatus{
		State:                   stateName(st.State),
		Win32ExitCode:           st.Win32ExitCode,
		ServiceSpecificExitCode: st.ServiceSpecificExitCode,
		ProcessID:               st.ProcessId,
	}, nil
}

// Delete removes the registration.
func (v *winService) Delete() error { return v.s.Delete() }

// Close releases the handle.
func (v *winService) Close() error { return v.s.Close() }

// toMgrConfig maps the portable registration onto mgr.Config. Every value comes from
// installServiceConfig, which a portable test pins; this is the field copy.
func toMgrConfig(cfg serviceConfig) mgr.Config {
	m := mgr.Config{
		// UpdateConfig sends an empty BinaryPathName as NULL, which ChangeServiceConfig reads as "leave
		// it alone": without this a second install would report an update and keep the old flags.
		// CreateService takes the path from its own arguments and ignores this field.
		BinaryPathName:   cfg.BinaryPathName,
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartManual,
		ErrorControl:     mgr.ErrorNormal,
		DisplayName:      cfg.DisplayName,
		Description:      cfg.Description,
		ServiceStartName: cfg.ServiceStartName,
		DelayedAutoStart: cfg.DelayedAutoStart,
	}
	if cfg.AutoStart {
		m.StartType = mgr.StartAutomatic
	}
	if cfg.UnrestrictedSidType {
		m.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	}
	return m
}

// splitExeAndArgs takes the exe out of a command line and leaves the rest as arguments, because
// CreateService wants them apart. The tokenizer is the portable one, so what goes in matches what
// dataDirFromCommandLine reads back out.
func splitExeAndArgs(cmdline string) (string, []string) {
	parts := splitCommandLine(cmdline)
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

// stateName renders an SCM state as the lower-case token `service status` prints.
func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start_pending"
	case svc.StopPending:
		return "stop_pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue_pending"
	case svc.PausePending:
		return "pause_pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state_%d", uint32(s))
	}
}

// platformInstallEventSource registers the Application log source with EventCreate.exe as its
// message file, so the text is rendered as written and no message DLL has to ship. An
// already-registered source is not an error: install is idempotent.
func platformInstallEventSource(src string) error {
	err := eventlog.InstallAsEventCreate(src, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err == nil || errors.Is(err, os.ErrExist) || strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return fmt.Errorf("register the %s event source: %w", src, err)
}

// platformRemoveEventSource removes the source. An absent one is not an error.
func platformRemoveEventSource(src string) error {
	if err := eventlog.Remove(src); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the %s event source: %w", src, err)
	}
	return nil
}

// platformRunICacls runs icacls with the argument list install.IcaclsLockdownArgs built. The output
// is taken as well as the status, because icacls says which term or path it refused and that is the
// only account of a failure the caller gets.
func platformRunICacls(args []string) ([]byte, error) {
	// #nosec G204 -- fixed binary; the arguments are this process's own data dir and two fixed
	// principal names, never anything a remote caller supplies.
	return exec.Command("icacls", args...).CombinedOutput()
}

// platformRunFirewall runs netsh. It is reached only from `--firewall`, which is off by default:
// the install prints the line and leaves the decision to the operator.
func platformRunFirewall(args []string) ([]byte, error) {
	// #nosec G204 -- fixed binary; the arguments are built from the validated --listen port.
	return exec.Command("netsh", args...).CombinedOutput()
}

// runAsWindowsService hosts the server under the SCM when the SCM is what started it. It returns
// (code, true) in that case and (0, false) for a console run, which then takes today's path
// unchanged - `svc.Run` is entered only when svc.IsWindowsService() is true.
//
// Three things happen here that a console run does not need:
//   - the ACL policy is installed before the first write, which includes the log file;
//   - stderr is replaced by the rotating log file, because a service has no console. 10 MiB a file,
//     five files, an explicit 50 MiB retention, owner-only plus the policy's SIDs, through logx so
//     the allowlist and the redaction still apply;
//   - the readiness seam becomes the handler's progress call, so the SCM learns the service is
//     Running at exactly the point the Linux half sends READY=1: after the last thing that can fail.
func runAsWindowsService() (int, bool) {
	if !service.IsWindowsService() {
		return 0, false
	}
	args := os.Args[1:]
	dataDir, ok := flagValue(args, "data-dir")
	if !ok || dataDir == "" {
		dataDir = defaultServiceDataDir()
	}
	logDir := serviceLogDir(dataDir)

	// Before the first write. A service SID that cannot be resolved narrows the policy (G17) rather
	// than stopping the service from starting; the narrowing is logged to the log file below.
	narrowed, code, reason, err := resolveServicePolicy()
	if err != nil {
		return reportServiceStartFailure(logDir, code, reason, err)
	}

	w, err := logx.NewRotatingWriter(filepath.Join(logDir, "server.log"), logx.DefaultLogMaxBytes, logx.DefaultLogKeep)
	if err != nil {
		return reportServiceStartFailure(logDir, exitRuntime, "log-unwritable", err)
	}
	defer func() { _ = w.Close() }()
	if narrowed {
		logx.New(w).Warn("acl policy", "reason", service.ACLPolicyNarrowedReason, "op", "run")
	}

	elog, elogErr := eventlog.Open(service.EventSourceName)
	if elogErr == nil {
		defer func() { _ = elog.Close() }()
	}

	h := &service.Handler{
		Dir:   logDir,
		Table: service.ServerTable(),
		Log:   logx.New(w),
		Event: func(level service.EventLevel, text string) {
			if elogErr != nil {
				return
			}
			switch level {
			case service.EventError:
				_ = elog.Error(eventIDError, text)
			case service.EventWarning:
				_ = elog.Warning(eventIDWarn, text)
			default:
				_ = elog.Info(eventIDInfo, text)
			}
		},
		Run: func(ctx context.Context, progress func(string)) int {
			serviceReady.Store(progress)
			return run(ctx, args, os.Getenv, strings.NewReader(""), w)
		},
	}
	// The readiness seam is replaced before svc.Run, not from inside the handler's goroutine, so
	// nothing writes a package variable while another goroutine could read it.
	notifyReady = func() error {
		if p, ok := serviceReady.Load().(func(string)); ok && p != nil {
			p(service.ReadyStage)
		}
		return nil
	}
	if err := svc.Run(service.WindowsServiceName, h); err != nil {
		if elogErr == nil {
			_ = elog.Error(eventIDError, "the service handler could not be started: "+logx.Redact(err.Error()))
		}
		return exitRuntime, true
	}
	return 0, true
}

// reportServiceStartFailure records a fatal that happened before the handler existed, so even a
// service that never reached svc.Run leaves a marker and a line an operator can read. There is no
// log file yet at this point, so the event log is the only place the reason can go.
func reportServiceStartFailure(logDir string, code int, reason string, cause error) (int, bool) {
	_ = service.WriteMarker(logDir, service.Marker{
		Exit: code, Reason: reason, TS: time.Now(), Boot: service.BootInstant(),
	})
	if elog, err := eventlog.Open(service.EventSourceName); err == nil {
		defer func() { _ = elog.Close() }()
		_ = elog.Error(eventIDError, fmt.Sprintf("the service could not start: exit=%d reason=%s: %s",
			code, reason, logx.Redact(cause.Error())))
	}
	return code, true
}

// serviceReady holds the handler's progress function while the service runs, so the readiness seam
// can reach it without a package variable being written from the handler's goroutine.
var serviceReady atomic.Value
