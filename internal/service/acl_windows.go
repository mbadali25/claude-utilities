package service

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// platformACLSupported is true: this is the OS the policy exists for.
const platformACLSupported = true

// platformServiceRegistered answers "is the ClaudeSwapServer service registered" with a read-only
// SCM query: connect, open the service for SERVICE_QUERY_CONFIG, close. It creates nothing, starts
// nothing and changes nothing, so every server command can call it.
//
// ERROR_SERVICE_DOES_NOT_EXIST is the one failure that is an answer rather than a problem: it means
// no service, which is the normal state before `service install` has run. Anything else - an SCM
// this process cannot connect to, a handle it cannot open - is returned as an error, and ACLPolicy
// turns that into the G17 refusal rather than guessing Administrators-only.
//
// mgr.Connect() asks for full access, which needs elevation; this uses the narrower
// SC_MANAGER_CONNECT so an unelevated `server vault status` can still answer the question.
func platformServiceRegistered() (bool, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, fmt.Errorf("open the service control manager: %w", err)
	}
	m := &mgr.Mgr{Handle: h}
	defer func() { _ = m.Disconnect() }()

	name, err := windows.UTF16PtrFromString(WindowsServiceName)
	if err != nil {
		return false, err
	}
	sh, err := windows.OpenService(m.Handle, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, fmt.Errorf("open the %s service: %w", WindowsServiceName, err)
	}
	_ = windows.CloseServiceHandle(sh)
	return true, nil
}

// platformLookupServiceSID resolves the virtual account `NT SERVICE\ClaudeSwapServer` to its SID
// string. The account exists because the service is registered with SERVICE_SID_TYPE_UNRESTRICTED;
// a lookup that fails anyway is the G17 case and the caller refuses to write.
func platformLookupServiceSID() (string, error) {
	sid, _, _, err := windows.LookupSID("", WindowsServiceAccount)
	if err != nil {
		return "", fmt.Errorf("resolve %s to a SID: %w", WindowsServiceAccount, err)
	}
	s := sid.String()
	if s == "" {
		return "", fmt.Errorf("resolve %s to a SID: the lookup returned an unprintable SID", WindowsServiceAccount)
	}
	return s, nil
}
