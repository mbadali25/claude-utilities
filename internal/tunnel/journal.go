package tunnel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The journal is what makes a hard kill of the server survivable. The PowerShell supervisor kills
// its children in a `finally` block, which does not run when the task is hard-killed, and the
// measurement run left orphans exactly that way. Every spawn is recorded here and removed on
// exit, so a new server process can find and reap what its predecessor left behind.
//
// A pid alone is not enough to kill safely - pids are reused - so reap goes through killIfSSH,
// which refuses any pid that is not running ssh.

// JournalFileName is the journal's name inside the data dir.
const JournalFileName = "tunnels-journal.json"

type journalEntry struct {
	HostID  string    `json:"hostId"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	// KeyPath is the ephemeral private key file, so a reap can delete an orphan too.
	KeyPath string `json:"keyPath,omitempty"`
}

type journal struct {
	mu      sync.Mutex
	path    string
	entries map[int]journalEntry
}

func openJournal(dataDir string) (*journal, []journalEntry, error) {
	j := &journal{path: filepath.Join(dataDir, JournalFileName), entries: map[int]journalEntry{}}
	data, err := os.ReadFile(filepath.Clean(j.path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return j, nil, nil
		}
		return nil, nil, err
	}
	var list []journalEntry
	if err := json.Unmarshal(data, &list); err != nil {
		// A truncated journal is not worth failing a server start over: the worst case is an
		// orphan that the operator finds by command line, which the runbook already covers.
		return j, nil, nil
	}
	return j, list, nil
}

// add records a spawn. A failure to persist is returned, not swallowed: the whole point of the
// journal is that it is there after a hard kill.
func (j *journal) add(e journalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries[e.PID] = e
	return j.saveLocked()
}

func (j *journal) remove(pid int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.entries, pid)
	_ = j.saveLocked() // the pid is already gone; a failed write only risks a harmless reap
}

func (j *journal) clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = map[int]journalEntry{}
	_ = j.saveLocked()
}

func (j *journal) saveLocked() error {
	list := make([]journalEntry, 0, len(j.entries))
	for _, e := range j.entries {
		list = append(list, e)
	}
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, j.path); err != nil {
		removeQuiet(tmp)
		return err
	}
	return nil
}

// reap kills the tunnel children a previous server process left behind and deletes their
// ephemeral key files. It returns how many it actually terminated. A pid that is gone, reused by
// something else, or not running ssh is left alone - killIfSSH is what decides.
func reap(entries []journalEntry) int {
	killed := 0
	for _, e := range entries {
		if done, _ := killIfSSH(e.PID); done {
			killed++
		}
		if e.KeyPath != "" {
			removeQuiet(e.KeyPath)
		}
	}
	return killed
}
