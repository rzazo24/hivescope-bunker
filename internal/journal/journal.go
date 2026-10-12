// Package journal keeps a record of what the bunker signed, refused and paired, one JSON line each, so the relay's panel can show it.
// It holds no secrets (no content, no keys): when, which connection, which kind, the event id and why something was refused.
// The file lives in its own folder (mode 0755, file 0644) so that folder alone can be shown, read-only, to the panel.
package journal

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	Time    int64  `json:"t"`
	Outcome string `json:"outcome"` // signed | refused | paired
	Conn    string `json:"conn,omitempty"`
	Profile string `json:"profile,omitempty"`
	Kind    *int   `json:"kind,omitempty"`
	ID      string `json:"id,omitempty"`
	Method  string `json:"method,omitempty"`
	Client  string `json:"client,omitempty"` // first characters of the app's key, when the connection is unknown
	Reason  string `json:"reason,omitempty"`
}

const keep, trimAt = 1000, 2000 // past trimAt lines, only the newest keep stay

type Journal struct {
	path  string
	mu    sync.Mutex
	lines int
}

func Open(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o755)
	j := &Journal{path: filepath.Join(dir, "signatures.jsonl")}
	j.lines = len(j.read())
	return j, nil
}

func (j *Journal) read() []string {
	f, err := os.Open(j.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if sc.Text() != "" {
			out = append(out, sc.Text())
		}
	}
	return out
}

// Add appends one entry (Time filled in when zero). A failure to write is not fatal: signing does not depend on the journal.
func (j *Journal) Add(e Entry) error {
	if j == nil {
		return nil
	}
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lines >= trimAt {
		lines := j.read()
		if len(lines) > keep {
			lines = lines[len(lines)-keep:]
		}
		tmp := j.path + ".tmp"
		data := []byte{}
		for _, l := range lines {
			data = append(append(data, l...), '\n')
		}
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, j.path); err != nil {
			return err
		}
		j.lines = len(lines)
	}
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Chmod(0o644)
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	j.lines++
	return nil
}
