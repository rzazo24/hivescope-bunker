package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnlyTheNewestAreKept(t *testing.T) {
	dir := t.TempDir()
	j, _ := Open(dir)
	for i := 0; i < trimAt+5; i++ {
		_ = j.Add(Entry{Outcome: "signed", Conn: "c"})
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "signatures.jsonl"))
	if n := strings.Count(string(raw), "\n"); n != keep+5 {
		t.Fatalf("%d lines", n)
	}
	var nilJ *Journal
	if nilJ.Add(Entry{}) != nil {
		t.Fatal("no journal: nothing to do")
	}
}
