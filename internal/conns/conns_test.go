package conns

import (
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestRefreshGivesAnOldConnectionWhatItsProfileAllowsNow(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "c.json"))
	c, _, err := s.Add("phone", "quill", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// an old connection, made when the profile had fewer kinds
	list, _ := s.load()
	list[0].Kinds = []int{1, 3}
	list[0].Clients = []string{"client-key"}
	if err := s.save(list); err != nil {
		t.Fatal(err)
	}
	got, err := s.Refresh("phone")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Kinds, Profiles["quill"].Kinds) || !slices.Contains(got.Kinds, 10000) {
		t.Fatalf("kinds %v", got.Kinds)
	}
	back, _ := s.ByClient("client-key")
	if back.ID != c.ID || back.SecretHash != c.SecretHash || !slices.Contains(back.Kinds, 10000) {
		t.Fatalf("after refresh: %+v", back)
	}
	if err := s.Revoke("phone"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh("phone"); err == nil {
		t.Fatal("a revoked connection must not be refreshed")
	}
}
