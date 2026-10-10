package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func TestRoundTripAndNeverInTheClear(t *testing.T) {
	ScryptLogN = 10
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	nsec, _ := nip19.EncodePrivateKey(sk)
	path := filepath.Join(t.TempDir(), "key")
	got, err := Init(path, nsec, "correct horse battery")
	if err != nil || got != pk {
		t.Fatal(got, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), sk) || strings.Contains(string(raw), nsec) {
		t.Fatal("the secret is on disk in the clear")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatal("the key file must be 0600, is", fi.Mode().Perm())
	}
	v := New(path)
	if !v.Locked() {
		t.Fatal("a new vault must start locked")
	}
	if v.Unlock("wrong password!!") == nil || !v.Locked() {
		t.Fatal("a wrong password unlocked it")
	}
	if err := v.Unlock("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if p, _ := v.PubKey(); p != pk {
		t.Fatal("wrong public key")
	}
	v.Lock()
	if _, err := v.PubKey(); err != ErrLocked {
		t.Fatal("still unlocked")
	}
	var evt nostr.Event
	if v.Sign(&evt) != ErrLocked {
		t.Fatal("signed while locked")
	}
}

func TestInitRefusesOverwritingAndWeakPasswords(t *testing.T) {
	ScryptLogN = 10
	path := filepath.Join(t.TempDir(), "key")
	sk := nostr.GeneratePrivateKey()
	if _, err := Init(path, sk, "short"); err == nil {
		t.Fatal("accepted a short password")
	}
	if _, err := Init(path, "not a key", "a long enough password"); err == nil {
		t.Fatal("accepted junk as a key")
	}
	if _, err := Init(path, sk, "a long enough password"); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(path, nostr.GeneratePrivateKey(), "a long enough password"); err == nil {
		t.Fatal("overwrote an existing key")
	}
}
