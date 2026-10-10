// Package vault keeps the user's secret key: encrypted on disk (NIP-49, scrypt + XChaCha20-Poly1305) and, once unlocked, only in memory.
// The key is never written in the clear, never printed, and never leaves this process.
package vault

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip49"
)

// ScryptLogN: 18 is ~256 MiB of memory to try one password, slow on purpose for anyone who steals the file (tests lower it).
var ScryptLogN uint8 = 18

var ErrLocked = errors.New("the bunker is locked")

type Vault struct {
	path string
	mu   sync.RWMutex
	sk   string // hex, empty while locked
	pk   string // hex public key; known only when unlocked (the file does not reveal it)
}

func New(path string) *Vault { return &Vault{path: path} }

// Exists says whether a key has been imported.
func (v *Vault) Exists() bool { _, err := os.Stat(v.path); return err == nil }

// Init encrypts a secret key (nsec1… or 64 hex characters) with the password and saves it, mode 0600. It refuses to overwrite.
func Init(path, secret, password string) (pubkey string, err error) {
	if len(password) < 10 {
		return "", errors.New("the password must have at least 10 characters")
	}
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists: refusing to overwrite a key", path)
	}
	sk, err := parseSecret(secret)
	if err != nil {
		return "", err
	}
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return "", err
	}
	code, err := nip49.Encrypt(sk, password, ScryptLogN, nip49.NotKnownToHaveBeenHandledInsecurely)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(code+"\n"), 0o600); err != nil {
		return "", err
	}
	return pk, nil
}

func parseSecret(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "nsec1") {
		prefix, data, err := nip19.Decode(s)
		if err != nil || prefix != "nsec" {
			return "", errors.New("that is not a valid nsec")
		}
		return data.(string), nil
	}
	if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
		return "", errors.New("the key must be an nsec1… or 64 hex characters")
	}
	return strings.ToLower(s), nil
}

func (v *Vault) Unlock(password string) error {
	raw, err := os.ReadFile(v.path)
	if err != nil {
		return err
	}
	sk, err := nip49.Decrypt(strings.TrimSpace(string(raw)), password)
	if err != nil {
		return errors.New("wrong password")
	}
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.sk, v.pk = sk, pk
	v.mu.Unlock()
	return nil
}

func (v *Vault) Lock() { v.mu.Lock(); v.sk, v.pk = "", ""; v.mu.Unlock() }

func (v *Vault) Locked() bool { v.mu.RLock(); defer v.mu.RUnlock(); return v.sk == "" }

func (v *Vault) PubKey() (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sk == "" {
		return "", ErrLocked
	}
	return v.pk, nil
}

func (v *Vault) Sign(evt *nostr.Event) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sk == "" {
		return ErrLocked
	}
	evt.PubKey = v.pk
	return evt.Sign(v.sk)
}
