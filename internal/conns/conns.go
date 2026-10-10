// Package conns is the list of apps allowed to ask the bunker for signatures: what each may sign, how often, and who has paired.
// Only a hash of each pairing secret is stored, so the file alone cannot be used to connect.
package conns

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Profile is what a kind of app may do. A new app gets one of these; nothing else is ever allowed.
type Profile struct {
	Kinds      []int
	MaxPerHour int
	MaxClients int // how many different client keys may pair with one secret (a web page makes a new key on every login)
}

var Profiles = map[string]Profile{
	"quill":     {Kinds: []int{1, 3, 6, 7, 10002}, MaxPerHour: 60, MaxClients: 1},
	"nostrclaw": {Kinds: []int{1, 5, 7, 10050}, MaxPerHour: 20, MaxClients: 1},
	"panel":     {Kinds: []int{27235}, MaxPerHour: 30, MaxClients: 50}, // the relay panel signs only its NIP-98 login event
}

type Conn struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Profile    string   `json:"profile"`
	SecretHash string   `json:"secret_hash"`
	Clients    []string `json:"clients"` // client keys that have paired
	Kinds      []int    `json:"kinds"`
	MaxPerHour int      `json:"max_per_hour"`
	MaxClients int      `json:"max_clients"`
	Created    int64    `json:"created"`
	LastUsed   int64    `json:"last_used"`
	Revoked    bool     `json:"revoked"`
	URLPrefix  string   `json:"url_prefix,omitempty"` // panel only: the NIP-98 login it signs must be for a URL that starts with this
}

type Store struct {
	path string
	mu   sync.Mutex
}

func Open(path string) *Store { return &Store{path: path} }

func hash(secret string) string { h := sha256.Sum256([]byte(secret)); return hex.EncodeToString(h[:]) }

func (s *Store) load() ([]Conn, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Conn
	return out, json.Unmarshal(raw, &out)
}

func (s *Store) save(list []Conn) error {
	raw, _ := json.MarshalIndent(list, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) List() ([]Conn, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.load() }

// Add creates a connection and returns the pairing secret ONCE: only its hash is kept.
func (s *Store) Add(name, profile, urlPrefix string, now time.Time) (Conn, string, error) {
	p, ok := Profiles[profile]
	if !ok {
		return Conn{}, "", fmt.Errorf("unknown profile %q", profile)
	}
	if profile == "panel" && !strings.HasPrefix(urlPrefix, "https://") && !strings.HasPrefix(urlPrefix, "http://127.0.0.1") && !strings.HasPrefix(urlPrefix, "http://localhost") { // http only for local tests
		return Conn{}, "", errors.New("the panel profile needs --url <https://… the address its login is for>: it will sign only logins for that address")
	}
	if profile != "panel" && urlPrefix != "" {
		return Conn{}, "", errors.New("--url only applies to the panel profile")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return Conn{}, "", err
	}
	for _, c := range list {
		if c.Name == name && !c.Revoked {
			return Conn{}, "", fmt.Errorf("there is already a connection called %q", name)
		}
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	secret := hex.EncodeToString(b)
	id := make([]byte, 4)
	_, _ = rand.Read(id)
	c := Conn{ID: hex.EncodeToString(id), Name: name, Profile: profile, SecretHash: hash(secret), Kinds: slices.Clone(p.Kinds), MaxPerHour: p.MaxPerHour, MaxClients: p.MaxClients, URLPrefix: urlPrefix, Created: now.Unix()}
	return c, secret, s.save(append(list, c))
}

func (s *Store) Revoke(idOrName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return err
	}
	for i := range list {
		if (list[i].ID == idOrName || list[i].Name == idOrName) && !list[i].Revoked {
			list[i].Revoked = true
			return s.save(list)
		}
	}
	return fmt.Errorf("no active connection %q", idOrName)
}

// ByClient finds the active connection a client key has paired with.
func (s *Store) ByClient(client string) (Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, _ := s.load()
	for _, c := range list {
		if !c.Revoked && slices.Contains(c.Clients, client) {
			return c, true
		}
	}
	return Conn{}, false
}

var ErrBadSecret = errors.New("unknown or used-up pairing secret")

// Pair binds a client key to the connection whose secret it presents. It fails when the secret is wrong, revoked, or already used by as many clients as allowed.
func (s *Store) Pair(client, secret string, now time.Time) (Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return Conn{}, err
	}
	h := hash(secret)
	for i := range list {
		c := &list[i]
		if c.Revoked || c.SecretHash != h {
			continue
		}
		if slices.Contains(c.Clients, client) {
			return *c, nil
		}
		if len(c.Clients) >= c.MaxClients {
			return Conn{}, ErrBadSecret
		}
		c.Clients = append(c.Clients, client)
		c.LastUsed = now.Unix()
		return *c, s.save(list)
	}
	return Conn{}, ErrBadSecret
}

func (s *Store) Touch(id string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, _ := s.load()
	for i := range list {
		if list[i].ID == id {
			list[i].LastUsed = now.Unix()
			_ = s.save(list)
			return
		}
	}
}
