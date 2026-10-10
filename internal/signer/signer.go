// Package signer answers NIP-46 requests. It is the only place that decides whether something gets signed, and it decides from one rule:
// a paired app may sign only the kinds its connection allows, at most N per hour, and only while the bunker is unlocked.
// Everything else (encrypting, decrypting, unknown methods) is refused.
package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip46"

	"hivescope-bunker/internal/conns"
	"hivescope-bunker/internal/vault"
)

const maxAge = 10 * time.Minute // a request older than this is a replay (a relay re-sending), not something a person just did

type Handler struct {
	Vault  *vault.Vault
	Conns  *conns.Store
	Relays []string
	Now    func() time.Time
	Logf   func(format string, args ...any)

	transportSK string
	transportPK string

	mu    sync.Mutex
	seen  map[string]time.Time // request ids already handled
	signs map[string][]time.Time
}

func New(transportSK string, v *vault.Vault, c *conns.Store, relays []string) (*Handler, error) {
	pk, err := nostr.GetPublicKey(transportSK)
	if err != nil {
		return nil, err
	}
	return &Handler{Vault: v, Conns: c, Relays: relays, Now: time.Now, Logf: log.Printf, transportSK: transportSK, transportPK: pk, seen: map[string]time.Time{}, signs: map[string][]time.Time{}}, nil
}

// TransportPubKey is the key in the bunker:// address. It is NOT the user's key: it only carries the encrypted conversation.
func (h *Handler) TransportPubKey() string { return h.transportPK }

func (h *Handler) session(client string) (nip46.Session, error) {
	shared, err := nip04.ComputeSharedSecret(client, h.transportSK)
	if err != nil {
		return nip46.Session{}, err
	}
	ck, err := nip44.GenerateConversationKey(client, h.transportSK)
	if err != nil {
		return nip46.Session{}, err
	}
	return nip46.Session{PublicKey: h.transportPK, SharedKey: shared, ConversationKey: ck}, nil
}

// Handle takes one kind-24133 event addressed to the bunker and returns the event to publish back (nil: say nothing).
func (h *Handler) Handle(ev *nostr.Event) *nostr.Event {
	now := h.Now()
	if ev.Kind != nostr.KindNostrConnect || !ev.CheckID() {
		return nil
	}
	if ok, _ := ev.CheckSignature(); !ok {
		return nil
	}
	if now.Sub(ev.CreatedAt.Time()) > maxAge || ev.CreatedAt.Time().Sub(now) > maxAge {
		return nil
	}
	sess, err := h.session(ev.PubKey)
	if err != nil {
		return nil
	}
	req, err := sess.ParseRequest(ev)
	if err != nil || req.ID == "" {
		return nil
	}
	if !h.firstTime(ev.ID, now) {
		return nil
	}
	result, rerr := h.dispatch(ev.PubKey, req, now)
	if rerr != nil {
		h.Logf("refused %s from %s: %v", req.Method, short(ev.PubKey), rerr)
	}
	_, out, err := sess.MakeResponse(req.ID, ev.PubKey, result, rerr)
	if err != nil {
		return nil
	}
	if err := out.Sign(h.transportSK); err != nil {
		return nil
	}
	return &out
}

func (h *Handler) firstTime(id string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, t := range h.seen {
		if now.Sub(t) > 2*maxAge {
			delete(h.seen, k)
		}
	}
	if _, dup := h.seen[id]; dup {
		return false
	}
	h.seen[id] = now
	return true
}

func (h *Handler) dispatch(client string, req nip46.Request, now time.Time) (string, error) {
	switch req.Method {
	case "connect":
		secret := ""
		if len(req.Params) >= 2 {
			secret = req.Params[1]
		}
		if c, ok := h.Conns.ByClient(client); ok {
			h.Conns.Touch(c.ID, now)
			return "ack", nil
		}
		c, err := h.Conns.Pair(client, secret, now)
		if err != nil {
			return "", errors.New("not authorised")
		}
		h.Logf("paired %q (%s) with client %s", c.Name, c.Profile, short(client))
		return "ack", nil
	case "ping":
		return "pong", nil
	}
	c, ok := h.Conns.ByClient(client)
	if !ok {
		return "", errors.New("not authorised")
	}
	switch req.Method {
	case "get_public_key":
		pk, err := h.Vault.PubKey()
		return pk, err
	case "get_relays":
		m := map[string]map[string]bool{}
		for _, r := range h.Relays {
			m[r] = map[string]bool{"read": true, "write": true}
		}
		b, _ := json.Marshal(m)
		return string(b), nil
	case "sign_event":
		return h.sign(c, req, now)
	}
	return "", fmt.Errorf("%q is not supported", req.Method)
}

func (h *Handler) sign(c conns.Conn, req nip46.Request, now time.Time) (string, error) {
	if len(req.Params) != 1 {
		return "", errors.New("sign_event takes one event")
	}
	var evt nostr.Event
	if err := json.Unmarshal([]byte(req.Params[0]), &evt); err != nil {
		return "", errors.New("that is not an event")
	}
	if !slices.Contains(c.Kinds, evt.Kind) {
		return "", fmt.Errorf("%s may not sign kind %d", c.Name, evt.Kind)
	}
	if c.URLPrefix != "" && !signsOnlyFor(evt, c.URLPrefix) {
		return "", fmt.Errorf("%s may only sign a login for %s", c.Name, c.URLPrefix)
	}
	if h.Vault.Locked() {
		return "", vault.ErrLocked
	}
	if !h.allow(c, now) {
		return "", errors.New("too many signatures in the last hour")
	}
	evt.PubKey, evt.ID, evt.Sig = "", "", ""
	if err := h.Vault.Sign(&evt); err != nil {
		return "", err
	}
	h.Conns.Touch(c.ID, now)
	h.Logf("signed kind %d for %s (%s)", evt.Kind, c.Name, evt.ID[:8])
	b, _ := json.Marshal(evt)
	return string(b), nil
}

// signsOnlyFor: a NIP-98 event names the address it is for in its `u` tag; a panel connection signs only ones for its own address,
// so a leaked pairing address cannot be used to log in to anything else.
func signsOnlyFor(evt nostr.Event, prefix string) bool {
	for _, tag := range evt.Tags {
		if len(tag) >= 2 && tag[0] == "u" && strings.HasPrefix(tag[1], prefix) {
			return true
		}
	}
	return false
}

// allow counts signatures per connection over the last hour; a refused one is not counted.
func (h *Handler) allow(c conns.Conn, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	recent := h.signs[c.ID][:0]
	for _, t := range h.signs[c.ID] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) >= c.MaxPerHour {
		h.signs[c.ID] = recent
		return false
	}
	h.signs[c.ID] = append(recent, now)
	return true
}

func short(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}
