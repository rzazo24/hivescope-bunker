// Package server connects the handler to the relays (it listens for kind-24133 requests addressed to the bunker and publishes the answers)
// and to the local control socket (unlock, lock, status), which only the owner of the state directory can reach.
package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"hivescope-bunker/internal/conns"
	"hivescope-bunker/internal/signer"
	"hivescope-bunker/internal/vault"
)

type Control struct {
	Cmd      string `json:"cmd"`
	Password string `json:"password,omitempty"`
}

type Reply struct {
	OK     bool   `json:"ok"`
	Msg    string `json:"msg,omitempty"`
	Locked bool   `json:"locked"`
	Conns  int    `json:"connections"`
}

// ListenRelays answers requests until ctx ends. The pool reconnects to a relay that drops.
func ListenRelays(ctx context.Context, h *signer.Handler, relays []string) {
	pool := nostr.NewSimplePool(ctx)
	since := nostr.Timestamp(time.Now().Add(-2 * time.Minute).Unix())
	filter := nostr.Filter{Kinds: []int{nostr.KindNostrConnect}, Tags: nostr.TagMap{"p": []string{h.TransportPubKey()}}, Since: &since}
	for re := range pool.SubscribeMany(ctx, relays, filter) {
		ev := re.Event
		go func() {
			out := h.Handle(ev)
			if out == nil {
				return
			}
			for res := range pool.PublishMany(ctx, relays, *out) {
				if res.Error != nil {
					log.Printf("answer to %s not accepted by %s: %v", ev.ID[:8], res.RelayURL, res.Error)
				}
			}
		}()
	}
}

// ServeControl listens on a unix socket (mode 0600). One JSON line in, one JSON line out.
func ServeControl(ctx context.Context, path string, v *vault.Vault, c *conns.Store) error {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = ln.Close(); _ = os.Remove(path) }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			var req Control
			if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
				return
			}
			_ = json.NewEncoder(conn).Encode(Do(req, v, c))
		}()
	}
}

func Do(req Control, v *vault.Vault, c *conns.Store) Reply {
	n := 0
	if list, err := c.List(); err == nil {
		for _, x := range list {
			if !x.Revoked {
				n++
			}
		}
	}
	rep := Reply{Conns: n}
	switch req.Cmd {
	case "unlock":
		if err := v.Unlock(req.Password); err != nil {
			rep.Msg = err.Error()
		} else {
			rep.OK = true
			rep.Msg = "unlocked"
			log.Printf("unlocked")
		}
	case "lock":
		v.Lock()
		rep.OK = true
		rep.Msg = "locked"
		log.Printf("locked")
	case "status":
		rep.OK = true
	default:
		rep.Msg = "unknown command"
	}
	rep.Locked = v.Locked()
	return rep
}

var ErrNotRunning = errors.New("the bunker is not running (nothing is listening on its control socket)")

// Ask sends one command to a running bunker.
func Ask(path string, req Control) (Reply, error) {
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return Reply{}, ErrNotRunning
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Reply{}, err
	}
	var rep Reply
	return rep, json.NewDecoder(conn).Decode(&rep)
}
