package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"

	"hivescope-bunker/internal/conns"
	"hivescope-bunker/internal/signer"
	"hivescope-bunker/internal/vault"
)

// The bunker against a REAL relay (the khatru build in RELAY_BIN) and a real NIP-46 client (go-nostr's). Skipped without the binary.
func relayBin(t *testing.T) string {
	for _, p := range []string{os.Getenv("RELAY_BIN"), "../../../nostr-relay-khatru/nostr-relay-khatru"} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	t.Skip("no relay binary (set RELAY_BIN)")
	return ""
}

func startRelay(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cmd := exec.Command(relayBin(t))
	cmd.Env = append(os.Environ(), "RELAY_DB_PATH="+filepath.Join(t.TempDir(), "r.sqlite"), fmt.Sprintf("RELAY_LISTEN_ADDR=127.0.0.1:%d", port),
		"RELAY_EVENTS_PER_MINUTE=1000000", "RELAY_EVENTS_BURST=1000000", "RELAY_REQS_PER_MINUTE=1000000", "RELAY_REQS_BURST=1000000", "RELAY_CONNS_PER_MINUTE=1000000", "RELAY_CONNS_BURST=1000000")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	for i := 0; i < 80; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d", port), nil)
		req.Header.Set("Accept", "application/nostr+json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Sprintf("ws://127.0.0.1:%d", port)
}

func TestEndToEndThroughARealRelay(t *testing.T) {
	relay := startRelay(t)
	vault.ScryptLogN = 10
	dir := t.TempDir()
	userSK := nostr.GeneratePrivateKey()
	userPK, _ := nostr.GetPublicKey(userSK)
	if _, err := vault.Init(filepath.Join(dir, "key"), userSK, "a long enough password"); err != nil {
		t.Fatal(err)
	}
	v := vault.New(filepath.Join(dir, "key"))
	store := conns.Open(filepath.Join(dir, "c.json"))
	transport := nostr.GeneratePrivateKey()
	h, err := signer.New(transport, v, store, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go ListenRelays(ctx, h, []string{relay})
	time.Sleep(500 * time.Millisecond)

	// the control side: a locked bunker refuses, unlocking is done through the same function the socket uses
	_, secret, _ := store.Add("quill", "quill", time.Now())
	tpk, _ := nostr.GetPublicKey(transport)
	addr := fmt.Sprintf("bunker://%s?relay=%s&secret=%s", tpk, relay, secret)
	clientSK := nostr.GeneratePrivateKey()
	client, err := nip46.ConnectBunker(ctx, clientSK, addr, nil, nil)
	if err != nil {
		t.Fatal("connect:", err)
	}
	pub, err := client.GetPublicKey(ctx)
	if err == nil {
		t.Fatalf("a locked bunker gave the key: %s", pub)
	}
	if rep := Do(Control{Cmd: "unlock", Password: "wrong password!!"}, v, store); rep.OK {
		t.Fatal("wrong password unlocked")
	}
	if rep := Do(Control{Cmd: "unlock", Password: "a long enough password"}, v, store); !rep.OK || rep.Locked {
		t.Fatal("unlock failed")
	}
	if pub, err = client.GetPublicKey(ctx); err != nil || pub != userPK {
		t.Fatalf("get_public_key = %q, %v", pub, err)
	}
	evt := nostr.Event{Kind: 1, Content: "signed through a real relay", CreatedAt: nostr.Now(), Tags: nostr.Tags{}}
	if err := client.SignEvent(ctx, &evt); err != nil {
		t.Fatal("sign:", err)
	}
	if ok, _ := evt.CheckSignature(); !ok || evt.PubKey != userPK {
		t.Fatal("the event is not signed by the user's key")
	}
	bad := nostr.Event{Kind: 0, Content: "{}", CreatedAt: nostr.Now(), Tags: nostr.Tags{}}
	if err := client.SignEvent(ctx, &bad); err == nil {
		t.Fatal("a profile (kind 0) was signed for quill")
	}
}

// Not a test: with BUNKER_HOLD=<seconds> and BUNKER_ADDR_FILE it serves a bunker (profile from BUNKER_PROFILE, default quill) on a real relay and writes
// the relay URL and bunker address to the file, so a client in another language can be tried against it.
func TestHoldForAnExternalClient(t *testing.T) {
	hold := os.Getenv("BUNKER_HOLD")
	if hold == "" {
		t.Skip("BUNKER_HOLD not set")
	}
	var secs int
	fmt.Sscan(hold, &secs)
	relay := startRelay(t)
	vault.ScryptLogN = 10
	dir := t.TempDir()
	userSK := nostr.GeneratePrivateKey()
	userPK, _ := nostr.GetPublicKey(userSK)
	_, _ = vault.Init(filepath.Join(dir, "key"), userSK, "a long enough password")
	v := vault.New(filepath.Join(dir, "key"))
	_ = v.Unlock("a long enough password")
	store := conns.Open(filepath.Join(dir, "c.json"))
	transport := nostr.GeneratePrivateKey()
	h, _ := signer.New(transport, v, store, []string{relay})
	profile := os.Getenv("BUNKER_PROFILE")
	if profile == "" {
		profile = "quill"
	}
	_, secret, _ := store.Add("held", profile, time.Now())
	tpk, _ := nostr.GetPublicKey(transport)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	go ListenRelays(ctx, h, []string{relay})
	time.Sleep(500 * time.Millisecond)
	_ = os.WriteFile(os.Getenv("BUNKER_ADDR_FILE"), []byte(fmt.Sprintf("%s\n%s\n%s\n", relay, fmt.Sprintf("bunker://%s?relay=%s&secret=%s", tpk, relay, secret), userPK)), 0o600)
	<-ctx.Done()
}
