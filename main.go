// hivescope-bunker: a NIP-46 remote signer for one account, running on your own server.
// The key is encrypted on disk and unlocked by hand after every start; each app that connects gets a profile that limits what it may sign.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"hivescope-bunker/internal/conns"
	"hivescope-bunker/internal/server"
	"hivescope-bunker/internal/signer"
	"hivescope-bunker/internal/vault"
)

type config struct {
	TransportSecret string   `json:"transport_secret"` // carries the encrypted conversation; it is NOT the user's key
	Relays          []string `json:"relays"`
}

var defaultRelays = []string{"wss://relay.hivescope.xyz", "wss://relay.damus.io"}

func stateDir() string {
	if d := os.Getenv("HIVESCOPE_BUNKER_DIR"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".hivescope-bunker")
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func loadConfig(dir string) config {
	var c config
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		die("no configuration in %s: run `hivescope-bunker init` first", dir)
	}
	if json.Unmarshal(raw, &c) != nil || c.TransportSecret == "" {
		die("the configuration in %s is damaged", dir)
	}
	return c
}

// secretPrompt reads a line from the terminal without echoing it.
func secretPrompt(prompt string) string {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		die("this needs a terminal (it will not read a secret from a pipe or an argument)")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = tty
	_ = off.Run()
	defer func() { on := exec.Command("stty", "echo"); on.Stdin = tty; _ = on.Run(); fmt.Fprintln(tty) }()
	line, _ := bufio.NewReader(tty).ReadString('\n')
	return strings.TrimSpace(line)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: hivescope-bunker init | serve | unlock | lock | status | add <name> <quill|nostrclaw|panel> | list | revoke <name> | refresh <name>")
		os.Exit(2)
	}
	dir := stateDir()
	switch os.Args[1] {
	case "init":
		cmdInit(dir)
	case "serve":
		cmdServe(dir)
	case "unlock":
		pw := secretPrompt("Password: ")
		reply(server.Ask(filepath.Join(dir, "control.sock"), server.Control{Cmd: "unlock", Password: pw}))
	case "lock":
		reply(server.Ask(filepath.Join(dir, "control.sock"), server.Control{Cmd: "lock"}))
	case "status":
		reply(server.Ask(filepath.Join(dir, "control.sock"), server.Control{Cmd: "status"}))
	case "add":
		if len(os.Args) != 4 && len(os.Args) != 6 {
			if len(os.Args) != 6 || os.Args[4] != "--url" {
				die("usage: add <name> <quill|nostrclaw|panel> [--url <https://… for the panel profile>]")
			}
		}
		url := ""
		if len(os.Args) == 6 {
			url = os.Args[5]
		}
		cmdAdd(dir, os.Args[2], os.Args[3], url)
	case "list":
		cmdList(dir)
	case "revoke":
		if len(os.Args) != 3 {
			die("usage: revoke <name or id>")
		}
		if err := conns.Open(filepath.Join(dir, "connections.json")).Revoke(os.Args[2]); err != nil {
			die("%v", err)
		}
		fmt.Println("revoked: it stops working at the next request")
	case "refresh":
		if len(os.Args) != 3 {
			die("usage: refresh <name or id>")
		}
		c, err := conns.Open(filepath.Join(dir, "connections.json")).Refresh(os.Args[2])
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("%s (%s) may now sign kinds %v, up to %d an hour: from its next request\n", c.Name, c.Profile, c.Kinds, c.MaxPerHour)
	default:
		die("unknown command %q", os.Args[1])
	}
}

func reply(r server.Reply, err error) {
	if err != nil {
		die("%v", err)
	}
	state := "unlocked"
	if r.Locked {
		state = "LOCKED"
	}
	fmt.Printf("%s · %d active connection(s)", state, r.Conns)
	if r.Msg != "" {
		fmt.Printf(" · %s", r.Msg)
	}
	fmt.Println()
	if !r.OK {
		os.Exit(1)
	}
}

func cmdInit(dir string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		die("%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.ncryptsec")); err == nil {
		die("there is already a key in %s", dir)
	}
	secret := secretPrompt("Secret key (nsec1… or hex; typed here, never printed or stored in the clear): ")
	pw := secretPrompt("Password to encrypt it (10+ characters): ")
	if pw != secretPrompt("Repeat the password: ") {
		die("the passwords differ")
	}
	pk, err := vault.Init(filepath.Join(dir, "key.ncryptsec"), secret, pw)
	if err != nil {
		die("%v", err)
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	cfg, _ := json.MarshalIndent(config{TransportSecret: hex.EncodeToString(b), Relays: defaultRelays}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfg, 0o600); err != nil {
		die("%v", err)
	}
	npub, _ := nip19.EncodePublicKey(pk)
	fmt.Printf("Key saved, encrypted, in %s.\nThis bunker signs as %s\nCheck it is the right account before going on.\n", dir, npub)
}

func cmdServe(dir string) {
	cfg := loadConfig(dir)
	v := vault.New(filepath.Join(dir, "key.ncryptsec"))
	if !v.Exists() {
		die("no key: run `hivescope-bunker init`")
	}
	store := conns.Open(filepath.Join(dir, "connections.json"))
	h, err := signer.New(cfg.TransportSecret, v, store, cfg.Relays)
	if err != nil {
		die("%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := server.ServeControl(ctx, filepath.Join(dir, "control.sock"), v, store); err != nil {
			die("control socket: %v", err)
		}
	}()
	fmt.Printf("hivescope-bunker listening on %s, LOCKED: run `hivescope-bunker unlock`\n", strings.Join(cfg.Relays, ", "))
	server.ListenRelays(ctx, h, cfg.Relays)
}

func cmdAdd(dir, name, profile, urlPrefix string) {
	cfg := loadConfig(dir)
	store := conns.Open(filepath.Join(dir, "connections.json"))
	_, secret, err := store.Add(name, profile, urlPrefix, time.Now())
	if err != nil {
		die("%v", err)
	}
	pk, _ := nostr.GetPublicKey(cfg.TransportSecret)
	q := url.Values{}
	for _, r := range cfg.Relays {
		q.Add("relay", r)
	}
	q.Set("secret", secret)
	p := conns.Profiles[profile]
	if urlPrefix != "" {
		fmt.Printf("It signs only logins whose address starts with %s.\n", urlPrefix)
	}
	fmt.Printf("Connection %q (%s): may sign kinds %v, up to %d an hour.\nPaste this address into the app. It is shown only now and it is a password: do not share it.\n\nbunker://%s?%s\n", name, profile, p.Kinds, p.MaxPerHour, pk, q.Encode())
}

func cmdList(dir string) {
	list, err := conns.Open(filepath.Join(dir, "connections.json")).List()
	if err != nil {
		die("%v", err)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created < list[j].Created })
	for _, c := range list {
		state := "active"
		if c.Revoked {
			state = "revoked"
		}
		last := "never"
		if c.LastUsed > 0 {
			last = time.Unix(c.LastUsed, 0).Format("2006-01-02 15:04")
		}
		fmt.Printf("%-10s %-14s %-9s %-8s kinds=%v clients=%d/%d last used: %s\n", c.ID, c.Name, c.Profile, state, c.Kinds, len(c.Clients), c.MaxClients, last)
	}
	if len(list) == 0 {
		fmt.Println("no connections yet: add one with `hivescope-bunker add <name> <profile>`")
	}
}
