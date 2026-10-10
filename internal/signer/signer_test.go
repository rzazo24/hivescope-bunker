package signer

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip46"

	"hivescope-bunker/internal/conns"
	"hivescope-bunker/internal/vault"
)

type rig struct {
	t      *testing.T
	h      *Handler
	store  *conns.Store
	vault  *vault.Vault
	userPK string
	now    time.Time
	n      int
}

func newRig(t *testing.T, unlock bool) *rig {
	t.Helper()
	vault.ScryptLogN = 10
	dir := t.TempDir()
	userSK := nostr.GeneratePrivateKey()
	userPK, _ := nostr.GetPublicKey(userSK)
	keyfile := filepath.Join(dir, "key")
	if _, err := vault.Init(keyfile, userSK, "a long enough password"); err != nil {
		t.Fatal(err)
	}
	v := vault.New(keyfile)
	if unlock {
		if err := v.Unlock("a long enough password"); err != nil {
			t.Fatal(err)
		}
	}
	store := conns.Open(filepath.Join(dir, "conns.json"))
	h, err := New(nostr.GeneratePrivateKey(), v, store, []string{"wss://relay.example"})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, h: h, store: store, vault: v, userPK: userPK, now: time.Unix(1_800_000_000, 0)}
	h.Now = func() time.Time { return r.now }
	h.Logf = func(string, ...any) {}
	return r
}

// client is an app with its own key, talking to the bunker the way a real NIP-46 client does.
type client struct {
	r  *rig
	sk string
	pk string
}

func (r *rig) newClient() *client {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	return &client{r: r, sk: sk, pk: pk}
}

// call sends one request and returns (result, error text); "" for both means the bunker stayed silent.
func (c *client) call(method string, params ...string) (string, string) {
	c.r.n++
	return c.callID(string(rune('a'+c.r.n%26))+strings.Repeat("x", c.r.n), method, params...)
}

func (c *client) callID(id, method string, params ...string) (string, string) {
	ck, _ := nip44.GenerateConversationKey(c.r.h.TransportPubKey(), c.sk)
	body, _ := json.Marshal(nip46.Request{ID: id, Method: method, Params: params})
	enc, _ := nip44.Encrypt(string(body), ck)
	ev := nostr.Event{Kind: nostr.KindNostrConnect, CreatedAt: nostr.Timestamp(c.r.now.Unix()), Content: enc, Tags: nostr.Tags{{"p", c.r.h.TransportPubKey()}}}
	_ = ev.Sign(c.sk)
	out := c.r.h.Handle(&ev)
	if out == nil {
		return "", ""
	}
	plain, err := nip44.Decrypt(out.Content, ck)
	if err != nil {
		c.r.t.Fatal("cannot read the answer:", err)
	}
	var resp nip46.Response
	_ = json.Unmarshal([]byte(plain), &resp)
	return resp.Result, resp.Error
}

func (r *rig) pair(profile string) (*client, string) {
	url := ""
	if profile == "panel" {
		url = "https://relay.example/admin/api/"
	}
	c, secret, err := r.store.Add(profile+"-app", profile, url, r.now)
	if err != nil {
		r.t.Fatal(err)
	}
	_ = c
	cl := r.newClient()
	res, e := cl.call("connect", r.h.TransportPubKey(), secret)
	if res != "ack" || e != "" {
		r.t.Fatalf("pairing failed: %q %q", res, e)
	}
	return cl, secret
}

func note(content string) string {
	b, _ := json.Marshal(nostr.Event{Kind: 1, Content: content, CreatedAt: nostr.Timestamp(1_800_000_000), Tags: nostr.Tags{}})
	return string(b)
}

func eventOfKind(k int) string {
	b, _ := json.Marshal(nostr.Event{Kind: k, Content: "", CreatedAt: nostr.Timestamp(1_800_000_000), Tags: nostr.Tags{}})
	return string(b)
}

func TestPairedAppSignsAllowedKindAsTheUser(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("quill")
	if pk, e := c.call("get_public_key"); pk != r.userPK || e != "" {
		t.Fatalf("get_public_key = %q %q", pk, e)
	}
	res, e := c.call("sign_event", note("hello"))
	if e != "" {
		t.Fatal(e)
	}
	var ev nostr.Event
	_ = json.Unmarshal([]byte(res), &ev)
	if ev.PubKey != r.userPK || ev.Content != "hello" {
		t.Fatalf("wrong event %+v", ev)
	}
	if ok, _ := ev.CheckSignature(); !ok || !ev.CheckID() {
		t.Fatal("the signature is not valid")
	}
}

func TestKindsOutsideTheConnectionAreRefused(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("panel") // the panel may sign only kind 27235
	for _, k := range []int{1, 3, 0, 5, 30078} {
		if res, e := c.call("sign_event", eventOfKind(k)); res != "" || !strings.Contains(e, "may not sign") {
			t.Fatalf("kind %d: %q %q", k, res, e)
		}
	}
	if _, e := c.call("sign_event", loginEvent("https://relay.example/admin/api/login")); e != "" {
		t.Fatal(e)
	}
	q, _ := r.pair("quill")
	if _, e := q.call("sign_event", eventOfKind(5)); e == "" { // quill cannot delete; nostrclaw can
		t.Fatal("quill signed a deletion")
	}
}

func TestUnknownClientsAndWrongSecretsGetNothing(t *testing.T) {
	r := newRig(t, true)
	r.pair("quill")
	stranger := r.newClient()
	if res, e := stranger.call("sign_event", note("x")); res != "" || e != "not authorised" {
		t.Fatalf("%q %q", res, e)
	}
	if _, e := stranger.call("get_public_key"); e != "not authorised" {
		t.Fatal("a stranger learned the key")
	}
	if _, e := stranger.call("connect", r.h.TransportPubKey(), "wrong"); e != "not authorised" {
		t.Fatal("a wrong secret paired")
	}
	if _, e := stranger.call("connect", r.h.TransportPubKey()); e != "not authorised" {
		t.Fatal("no secret paired")
	}
}

func TestASecretPairsOnlyAsManyClientsAsAllowed(t *testing.T) {
	r := newRig(t, true)
	_, secret := r.pair("quill") // one client allowed
	second := r.newClient()
	if _, e := second.call("connect", r.h.TransportPubKey(), secret); e != "not authorised" {
		t.Fatal("a second device paired with a single-use secret")
	}
	_, panelSecret := r.pair("panel") // a web page makes a new key on every login
	for i := 0; i < 5; i++ {
		if res, e := r.newClient().call("connect", r.h.TransportPubKey(), panelSecret); res != "ack" {
			t.Fatalf("login %d: %q", i, e)
		}
	}
}

func TestRevokedConnectionStopsAtOnce(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("quill")
	if err := r.store.Revoke("quill-app"); err != nil {
		t.Fatal(err)
	}
	if _, e := c.call("sign_event", note("x")); e != "not authorised" {
		t.Fatalf("a revoked app signed: %q", e)
	}
}

func TestLockedBunkerSignsNothing(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("quill")
	r.vault.Lock()
	if res, e := c.call("sign_event", note("x")); res != "" || !strings.Contains(e, "locked") {
		t.Fatalf("%q %q", res, e)
	}
	if _, e := c.call("get_public_key"); !strings.Contains(e, "locked") {
		t.Fatal("the key was given while locked")
	}
	if err := r.vault.Unlock("a long enough password"); err != nil {
		t.Fatal(err)
	}
	if _, e := c.call("sign_event", note("x")); e != "" {
		t.Fatal(e)
	}
}

func TestRateLimitPerHour(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("nostrclaw") // 20 an hour
	for i := 0; i < 20; i++ {
		if _, e := c.call("sign_event", note("n")); e != "" {
			t.Fatalf("signature %d refused: %s", i, e)
		}
	}
	if _, e := c.call("sign_event", note("n")); !strings.Contains(e, "too many") {
		t.Fatalf("no limit: %q", e)
	}
	r.now = r.now.Add(61 * time.Minute)
	if _, e := c.call("sign_event", note("n")); e != "" {
		t.Fatalf("still limited an hour later: %s", e)
	}
}

func (c *client) event(id, method string, at time.Time) nostr.Event {
	ck, _ := nip44.GenerateConversationKey(c.r.h.TransportPubKey(), c.sk)
	body, _ := json.Marshal(nip46.Request{ID: id, Method: method})
	enc, _ := nip44.Encrypt(string(body), ck)
	ev := nostr.Event{Kind: nostr.KindNostrConnect, CreatedAt: nostr.Timestamp(at.Unix()), Content: enc, Tags: nostr.Tags{{"p", c.r.h.TransportPubKey()}}}
	_ = ev.Sign(c.sk)
	return ev
}

func TestRepliesAreNeverRepeatedAndOldRequestsAreIgnored(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("quill")
	ev := c.event("p1", "ping", r.now)
	if r.h.Handle(&ev) == nil {
		t.Fatal("no answer to a fresh request")
	}
	if r.h.Handle(&ev) != nil {
		t.Fatal("the same event (a relay re-sending it) was answered twice")
	}
	old := c.event("p2", "ping", r.now.Add(-time.Hour))
	if r.h.Handle(&old) != nil {
		t.Fatal("an hour-old request was answered")
	}
}

func TestEncryptionAndUnknownMethodsAreRefused(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("quill")
	other := r.newClient().pk
	for _, m := range []string{"nip44_decrypt", "nip44_encrypt", "nip04_decrypt", "nip04_encrypt", "whatever"} {
		if res, e := c.call(m, other, "x"); res != "" || e == "" {
			t.Fatalf("%s: %q %q", m, res, e)
		}
	}
}

func TestForgedEventsAreIgnored(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("quill")
	ck, _ := nip44.GenerateConversationKey(r.h.TransportPubKey(), c.sk)
	body, _ := json.Marshal(nip46.Request{ID: "f1", Method: "ping"})
	enc, _ := nip44.Encrypt(string(body), ck)
	ev := nostr.Event{Kind: nostr.KindNostrConnect, CreatedAt: nostr.Timestamp(r.now.Unix()), Content: enc, Tags: nostr.Tags{{"p", r.h.TransportPubKey()}}}
	_ = ev.Sign(c.sk)
	ev.Sig = strings.Repeat("0", 128) // not signed by the client any more
	if r.h.Handle(&ev) != nil {
		t.Fatal("a badly signed request was answered")
	}
}

func loginEvent(u string) string {
	b, _ := json.Marshal(nostr.Event{Kind: 27235, Content: "", CreatedAt: nostr.Timestamp(1_800_000_000), Tags: nostr.Tags{{"u", u}, {"method", "POST"}}})
	return string(b)
}

func TestPanelSignsOnlyLoginsForItsOwnAddress(t *testing.T) {
	r := newRig(t, true)
	c, _ := r.pair("panel")
	if _, e := c.call("sign_event", loginEvent("https://relay.example/admin/api/login")); e != "" {
		t.Fatal("refused its own login:", e)
	}
	for _, u := range []string{"https://evil.example/admin/api/login", "https://relay.example.evil.com/x", "http://relay.example/admin/api/login"} {
		if res, e := c.call("sign_event", loginEvent(u)); res != "" || !strings.Contains(e, "may only sign a login for") {
			t.Fatalf("%s: %q %q", u, res, e)
		}
	}
	if _, e := c.call("sign_event", eventOfKind(27235)); !strings.Contains(e, "may only sign a login for") {
		t.Fatal("signed a login that names no address")
	}
}
