package signer

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nbd-wtf/go-nostr"
)

// Some kinds are only safe in one exact shape, whatever the app asking says: the bunker checks the content too, not just the kind, so that a
// leaked bunker:// address of the connection cannot get a broader permission signed than the app itself would ever ask for.

var (
	hex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digits = regexp.MustCompile(`^[0-9]+$`)
)

const (
	blossomAuthKind    = 24242
	blossomServersKind = 10063
	uploadTTL          = 300             // an upload permission lasts at most 5 minutes
	clockSkew          = 5 * time.Minute // and is made now, not dated in the future to be used later
)

// checkContent returns why an event of a kind with a fixed shape may not be signed, or nil (also for every other kind).
func checkContent(evt nostr.Event, now time.Time) error {
	switch evt.Kind {
	case blossomAuthKind:
		return checkUploadAuth(evt, now)
	case blossomServersKind:
		return checkServerList(evt)
	}
	return nil
}

// checkUploadAuth: Blossom (BUD-02) permission to upload ONE file, named by its hash, for a few minutes. Never a delete, a list, or one that lasts.
func checkUploadAuth(evt nostr.Event, now time.Time) error {
	bad := errors.New("only a permission to upload one file, for 5 minutes, may be signed")
	if utf8.RuneCountInString(evt.Content) > 100 || len(evt.Tags) != 3 {
		return bad
	}
	var t, x, exp []string
	for _, tag := range evt.Tags {
		if len(tag) != 2 {
			return bad
		}
		switch tag[0] {
		case "t":
			if t != nil {
				return bad
			}
			t = tag
		case "x":
			if x != nil {
				return bad
			}
			x = tag
		case "expiration":
			if exp != nil {
				return bad
			}
			exp = tag
		default:
			return bad
		}
	}
	if t == nil || x == nil || exp == nil || t[1] != "upload" || !hex64.MatchString(x[1]) || !digits.MatchString(exp[1]) {
		return bad
	}
	until, err := strconv.ParseInt(exp[1], 10, 64)
	if err != nil {
		return bad
	}
	created := int64(evt.CreatedAt)
	if left := until - created; left <= 0 || left > uploadTTL {
		return bad
	}
	if d := evt.CreatedAt.Time().Sub(now); d > clockSkew || d < -clockSkew {
		return errors.New("an upload permission must be dated now")
	}
	return nil
}

// checkServerList: the reader's Blossom server list (BUD-03), one to five https servers and nothing else.
func checkServerList(evt nostr.Event) error {
	bad := errors.New("only a list of 1 to 5 https servers may be signed")
	if evt.Content != "" || len(evt.Tags) < 1 || len(evt.Tags) > 5 {
		return bad
	}
	seen := map[string]bool{}
	for _, tag := range evt.Tags {
		if len(tag) != 2 || tag[0] != "server" || !tidyServer(tag[1]) || seen[tag[1]] {
			return bad
		}
		seen[tag[1]] = true
	}
	return nil
}

// tidyServer: exactly https://host (lower case, optional port), as Quill writes it: no path, user, query or fragment.
func tidyServer(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && u.User == nil &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && s == "https://"+u.Host
}
