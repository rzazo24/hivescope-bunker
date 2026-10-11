# hivescope-bunker

**[English](README.md) · [Español](README.es.md)**

A [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signer for **one Nostr account**, running on **your own server**. The apps you use
(a client like [Quill](https://github.com/rzazo24/quill), an assistant like [nostrclaw](https://github.com/rzazo24/nostrclaw), a relay's admin panel) ask it to
sign; each one is allowed to sign **only what it needs**, and your key never leaves this process.

It exists because a phone signer that must be woken by a push notification can fail at the worst moment. Running your own is more reliable, but it is a real
trade: **your key lives (encrypted) on a server instead of in your phone's keychain.** Read [what it cannot protect against](#what-it-cannot-protect-against) before you use it.

## How it keeps the key safe

- The key is stored **encrypted** ([NIP-49](https://github.com/nostr-protocol/nips/blob/master/49.md): scrypt + XChaCha20-Poly1305), mode 0600, with a password you choose. It is never written in the clear and never printed.
- After every start the bunker is **locked**. You unlock it by hand (`hivescope-bunker unlock`); the decrypted key then lives only in memory.
- Each app has its own **connection** with a **profile**: which event kinds it may sign and how many signatures per hour. Anything else is refused.

  | profile | kinds | per hour | notes |
  |---|---|---|---|
  | `quill` | 1, 3, 6, 7, 10000, 10002 | 60 | notes, follow list, reposts, reactions, mute list (public part), relay list |
  | `nostrclaw` | 1, 5, 7, 10050 | 20 | notes, deletions, reactions, DM relay list |
  | `panel` | 27235 | 30 | only a relay panel's NIP-98 login, and only for the address given with `--url` |

- Pairing secrets are stored only as **hashes**: the connections file alone cannot be used to connect. Revoking a connection stops it at the next request.
- Encryption and decryption requests (`nip04_*`, `nip44_*`) and unknown methods are **refused**. Old requests and repeated events are ignored.
- **No port is opened.** The bunker connects out to relays; its control socket is a unix socket (mode 0600).
- Every signature is logged (kind, app, short id), never the content.

## Install

You need Go 1.25+ and a Linux server with systemd.

```bash
git clone https://github.com/rzazo24/hivescope-bunker && cd hivescope-bunker
CGO_ENABLED=0 go build -o hivescope-bunker .
./hivescope-bunker init      # asks, in the terminal and without echo, for your nsec and a password (10+ characters)
```

`init` prints the `npub` it will sign as: **check it is the right account**. Then run it as a service that starts **locked** (edit the paths and user in the file first):

```bash
sudo cp deploy/hivescope-bunker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now hivescope-bunker
./hivescope-bunker unlock    # asks for the password
```

State lives in `~/.hivescope-bunker` (or `$HIVESCOPE_BUNKER_DIR`): `key.ncryptsec`, `config.json`, `connections.json`, `control.sock`.
Default relays are `relay.hivescope.xyz` and `relay.damus.io`; change them in `config.json`.

## Connect an app

```bash
./hivescope-bunker add quill-phone quill                 # prints a bunker:// address ONCE: it is a password
./hivescope-bunker add nostrclaw nostrclaw
./hivescope-bunker add panel panel --url https://your-relay.example/admin/api/login
./hivescope-bunker list                                  # connections, kinds, last use
./hivescope-bunker revoke quill-phone
./hivescope-bunker refresh quill-phone                   # after an update that widens a profile: gives an existing connection the new kinds
```

Paste the address into the app (never into a chat or a tool that logs it):

- **Quill**: *Me › Connect a signer › Paste and connect* (any `bunker://` address works).
- **nostrclaw**: `node dist/index.js connect-bunker --claude nostrclaw-sign` in your own terminal. A bunker approves by policy, not by a person, so its signatures come back in milliseconds and nostrclaw would discard them; set `"minHumanApprovalMs": 0` in its `policy.json` (see its README).
- **A relay panel with bunker login** (as in [nostr-relay-khatru](https://github.com/rzazo24/nostr-relay-khatru)): paste the address in the panel's login.

Other commands: `lock` (forget the key from memory now), `status`.

## After a restart

The service starts **locked**, so nothing can sign until you run `./hivescope-bunker unlock` over SSH. That is the price of not keeping the password on the server.

## Back up the key

Copy the single line in `~/.hivescope-bunker/key.ncryptsec` (it starts with `ncryptsec1`) to a password manager. It is encrypted, so it is safe to keep; **the password must be kept apart from it.** Connections are not part of the backup: create them again with `add`.

## What it cannot protect against

- Someone with **root on the machine while the bunker is unlocked** can sign within each connection's limits, and can read the key from memory.
- A weak password: the file is only as strong as it. Use a long one.
- A malicious app you paired. That is why every connection has a short list of kinds and an hourly limit.

## Tests

```bash
go test ./...
```

The end-to-end test starts a real relay and a real NIP-46 client; it needs `RELAY_BIN` (a build of [nostr-relay-khatru](https://github.com/rzazo24/nostr-relay-khatru)) and is skipped without it.

## License

MIT
