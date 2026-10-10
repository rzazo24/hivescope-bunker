# hivescope-bunker

A NIP-46 remote signer for **one account**, running on your own server. Apps (Quill, nostrclaw, the relay panel) ask it to sign;
the key never leaves this process.

## How it keeps the key safe

- The key is stored **encrypted** (NIP-49: scrypt + XChaCha20-Poly1305), mode 0600, with a password you choose. It is never written in the clear.
- After every start the bunker is **locked**. You unlock it by hand (`hivescope-bunker unlock`); the decrypted key lives only in memory.
- Each app has its own **connection** with a **profile**: which event kinds it may sign and how many per hour. Anything else is refused.
  - `quill`: kinds 1, 3, 6, 7, 10002 (60/hour)
  - `nostrclaw`: kinds 1, 5, 7, 10050 (20/hour)
  - `panel`: kind 27235 only, the relay panel's NIP-98 login (30/hour)
- Pairing secrets are stored only as hashes. Revoking a connection stops it at the next request.
- Encryption/decryption requests (nip04/nip44) and unknown methods are refused. Old or repeated requests are ignored.
- No port is opened: the bunker connects out to relays, and the control socket is a unix socket (0600).

What it cannot protect against: someone with root on the machine **while it is unlocked**.

## Use

```
hivescope-bunker init                  # asks for the nsec and a password in the terminal (never as an argument)
hivescope-bunker serve                 # starts locked (run it under systemd, see below)
hivescope-bunker unlock                # asks for the password
hivescope-bunker add quill-phone quill # prints a bunker:// address, ONCE: it is a password
hivescope-bunker list | revoke <name> | lock | status
```

State lives in `~/.hivescope-bunker` (or `$HIVESCOPE_BUNKER_DIR`). Default relays: relay.hivescope.xyz and relay.damus.io (edit `config.json`).

## Tests

`go test ./...`. The end-to-end test starts a real relay and a real NIP-46 client; it needs `RELAY_BIN` (the khatru build) and is skipped without it.
