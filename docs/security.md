# Security

How Dirl protects keys, access and the browser session, and why.

## Vault

`dataDir/vault.json` holds hosts, keys, host key pins, snippets and the UI settings as one AES-256-GCM ciphertext,
with a new random nonce on every write. The data key (DEK) is random and stored only wrapped: encrypted with a key
derived from the passphrase with Argon2id (64 MiB, 3 passes, stored next to the salt so they can be raised later), and
in key file mode additionally with the key file. Changing the passphrase creates a new DEK, re-encrypts the vault and
deletes the local backups, so the old passphrase opens nothing on the server any more. Backups downloaded earlier
still open with it. GCM also protects integrity, so nobody with write access can change a pinned host key or add a
user in the file.

The Argon2 parameters are not authenticated. Changing them only derives a wrong key, but huge values would exhaust the
heap or hang the unlock, so unlock and restore refuse more than 128 MiB, 10 passes or 4 lanes with a message instead
of running Argon2.

Writes go to a temporary file, are `fsync`ed and renamed over the old file. The previous three versions are kept as
`vault.json.1` to `vault.json.3`. Settings offers the current file as encrypted backup download, the setup page of a
fresh installation restores it.

GCM does not notice an older genuine version put back in place of the current one: every version opens with the same
DEK until the passphrase changes. Whoever can write to the data directory can therefore bring back a removed user or
an old host key pin, for example from `vault.json.1`. Real protection against that would need a place outside the
data directory that Dirl can write and an attacker cannot reset, which a plain server does not have. Only `dirl` and
root can write there with mode 0700 as in the [deployment](deployment.md), and both are beyond such a protection
anyway: root can read everything, the `dirl` user can read the keys from the memory of its own process unless ptrace
is restricted on the system. Keep the data directory to `dirl` alone.

KotNexLib's `AES.GCM.encrypt` only returns the ciphertext, and with its default nonce argument the result can never
be decrypted again. Dirl always creates the nonce itself and stores it next to the ciphertext
([crypto/Aead.kt](../src/main/kotlin/bayern/kickner/dirl/crypto/Aead.kt)).

## Access

Two gates: the group restriction in Pocket ID, then Dirl's own list of allowed users.

- While the vault is unlocked, the list in the vault decides, checked on every request. Removing a user ends their
  sessions and open terminals.
- While the vault is sealed, a plain copy (`dataDir/access.json`, `0600`) decides who reaches the unlock page.
  Tampering with it gives access to the passphrase prompt and nothing else. It is rewritten on every unlock.
- Before a vault exists, everybody the provider lets through may create it or restore a backup (first-run
  bootstrap). Whoever restores a backup may reach the unlock page, after the unlock the restored user list decides.
- `oidc.allowedSubjects` in the config is a break-glass list for the case that nobody in the UI list can log in.
- Rejected logins appear under Settings as access requests (in memory, the latest 20).
- You cannot remove yourself and the last user cannot be removed.
- There are no roles. Every allowed user can do everything: use all hosts, change hosts, keys and snippets, export
  keys (with the vault passphrase), allow and remove users, end sessions, seal the vault and change the passphrase
  (with the old one). Only allow people you would give the same access to every host yourself.

## SSH

- Connections only exist while somebody uses Dirl. Every request of a logged-in user counts while it runs (a
  download until it is done, a WebSocket until it is closed), and every Dirl page keeps a presence WebSocket open
  ([ssh/Presence.kt](../src/main/kotlin/bayern/kickner/dirl/ssh/Presence.kt)). 30 seconds after the last one ended,
  the next status round closes all connections, so they stay at most about 90 seconds after the last tab was
  closed, about two minutes after a laptop went to sleep. The next visit connects again. Closing keeps the backoff
  and the stop after rejected logins. The presence WebSocket carries no data, never extends the session and is
  closed when the session ends, so a forgotten tab does not keep the connections open.
- One connection per host while somebody is there. Terminals, SFTP and metrics are channels on it, a second
  terminal on the same host is a new channel with its own shell. OpenSSH allows 10 of them per connection
  (`MaxSessions`), so the eleventh terminal on a host, or the file manager next to ten terminals, is refused with that
  explanation. A refused terminal closes its channel again, so failed attempts never use up the limit.
- Failed connects back off from 30 seconds to 15 minutes. Three rejected logins in a row stop the host until
  "Connect now" is clicked. OpenSSH 9.8 and later (Debian 13 ships 10.0) do something similar on their own:
  `PerSourcePenalties` blocks a source address for a while after failed logins, which was confirmed in the tests.
  Dirl then shows "the server dropped the connection before the handshake" instead of a cryptic error.
- No TCP pings. A bare TCP connect shows up as `kex_exchange_identification` in the sshd log, which aggressive
  fail2ban filters count. Liveness comes from SSH keepalives (`KEEP_ALIVE`, which detects dead peers, unlike the
  default `HEARTBEAT`) and the status poll.
- Host keys: trust on first use. The first connection shows the `SHA256:` fingerprint for confirmation, the pin is
  stored per host in the vault. A different key blocks the host hard and is audited. Changing address, port or jump
  host removes the pin.
- Jump hosts: up to two, through direct-tcpip channels on the jump host's own managed connection. Every hop checks its
  own pinned key. Cycles and longer chains are rejected when a host is saved, also for the hosts behind it. A host
  marked "jump host only" offers no terminal, no files and no metrics, its connection is still kept and shown while
  somebody uses Dirl. Reference counting on the jump connection, as the concept suggested, is not needed: all
  connections are closed together when nobody uses Dirl, a dead jump connection takes its targets down and they
  reconnect through the backoff.
- Keys: Ed25519 generated with BouncyCastle in OpenSSH format, imports of unencrypted OpenSSH or PEM keys.
- Terminal: `xterm-256color` PTY with a plain login shell. There is no tmux integration: a shared session name would
  put several users into the same shell. Whoever wants tmux starts it in the terminal.
  Terminal input counts as session activity. A watchdog closes the terminal when the session ends or access is
  removed, sealing the vault closes all of them at once. After a disconnect, Enter reloads the page, which leads to
  the login when the session ended.
- Metrics: one `exec` per host and minute while somebody uses Dirl
  ([ssh/Metrics.kt](../src/main/kotlin/bayern/kickner/dirl/ssh/Metrics.kt)), plus one right after an arrival, unlock
  or "Connect now". It reads `/proc/stat` twice one second apart, so each poll has the CPU usage on its own. Only the
  latest sample per host is kept, in memory, and forgotten when nobody uses Dirl. A host whose previous poll still
  runs is skipped. Bind mounts and btrfs subvolumes of one device are shown once. Pure jump hosts with
  `command="/bin/false"` have no metrics.
- SFTP: bytes only, no encoding guessing. An upload never replaces an existing file unless "Overwrite existing files"
  is ticked, the skipped names are shown at the form. Uploads and edits go to a temporary file and are renamed over
  the target (`posix-rename`, with a fallback for servers without it). The new file keeps the permissions, owner and
  group of the old one and is never readable by others in between. If the login may not keep the owner or group, the
  write is refused and the file stays unchanged, a file of another user is changed by logging in as that user.
  Downloads keep 16 reads of 32 KiB in flight and uploads 16 writes, so a long round trip does not throttle a transfer
  to one block at a time. The editor only opens valid UTF-8 up to 1 MiB that a browser gives back unchanged: files
  with NUL characters, a carriage return without a line feed or mixed CRLF and LF line endings are refused, they can
  be downloaded instead. It keeps CRLF line endings and a leading empty line.
- A compromised server is treated as an attacker. Everything Dirl reads from it is capped, so it cannot exhaust
  the heap (which would restart Dirl sealed): metrics output at 256 KiB, the editor at 1 MiB even if the server
  reports a smaller size, directory listings at 10000 entries. Terminal output and downloads are streamed.
- sshj has no ML-KEM or sntrup key exchange, connections use curve25519. Fine for internal hops, MINA SSHD would be
  the replacement if post-quantum key exchange becomes a requirement.

## Limiting a stolen Dirl key

Inside the running process the keys are in memory in plain text. What a stolen key can do matters more than how it
is stored. Each host page shows the line to put into `authorized_keys`:

```
restrict,pty,from="<Dirl IP>" ssh-ed25519 AAAA... dirl
```

A host marked "jump host only" gets forwarding to the hosts behind it and nothing else:

```
restrict,port-forwarding,permitopen="10.0.0.5:22",command="/bin/false",from="<Dirl IP>" ssh-ed25519 AAAA... dirl
```

A jump host that is also a terminal target keeps its PTY and gets the same narrow forwarding:

```
restrict,pty,port-forwarding,permitopen="10.0.0.5:22",from="<Dirl IP>" ssh-ed25519 AAAA... dirl
```

A host behind a jump host sees the connection coming from the jump host, not from Dirl. Its line therefore gets the
"Address seen by hosts behind it" set on the jump host, often the jump host's address in the internal network:

```
restrict,pty,from="10.0.0.1" ssh-ed25519 AAAA... dirl
```

Without that address the line shows `<JUMP-HOST-IP>` and the host page says where to set it. In a chain every host is
limited to the host right before it.

A "jump host only" without any host behind it gets no forwarding at all, because `port-forwarding` without
`permitopen` would allow every destination. All forms were verified against OpenSSH 10.2, the line behind a jump host
against 9.2: the target accepts commands, PTY and SFTP, both jump variants forward only to the permitted target and
refuse other destinations, the pure jump host runs no commands. Use a key that exists only for Dirl.
`AllowTcpForwarding` must stay enabled on jump hosts (the default). Raise `MaxSessions` on a host where more than
about eight terminals at once are normal, all users of Dirl share its one connection. Keep an emergency path that does
not depend on Dirl: your own keys in the password manager and the provider's console.

## Login and web hardening

- OIDC Authorization Code Flow with PKCE S256, `state` and `nonce`, as a confidential client: the token request
  carries the client secret (HTTP Basic), so a stolen code and verifier are still useless to anybody but Dirl. The
  login attempt (state, nonce, PKCE verifier) travels in a `SameSite=Lax` cookie for ten minutes, signed with an HMAC
  key that is new on every start. The server keeps no state for started logins, so anonymous requests cannot fill
  memory or block the login. The callback deletes the cookie and the provider accepts each code once, so a callback
  URL works once.
- Calls to the provider are limited to four at a time, and a failed discovery fetch is not repeated for 15 seconds.
  Anonymous login requests against a slow or unreachable provider can therefore not tie up the threads that serve
  terminals and file transfers. The discovery document is fetched once and kept until restart, so restart Dirl after
  the provider moved its endpoints.
- The ID token is not signature-checked. It comes straight from the token endpoint over TLS, which OIDC Core 1.0
  section 3.1.3.7 allows as replacement. `iss`, `aud`, `azp`, `exp`, `iat` and `nonce` are checked
  ([auth/IdToken.kt](../src/main/kotlin/bayern/kickner/dirl/auth/IdToken.kt)).
- Session: `__Host-session` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), 256 bit random token, in memory, 60
  minutes idle, 12 hours at most (both configurable). The automatic reload of the host overview and the presence
  WebSocket it opens do not count as activity, so an unattended browser still reaches the idle timeout. The callback
  answers with a page that refreshes to `/`, because a redirect would belong to the cross-site navigation and the
  browser would not send the Strict cookie.
- CSP `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; ...`. `unsafe-inline` for styles is
  required by xterm.js 6, which creates `<style>` elements without nonce support. Scripts stay strict.
- Every POST and every WebSocket upgrade must carry `Origin: <publicUrl>`, Ktor does not check that for WebSockets.
  `Referrer-Policy` is `same-origin`, not `no-referrer`: with `no-referrer` browsers send `Origin: null` on form
  posts, which broke every form in the first browser test.
- Further headers: `nosniff`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy` and `-Resource-Policy`,
  `Permissions-Policy`, `Cache-Control: no-store`, HSTS when `publicUrl` is https.
- WebSocket frames are capped at 1 MiB (Ktor's default is unlimited), pings every 20 seconds keep the proxy from
  closing idle terminals and the presence WebSocket, and let Dirl notice a vanished browser.
- Terminal output is untrusted input. It only ever goes into xterm.js, never into the DOM, and the links addon is
  not loaded. All HTML is built with kotlinx.html, which escapes every value.
  Remote file names are cleaned before they go into a `Content-Disposition` header.
- Destructive actions ask for confirmation, a private key export asks for the vault passphrase again.

## Audit log

`dataDir/audit.jsonl` (`0600`), one JSON object per line, appended and synced per entry: logins, rejected logins,
access granted and removed, sessions ended, vault setup, restore, backup download, unlocks, failures and lockouts,
passphrase and settings changes, host and key changes, key exports, host key pins and mismatches, terminal open and
close, every SFTP change and download and every file opened in the editor. Reading files in a terminal is not visible
there, only that the terminal was opened. Never terminal contents, passphrases or keys. The Audit page shows and
filters the latest entries and only reads the last MiB of the file, so a log that grows for years stays cheap to view.

[Back to the README](../README.md)
