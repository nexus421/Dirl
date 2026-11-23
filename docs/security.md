# Security

## In short

- Hosts, keys and snippets live in an encrypted vault. In passphrase mode a stolen disk or backup reveals nothing.
- Login only through your OIDC provider, then through Dirl's own list of allowed users. Every allowed user can do
  everything, there are no roles.
- Each Dirl key is limited on the host with `restrict` and `from=`, a stolen key is of little use elsewhere.
- Host keys are pinned, a changed key blocks the host.
- Everything an SSH server sends is treated as untrusted and capped.

What you should do:

- Allow only people you would give the same access to every host yourself.
- Put the `authorized_keys` line from the host page on every host and use a key that exists only for Dirl.
- Keep an emergency path that does not depend on Dirl: your own keys and the provider's console.
- Keep the data directory to Dirl alone and the key file out of its backup.

## Vault

- `dataDir/vault.json` is one AES-256-GCM ciphertext with a new nonce on every write, which Dirl always creates
  itself (KotNexLib's default nonce argument makes data undecryptable). GCM also stops anyone from changing a pinned
  host key or adding a user in the file.
- The random data key (DEK) is stored only wrapped: with a key derived from the passphrase by Argon2id (64 MiB,
  3 passes) and, in key file mode, with the key file.
- Changing the passphrase creates a new DEK and deletes the local backups, the old passphrase opens nothing on the
  server any more. A retired key file gets the same treatment, see
  [Changing the mode or the key file](configuration.md#changing-the-mode-or-the-key-file). Earlier downloads still
  open with the old secret.
- The Argon2 parameters are not authenticated, so unlock and restore refuse more than 128 MiB, 10 passes or 4 lanes.
- Five wrong passphrases (unlock, key export and passphrase change, all users together) lock all three for
  15 minutes and are audited. The counter is in memory, a restart resets it.
- Writes are atomic (`fsync`, rename), the three previous versions stay as `vault.json.1` to `.3`.
- Not protected: an older genuine version put back in place (for example `vault.json.1`) opens with the same DEK and
  brings back a removed user or an old host key pin. Only Dirl's user and root can write the data directory (`0700`,
  see [Deployment](deployment.md)), and both could do worse anyway.

## Access

- Two gates: the provider's restriction of the client (in Pocket ID a user group), then Dirl's list of allowed users.
  Other accounts end up as access requests under Settings (the latest 20, in memory). A request under the display name
  of an allowed user is marked. Display names lose control and formatting characters and are cut to 80 characters.
- The list is checked on every request and again once a request body arrived, so a form held back over a removal
  changes nothing. Removing a user ends their sessions at once and their terminals within 30 seconds.
- While the vault is sealed, a plain copy (`access.json`) decides who reaches the unlock page, nothing more.
- Before a vault exists, anybody the provider lets through may create or restore it, unless
  `oidc.allowedSubjects` is set. The users listed there are always allowed (break-glass).
- Nobody can remove themselves, the last user cannot be removed.

## SSH

- Connections exist only while a Dirl page is open and close about 90 seconds after the last tab. One connection per
  host, terminals, files and metrics are channels on it (OpenSSH allows 10, `MaxSessions`).
- Failed connects back off from 30 seconds to 15 minutes, three rejected logins stop the host until "Connect now". No
  bare TCP pings, which fail2ban counts, liveness comes from SSH keepalives.
- Host keys: trust on first use with the `SHA256:` fingerprint, pinned per host. A different key blocks the host and
  is audited. Changing address, port or jump host removes the pin.
- Jump hosts: up to two hops, each checks its own pin, cycles are rejected. A "jump host only" offers no terminal,
  files or metrics.
- All Dirl users log in with the same account per host, so a tmux session of the same name is shared. That is
  deliberate, the users share that account anyway.
- A compromised server is treated as an attacker. Everything read from it is capped so it cannot exhaust the heap
  (which restarts Dirl sealed): metrics output at 256 KiB, directory listings at 10000 entries and 16 MiB, SFTP
  packets at 1 MiB, checked before sshj allocates them. Its text (system name, errors, disconnect messages) loses
  control characters and is cut before it is shown or logged.
- Uploads go to a temporary file with a random name created with `O_EXCL`, owner and permissions are set through the
  open handle, and it replaces the target only once it arrived completely. That needs `Content-Length`, which browsers
  send, a chunked upload (`curl -T -`) is not protected. Without "Overwrite existing files" nothing is replaced. The
  new file keeps permissions, owner and group, or the write is refused.
- Remaining risk, as with `scp`: a symlink as upload target is followed. Do not upload with a privileged login into
  directories that less privileged users can write to.
- sshj has no post-quantum key exchange, connections use curve25519.

## Limiting a stolen Dirl key

Each host page shows the line for that host:

```
restrict,pty,from="<Dirl IP>" ssh-ed25519 AAAA... dirl
```

A "jump host only" may only forward to the hosts behind it, a jump host that is also a terminal target keeps its PTY:

```
restrict,port-forwarding,permitopen="10.0.0.5:22",permitlisten="127.0.0.1:1",command="/bin/false",from="<Dirl IP>" ssh-ed25519 AAAA... dirl
restrict,pty,port-forwarding,permitopen="10.0.0.5:22",permitlisten="127.0.0.1:1",from="<Dirl IP>" ssh-ed25519 AAAA... dirl
```

A host behind a jump host gets the "Address seen by hosts behind it" of the jump host in its `from=`.

- `from=` takes addresses, CIDR ranges, wildcards (`10.1.*`) and exclusions (`!10.0.0.9`). Dirl stores the list
  without spaces and rejects what OpenSSH would reject silently (a space after a comma, an empty entry, a CIDR range
  with host bits set). Host names only match with `UseDNS yes`.
- Settings can leave `from=` out for setups where a firewall decides. A stolen key then works from anywhere that
  reaches the port.
- `permitlisten="127.0.0.1:1"` blocks TCP remote forwarding (`ssh -R`) and needs OpenSSH 7.8 or newer. Jump host
  lines copied before it existed allow `-R`, copy them again.
- Remote forwarding to a Unix socket cannot be limited in `authorized_keys`. Close it at the end of the jump host's
  `sshd_config`:

  ```
  Match Address <Dirl IP>
      AllowStreamLocalForwarding no
  ```

- Verified against OpenSSH 9.2 and 10.2. Keep `AllowTcpForwarding` enabled on jump hosts and raise `MaxSessions` where
  more than about eight terminals at once are normal.

## Login and web hardening

- OIDC Authorization Code Flow with PKCE S256, `state` and `nonce`, as confidential client. The login attempt travels
  in a signed cookie, the server keeps no state for it. A callback URL works once.
- The ID token comes straight from the token endpoint over TLS and is not signature-checked (OIDC Core 3.1.3.7).
  `iss`, `aud`, `azp`, `exp`, `iat` and `nonce` are checked.
- `forceReauth` sends `prompt=login`, Dirl cannot check that the provider honoured it.
- At most four calls to the provider at a time, so a flood of logins cannot block terminals. Rate-limit `/auth/` in
  the reverse proxy. The provider's answers are read without a size limit, it is the party Dirl trusts with the login.
- Session: `__Host-session` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), 60 minutes idle, 12 hours at most. The
  automatic update of the overview and the presence WebSocket do not count as activity. A new login does not end an
  older session of the same browser, logging out does.
- Strict CSP for scripts, no inline scripts, no `innerHTML`. Styles allow `unsafe-inline` because xterm.js needs it.
- Every POST and WebSocket upgrade must carry `Origin: <publicUrl>`. `Referrer-Policy` stays `same-origin`, with
  `no-referrer` browsers send `Origin: null` and every form fails.
- Further headers: `nosniff`, `X-Frame-Options: DENY`, COOP, CORP, `Permissions-Policy`, `Cache-Control: no-store`,
  HSTS when `publicUrl` is https. WebSocket frames are capped at 1 MiB.
- Snippet names and commands with hidden characters (control characters, U+202E) are refused, so the import preview
  shows what a click sends.
- Terminal output only goes into xterm.js, never into the page. Remote file names are cleaned before they go into a
  download header. A private key export asks for the passphrase again.
- The terminal reads the clipboard only on a right click and only with "Copy selected text and paste with a right
  click" on under Settings (off by default). With it on, pasted text with a line break that would run right away, or
  with any other control character (an escape could end bracketed paste early), asks first and shows those
  characters. This holds for the right click and for the browser's own paste (Ctrl+Shift+V). With it off, the
  browser's paste reaches the shell without asking, as before 1.2.0.

## Update check

While somebody uses Dirl, the server asks `api.github.com` at most once an hour for the latest release. GitHub sees the
server's address and the JDK's user agent, nothing from the vault. At most 1 MiB is read, no redirects, only a
`tag_name` of the form `v1.2.3` is used, nothing is downloaded. It can be turned off under Settings.

## Audit log

`dataDir/audit.jsonl` (`0600`), one JSON line per event, synced per entry: logins, access changes, vault events,
changes to hosts, keys, snippets and settings, key exports, host key pins and mismatches, terminals opened and closed,
every SFTP change and download. Never terminal contents, passphrases or keys. The Audit page reads only the last MiB.

## Logs

Console (journald) and `dataDir/logs/app.log` run every line through one format
([logLine](../src/main/kotlin/bayern/kickner/dirl/Common.kt)): control characters show as escapes such as `\x1b`, so
nothing in a log can run escape sequences in the terminal of whoever reads it, and further lines of a message are
indented, so no text can pass for a log line of its own.

[Back to the README](../README.md)
