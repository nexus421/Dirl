# Dirl

Dirl is a small, self-hosted web SSH client: hosts with flat tags, a browser terminal (xterm.js), an SFTP file
manager, SSH key management, snippets and a status view with 24 hour charts (reachable, CPU, RAM, swap, disks). It
runs as one fat JAR (`java -jar`) behind a TLS-terminating reverse proxy, logs in through OpenID Connect (Pocket ID)
and is managed entirely in the browser.

It replaces a Termix installation with something small enough to review alone. There is no database, no frontend
framework and no plugin system: one Kotlin process on Ktor CIO, sshj for SSH, one encrypted JSON vault and about two
hundred lines of JavaScript. The design and its reasoning are in the German concept document
[termix-eigenbau-konzept.md](termix-eigenbau-konzept.md).

> Status: phases 1 to 3 of the concept are implemented and were clicked through in a browser against two real
> OpenSSH 10.2 servers (one as restricted jump host). 41 tests pass, eight of them against real `sshd` processes.
> Pocket ID itself, Zoraxy and the Incus container are not tested yet, see [Status](#status).

## Quick start

Requirements: JDK 25 to build (Amazon Corretto is the pinned toolchain, Gradle downloads it if missing). The JAR
targets Java 21, so the OpenJDK 21 from Debian 13 runs it.

```bash
./gradlew build shadowJar
```

```bash
cp config.example.json config.json
```

Set `publicUrl` and the `oidc` section, then:

```bash
java -jar build/libs/dirl.jar config=config.json
```

First run, all in the browser:

1. Sign in. As long as no vault exists, the first user the identity provider lets through may create it, so do this
   right after deployment. That user becomes the first allowed user.
2. Choose the vault passphrase (20 characters or 5 Diceware words, keep it in your password manager).
3. Settings: enter Dirl's source address, it fills `from="..."` in the `authorized_keys` lines.
4. Keys: generate an Ed25519 key.
5. Hosts: add a host. Its page shows the exact `authorized_keys` line, put it on the server.
6. Click "Connect now", compare the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the
   server and confirm it.
7. Open the terminal or the files.

Other people sign in, show up as access requests under Settings and are allowed with one click.

### Local development without Pocket ID

```bash
./gradlew devRun
```

Starts Dirl on `http://localhost:18080` together with a mock OIDC provider on port 18081 that offers two test users.
Data lives in `build/dev`, delete it to start over (`./gradlew clean` deletes it as well). The mock lives in the test sources and never ends up in the JAR.
`DEV_PASSPHRASE` in [DevServer.kt](src/test/kotlin/bayern/kickner/dirl/dev/DevServer.kt) is a suggestion for the
throwaway dev vault.

## Command line

Arguments are `key=value` pairs and bare words.

| Argument        | Default                 | Meaning                      |
|-----------------|-------------------------|------------------------------|
| `config=<path>` | `/etc/dirl/config.json` | Config file                  |
| `check`         |                         | Validate the config and exit |

| Exit code | Meaning                                                                         |
|-----------|---------------------------------------------------------------------------------|
| `0`       | Success (only with `check`, the server runs until stopped)                      |
| `1`       | Unexpected failure                                                              |
| `78`      | Config rejected or port cannot be bound (`EX_CONFIG`). systemd does not restart |

## Configuration

The config file only holds what is needed before anybody can log in: where to listen, how to reach the identity
provider and how the vault is unlocked. Everything else (users, hosts, keys, snippets, Dirl's source address,
passphrase) is managed in the UI and stored in the encrypted vault.

The file is read once at startup. Unknown keys are errors and all problems are reported at once. It holds no secret
except an optional OIDC client secret, so `0400` and owned by the service user.

| Field        | Type   | Default         | Description                                                                              |
|--------------|--------|-----------------|------------------------------------------------------------------------------------------|
| `host`       | string | `127.0.0.1`     | Bind address. TLS is done by the reverse proxy                                           |
| `port`       | int    | `8080`          | HTTP port                                                                                |
| `publicUrl`  | string | required        | URL in the browser, no trailing slash. OIDC redirect base and the only accepted `Origin` |
| `dataDir`    | string | `/var/lib/dirl` | Vault, backups, access list copy, audit log, logs                                        |
| `unlockMode` | string | `passphrase`    | `passphrase` or `keyfile`, see [Unlocking](#unlocking)                                   |
| `keyFile`    | string | `/etc/dirl/kek` | 32 random bytes, only read in `keyfile` mode                                             |
| `oidc`       | object | required        | See below                                                                                |
| `session`    | object | see below       | See below                                                                                |

`oidc`:

| Field             | Type     | Default                 | Description                                                                      |
|-------------------|----------|-------------------------|----------------------------------------------------------------------------------|
| `issuer`          | string   | required                | Issuer exactly as in the discovery document. `https` (or `http` on localhost)    |
| `clientId`        | string   | required                | Client ID in Pocket ID                                                           |
| `clientSecret`    | string   | `null`                  | Only for a confidential client. Pocket ID public clients with PKCE do not need it |
| `allowedSubjects` | string[] | `[]`                    | Break-glass list, always allowed. Only needed if nobody in the UI list can log in |
| `forceReauth`     | bool     | `true`                  | Sends `prompt=login`, so every login needs a fresh passkey                       |
| `scopes`          | string[] | `["openid", "profile"]` | Must contain `openid`                                                            |

`session`:

| Field                | Type | Default | Description                               |
|----------------------|------|---------|-------------------------------------------|
| `idleTimeoutMinutes` | int  | `30`    | Session expires after this much idle time |
| `maxAgeHours`        | int  | `12`    | Session expires this long after the login |

Pocket ID client setup: callback URL `<publicUrl>/auth/callback`, PKCE enabled, public client, under Access
"Selected user groups" a group like `dirl`. Optionally "Requires Re-Authentication".

## What the UI covers

| Page      | What you can do                                                                                                          |
|-----------|--------------------------------------------------------------------------------------------------------------------------|
| Hosts     | Overview cards with state, CPU, RAM and fullest disk, filter by tag. Add, edit, delete, connect now, disconnect. A host can be marked "jump host only" |
| Host      | Connection details, host key confirmation and pin removal, the restricted `authorized_keys` line with copy button, metrics with 24 hour charts, disks |
| Terminal  | xterm.js with resize, snippet buttons, a key bar with Ctrl, Esc, Tab, arrows on touch devices, Enter reconnects          |
| Files     | Breadcrumbs, path input, download, upload with progress (existing files only with "Overwrite existing files"), new directory, rename or move, delete, UTF-8 editor up to 1 MiB |
| Keys      | Generate Ed25519, import, rename, export after entering the passphrase again, delete unused keys, fingerprints           |
| Snippets  | Add, edit, delete, "run immediately" or "insert only"                                                                    |
| Audit     | The latest entries, filterable                                                                                           |
| Settings  | Access requests, allowed users, active sessions (end any), Dirl's source address, passphrase change, encrypted backup download, seal now |
| Setup     | Create the vault, or restore an encrypted backup                                                                         |

## Endpoints

Everything except `/login`, `/auth/*`, `/static/*` and `/healthz` requires a session of an allowed user. While the
vault is sealed only `/unlock`, `/setup`, `/setup/restore` and `/logout` work.

| Method | Path                                                         | Purpose                                         |
|--------|--------------------------------------------------------------|-------------------------------------------------|
| GET    | `/healthz`                                                   | Liveness, returns `ok`                          |
| GET    | `/login`, `/auth/start`, `/auth/callback`                    | Login                                           |
| POST   | `/logout`                                                    | End the session                                 |
| GET    | `/unlock`                                                    | Setup or unlock form                            |
| POST   | `/setup`, `/setup/restore`, `/unlock`                        | Create, restore or unlock the vault             |
| GET    | `/`                                                          | Host overview, `?tag=` filters                  |
| GET    | `/hosts/new`, `/hosts/{id}`, `/hosts/{id}/edit`              | Host pages                                      |
| GET    | `/hosts/{id}/chart.svg?m=cpu\|mem\|swap`                     | 24 hour chart                                   |
| POST   | `/hosts`, `/hosts/{id}`                                      | Add, save                                       |
| POST   | `/hosts/{id}/delete`, `/connect`, `/disconnect`, `/pin`, `/forget-key` | Host actions                          |
| GET    | `/hosts/{id}/terminal`                                       | Terminal page                                   |
| WS     | `/ws/terminal/{id}?cols=&rows=`                              | Terminal stream                                 |
| GET    | `/hosts/{id}/files?path=`, `/files/download`, `/files/edit`, `/files/rename` | File manager                    |
| POST   | `/hosts/{id}/files/upload`, `/mkdir`, `/delete`, `/rename`, `/save` | File operations                          |
| GET    | `/keys`, `/keys/{id}/export`                                 | Keys                                            |
| POST   | `/keys/generate`, `/keys/import`, `/keys/{id}/rename`, `/keys/{id}/export`, `/keys/{id}/delete` | Key actions  |
| GET    | `/snippets`, `/snippets/{id}/edit`                           | Snippets                                        |
| POST   | `/snippets`, `/snippets/{id}`, `/snippets/{id}/delete`       | Snippet actions                                 |
| GET    | `/audit?q=`                                                  | Audit log                                       |
| GET    | `/settings`, `/settings/backup`                              | Settings, encrypted vault download              |
| POST   | `/settings/users/allow`, `/settings/users/revoke`, `/settings/requests/dismiss`, `/settings/sessions/revoke`, `/settings/ssh`, `/settings/passphrase`, `/vault/seal` | Settings actions |

WebSocket protocol: binary frames carry terminal bytes in both directions. Text frames are JSON control messages,
`{"type":"resize","cols":120,"rows":40}` from the browser and `{"type":"error","message":"..."}` from the server.

## Behaviour

### Vault

`dataDir/vault.json` holds hosts, keys, host key pins, snippets and the UI settings as one AES-256-GCM ciphertext,
with a new random nonce on every write. The data key (DEK) is random and stored only wrapped: encrypted with a key
derived from the passphrase with Argon2id (64 MiB, 3 passes, stored next to the salt so they can be raised later),
and in key file mode additionally with the key file. Changing the passphrase rewraps the DEK, the data stays. GCM
also protects integrity, so nobody with write access can silently swap a pinned host key or add a user.

Writes go to a temporary file, are `fsync`ed and renamed over the old file. The previous three versions are kept as
`vault.json.1` to `vault.json.3`. Settings offers the current file as encrypted backup download, the setup page of a
fresh installation restores it.

KotNexLib's `AES.GCM.encrypt` only returns the ciphertext, and with its default nonce argument the result can never
be decrypted again. Dirl always creates the nonce itself and stores it next to the ciphertext
([crypto/Aead.kt](src/main/kotlin/bayern/kickner/dirl/crypto/Aead.kt)).

### Unlocking

| Scenario                                      | `passphrase` (default) | `keyfile`                                |
|-----------------------------------------------|------------------------|------------------------------------------|
| Full system backup or snapshot leaked         | protected              | **not** protected                        |
| tar of `/var/lib/dirl` leaked                 | protected              | protected while `/etc/dirl` is not in it |
| Root or code execution in the running process | not protected          | not protected                            |
| Unplanned restart                             | unlock once            | automatic                                |

In passphrase mode the process starts sealed: no SSH connections, no metrics, only login and unlock. Five wrong
passphrases lock unlocking for 15 minutes (counter in memory) and are written to the audit log. The passphrase check
before a key export counts towards the same lockout.

Key file mode: create the key with `head -c 32 /dev/urandom > /etc/dirl/kek`, `chmod 0400`, owner `dirl`, before
the vault is set up. The passphrase keeps working as fallback. Never put `/etc/dirl/kek` into the same backup as
`/var/lib/dirl`.

### Access

Two gates: the group restriction in Pocket ID, then Dirl's own list of allowed users.

- While the vault is unlocked, the list in the vault decides, checked on every request. Removing a user ends their
  sessions and open terminals.
- While the vault is sealed, a plain copy (`dataDir/access.json`, `0600`) decides who reaches the unlock page.
  Tampering with it gives access to the passphrase prompt and nothing else. It is rewritten on every unlock.
- Before a vault exists, everybody the provider lets through may create it (first-run bootstrap).
- `oidc.allowedSubjects` in the config is a break-glass list for the case that nobody in the UI list can log in.
- Rejected logins appear under Settings as access requests (in memory, the latest 20).
- You cannot remove yourself and the last user cannot be removed.

### SSH

- One long-lived connection per host. Terminals, SFTP and metrics are channels on it.
- Failed connects back off from 30 seconds to 15 minutes. Three rejected logins in a row stop the host until
  "Connect now" is clicked. OpenSSH 9.8 and later (Debian 13 ships 10.0) do something similar on their own:
  `PerSourcePenalties` blocks a source address for a while after failed logins, which was confirmed in the tests.
  Dirl then shows "the server dropped the connection before the handshake" instead of a cryptic error.
- No TCP pings. A bare TCP connect shows up as `kex_exchange_identification` in the sshd log, which aggressive
  fail2ban filters count. Liveness comes from SSH keepalives (`KEEP_ALIVE`, which detects dead peers, unlike the
  default `HEARTBEAT`) and the metrics poll.
- Host keys: trust on first use. The first connection shows the `SHA256:` fingerprint for confirmation, the pin is
  stored per host in the vault. A different key blocks the host hard and is audited. Changing address, port or jump
  host removes the pin.
- Jump hosts: up to two, through direct-tcpip channels on the jump host's own managed connection. Every hop checks
  its own pinned key. Cycles and longer chains are rejected when the host is saved. A host marked "jump host only"
  offers no terminal, no files and no metrics, its connection is still kept alive and shown. Reference counting on
  the jump connection, as the concept suggested, is not needed: connections are never closed for being idle, a dead
  jump connection takes its targets down and they reconnect through the backoff.
- Keys: Ed25519 generated with BouncyCastle in OpenSSH format, imports of unencrypted OpenSSH or PEM keys.
- Terminal: `xterm-256color` PTY, optionally inside `tmux new -A -s dirl-<name>` so it survives a page reload.
  Terminal input counts as session activity. A watchdog closes the terminal when the session ends or access is
  removed, sealing the vault closes all of them at once.
- Metrics: one `exec` per host and minute ([ssh/Metrics.kt](src/main/kotlin/bayern/kickner/dirl/ssh/Metrics.kt)),
  plus one right after unlock or "Connect now". 24 hours kept in memory, nothing persisted. Bind mounts and btrfs
  subvolumes of one device are shown once. Pure jump hosts with `command="/bin/false"` have no metrics.
- SFTP: bytes only, no encoding guessing. An upload never replaces an existing file unless "Overwrite existing
  files" is ticked, the skipped names are shown at the form. Uploads and edits go to a temporary file and are renamed over the target
  (`posix-rename`, with a fallback for servers without it). The editor only opens valid UTF-8 up to 1 MiB and keeps
  CRLF line endings and a leading empty line.
- sshj has no ML-KEM or sntrup key exchange, connections use curve25519. Fine for internal hops, MINA SSHD would be
  the replacement if post-quantum key exchange becomes a requirement.

### Limiting a stolen Dirl key

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

A "jump host only" without any host behind it gets no forwarding at all, because `port-forwarding` without
`permitopen` would allow every destination. All three forms were verified against OpenSSH 10.2: the target accepts
commands, PTY and SFTP, both jump variants forward only to the permitted target and refuse other destinations, the
pure jump host runs no commands. Use a key that exists only for Dirl. `AllowTcpForwarding` must
stay enabled on jump hosts (the default). Keep an emergency path that does not depend on Dirl: your own keys in the
password manager and the provider's console.

### Login and web hardening

- OIDC Authorization Code Flow with PKCE S256, `state` and `nonce`. The login attempt is kept on the server, the
  browser only holds a random ID in a `SameSite=Lax` cookie for ten minutes. A callback URL works once.
- The ID token is not signature-checked. It comes straight from the token endpoint over TLS, which OIDC Core 1.0
  section 3.1.3.7 allows as replacement. `iss`, `aud`, `azp`, `exp`, `iat` and `nonce` are checked
  ([auth/IdToken.kt](src/main/kotlin/bayern/kickner/dirl/auth/IdToken.kt)).
- Session: `__Host-session` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), 256 bit random token, in memory, 30
  minutes idle, 12 hours at most. The callback answers with a page that refreshes to `/`, because a redirect would
  belong to the cross-site navigation and the browser would not send the Strict cookie.
- CSP `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; ...`. `unsafe-inline` for styles is
  required by xterm.js 6, which creates `<style>` elements without nonce support. Scripts stay strict.
- Every POST and every WebSocket upgrade must carry `Origin: <publicUrl>`, Ktor does not check that for WebSockets.
  `Referrer-Policy` is `same-origin`, not `no-referrer`: with `no-referrer` browsers send `Origin: null` on form
  posts, which broke every form in the first browser test.
- Further headers: `nosniff`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy` and `-Resource-Policy`,
  `Permissions-Policy`, `Cache-Control: no-store`, HSTS when `publicUrl` is https.
- WebSocket frames are capped at 1 MiB (Ktor's default is unlimited), pings every 20 seconds keep the proxy from
  closing idle terminals.
- Terminal output is untrusted input. It only ever goes into xterm.js, never into the DOM, and the links addon is
  not loaded. All HTML is built with kotlinx.html, which escapes every value. Charts are SVG built from numbers only.
  Remote file names are cleaned before they go into a `Content-Disposition` header.
- Destructive actions ask for confirmation, a private key export asks for the vault passphrase again.

### Audit log

`dataDir/audit.jsonl` (`0600`), one JSON object per line, appended and synced per entry: logins, rejected logins,
access granted and removed, sessions ended, vault setup, restore, backup download, unlocks, failures and lockouts,
passphrase and settings changes, host and key changes, key exports, host key pins and mismatches, terminal open and
close, every SFTP change and download. Never terminal contents, passphrases or keys. The Audit page shows and filters
the latest entries.

## Deployment

Inside an Incus LXC behind Zoraxy:

```bash
useradd --system --home /var/lib/dirl --shell /usr/sbin/nologin dirl
install -d -o dirl -g dirl -m 0700 /var/lib/dirl
install -d -m 0755 /etc/dirl /opt/dirl
install -o dirl -g dirl -m 0400 config.json /etc/dirl/config.json
install -m 0644 build/libs/dirl.jar /opt/dirl/dirl.jar
install -m 0644 deploy/dirl.service /etc/systemd/system/dirl.service
systemctl daemon-reload
systemctl enable --now dirl
```

Then open `publicUrl` right away and create the vault, see [Quick start](#quick-start).

[deploy/dirl.service](deploy/dirl.service) runs with `-Xmx256m` (Argon2 briefly needs 64 MiB), `UMask=0077`, no
core dumps and systemd sandboxing. In an unprivileged container the sandboxing options can fail with
`status=226/NAMESPACE`. Then enable `security.nesting` for the container or drop the failing options.

Keep the keys out of swap:

```bash
incus config set <container> limits.memory 512MiB
incus config set <container> limits.memory.swap false
```

Zoraxy: proxy `publicUrl` to `127.0.0.1:8080` with WebSocket support. The 20 second WebSocket ping keeps idle
terminals open.

Backup: the encrypted download under Settings, or `tar czf dirl-$(date +%F).tgz -C /var/lib/dirl .`. Both are
useless without the passphrase.

Logs go to the console (journald) and to `dataDir/logs/app.log` (5 MiB, rotated). Libraries log through Klogger's
SLF4J provider, sshj only from WARN on.

## Development

```bash
./gradlew build
```

```bash
./gradlew devRun
```

The SSH integration tests ([SshIntegrationTest.kt](src/test/kotlin/bayern/kickner/dirl/ssh/SshIntegrationTest.kt))
start real OpenSSH servers as the current user on free loopback ports, no root needed. They use `/usr/sbin/sshd`
if installed (CI installs `openssh-server`), or an unpacked package from `DIRL_SSHD_ROOT`, and are skipped otherwise.
Without root and without installing anything:

```bash
apt-get download openssh-server openssh-sftp-server
```

```bash
for f in openssh-*.deb; do dpkg-deb -x "$f" "$HOME/sshd-root"; done
```

```bash
DIRL_SSHD_ROOT="$HOME/sshd-root" ./gradlew test
```

They cover trust on first use, a changed host key, the stop after three rejected logins, a restricted jump host,
atomic SFTP writes and the terminal WebSocket including resize. [LoginFlowTest.kt](src/test/kotlin/bayern/kickner/dirl/web/LoginFlowTest.kt)
runs the complete OIDC login against the mock provider.

```bash
unzip -p build/libs/dirl.jar META-INF/services/org.slf4j.spi.SLF4JServiceProvider
```

The last command must print `bayern.kickner.klogger.slf4j.KloggerServiceProvider`. Shadow's default duplicate
strategy drops duplicate service files before `mergeServiceFiles()` sees them, so
[build.gradle.kts](build.gradle.kts) uses `INCLUDE` with an `EXCLUDE` exception for everything else. CI checks it.

### Updating dependencies

Every dependency version, including transitive ones, is locked in [gradle.lockfile](gradle.lockfile), so a build
never picks up a new version unnoticed. Checksum verification of the artifacts (`verification-metadata.xml`, which
the concept suggested) was tried and dropped again: IntelliJ downloads source JARs and the Gradle sources for
display, and every one of them failed verification, which made the IDE sync fail. After changing a version in
`build.gradle.kts`:

```bash
./gradlew dependencies --write-locks
```

Review the diff of the lockfile before committing. Releases worth watching: sshj, Ktor, BouncyCastle, xterm.js.

### Project layout

One package per concern under `bayern.kickner.dirl`:

| Package / file     | Content                                                                                   |
|--------------------|-------------------------------------------------------------------------------------------|
| `Main.kt`          | Argument parsing, config, logging, wiring, server start                                   |
| `config`           | Config model and strict loader with validation                                            |
| `crypto`           | Argon2id KEK derivation, AES-GCM with explicit nonce                                      |
| `vault`            | Vault model, crash-safe store, lifecycle (setup, unlock, lockout, rewrap, backup, restore) |
| `audit`            | Append-only JSON lines audit log                                                          |
| `auth`             | OIDC client with PKCE, ID token validation, sessions, access control                      |
| `ssh`              | Keys, routes through jump hosts, connection manager, metrics                              |
| `web`              | Security guards, layout, error pages, charts, the routes of every page, terminal, SFTP    |
| `resources/static` | `app.css`, `app.js`, `terminal.js`, vendored xterm.js 6.0.0 and addon-fit 0.11.0          |
| test `dev`         | Mock OIDC provider and the `devRun` entry point                                           |

xterm.js is vendored, not fetched at build time. The files come from the npm tarballs `@xterm/xterm@6.0.0` and
`@xterm/addon-fit@0.11.0`, checked against the registry's SHA-512 integrity values, their SHA-256 sums are in
[SHA256SUMS](src/main/resources/static/vendor/xterm/SHA256SUMS).

Conventions follow [DemoAiProject](https://github.com/nexus421/DemoAiProject): `.not()` instead of `!`,
`runCatching` by default, expected outcomes as `ResultOf2` and sealed types, KDoc on every public declaration, no
em dashes, en dashes or semicolons in prose. Deliberate deviations, decided in the concept: the fat JAR is built
with Shadow instead of the Ktor plugin, Klogger's SLF4J provider replaces `slf4j-simple`, and the UI is
server-rendered kotlinx.html instead of Compose, because xterm.js lives in the DOM.

## Status

Verified:

- Build with every dependency of the concept's stack table, fat JAR with the merged Klogger SLF4J provider,
  BouncyCastle 1.86 everywhere.
- Every page clicked through in a browser, desktop and phone width, light layout and dark mode: login, setup,
  unlock with a wrong and the right passphrase, access request and grant, keys, hosts, host key confirmation for a
  jump host and a target behind it, terminal (fish shell, UTF-8, 300000 lines of output, `top`, resize to phone
  width, Ctrl+C from the key bar, snippets), files (upload with progress, CRLF preserving edit, rename, download,
  delete), metrics, audit log, settings, seal closing open terminals, key export, encrypted backup.
- Against OpenSSH 10.2: the restricted `authorized_keys` lines, jump host forwarding, `PerSourcePenalties`.
- 41 tests: vault (round trip, lockout, passphrase change, tampering, backups, key file, restore), OIDC (token
  checks, PKCE, the full flow, replayed callback), access control, security headers and origin checks, SSH
  integration as listed above plus both jump host variants and the upload overwrite protection.
- Dependency locking of every configuration.
- Argon2id with 64 MiB and 3 passes takes 100 to 200 ms on a fast desktop. Measure on the target, the concept aims
  for 0.5 to 1 s, raise `iterations` in [crypto/Argon2Kdf.kt](src/main/kotlin/bayern/kickner/dirl/crypto/Argon2Kdf.kt)
  if it is much faster there. Existing vaults keep their parameters until the passphrase is changed.

Still open:

- Pocket ID itself: PKCE, group restriction, `prompt=login` (the protocol is covered by the mock provider tests).
- Ten minutes idle behind Zoraxy.
- Incus: LXCFS values in `/proc/meminfo`, `memory.swap.max`, systemd sandboxing.
- tmux and vim were not installed on the test machine, `tmux new -A` is untested.

## Not in scope

Separate data per user, roles, sharing, RDP or VNC, Docker, tunnels, automations, plugins, desktop or mobile apps,
sync, LDAP and other logins than OIDC, TOTP or passkeys inside Dirl (Pocket ID does that), alerts, persisted metric
history, a database, i18n, themes, telemetry.

## Sources

- Concept: [termix-eigenbau-konzept.md](termix-eigenbau-konzept.md) (German).
- Conventions: [DemoAiProject](https://github.com/nexus421/DemoAiProject).
- [Klogger](https://github.com/nexus421/Klogger) 0.5.0, [KotNexLib](https://github.com/nexus421/KotNexLib) 4.4.1,
  [Ktor](https://ktor.io/) 3.6.0, [sshj](https://github.com/hierynomus/sshj) 0.41.2,
  [BouncyCastle](https://www.bouncycastle.org/) 1.86, [xterm.js](https://xtermjs.org/) 6.0.0.
- OpenID Connect Core 1.0 section 3.1.3.7, RFC 7636 (PKCE), OpenSSH `sshd_config(5)` (`PerSourcePenalties`).
