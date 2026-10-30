# Development

Requirements: JDK 25 (Amazon Corretto is the pinned toolchain, Gradle downloads it if missing). Always use the
Gradle wrapper.

## Build and test

```bash
./gradlew build
```

`build` compiles, runs all tests and builds the fat JAR `build/libs/dirl.jar` (`./gradlew shadowJar` alone skips the
tests). GitHub Actions runs the same on every push and pull request, including the SSH integration tests.

## Release

1. Set `version` in `build.gradle.kts`, commit and push.
2. Publish a release on GitHub with the tag `v<version>`, e.g. `v0.2.0` for `version = "0.2.0"`.

[release.yml](../.github/workflows/release.yml) then checks that the tag matches the version, runs all tests, builds
`dirl.jar` and attaches it to the release together with `dirl.jar.sha256`. A tag that does not match fails the run
and attaches nothing.

The actions in both workflows are pinned to commit hashes, the comment names the version. All of them run on
Node.js 24. `gradle/actions/setup-gradle` v6 keeps its caching in a closed-source component under the Gradle Terms of
Use (https://gradle.com/legal/terms-of-use/), using it means accepting them. `cache-provider: basic` would switch to an
open-source cache instead.

## Run locally without an OIDC provider

```bash
./gradlew devRun
```

Starts Dirl on `http://localhost:18080` together with a mock OIDC provider on port 18081 that offers two test users.
Data lives in `build/dev`, delete it to start over (`./gradlew clean` deletes it as well). The mock lives in the test
sources and never ends up in the JAR. `DEV_PASSPHRASE` in
[DevServer.kt](../src/test/kotlin/bayern/kickner/dirl/dev/DevServer.kt) is a suggestion for the throwaway dev vault.

## Demo with test data

```bash
./gradlew demoRun
```

Starts Dirl on `http://localhost:18090` with demo data, to look at the UI without setting anything up. "Sign in" logs
in Ada right away (mock provider on port 18091), the vault unlocks with a key file. The hosts are real OpenSSH
servers on loopback: two pinned hosts, a pure jump host with a host behind it, a host behind a proxy that delays
every packet by 70 ms (a round trip of about 140 ms), two hosts with partly replaced metrics (a full disk, reboot
needed, a failed service, more load), one offline and one with an unconfirmed host key. It needs an `sshd` like the
integration tests below, or an unpacked `openssh-server` in `build/sshd-root`. Every start begins from scratch in
`build/demo`. [DemoServer.kt](../src/test/kotlin/bayern/kickner/dirl/dev/DemoServer.kt) lives in the test sources and
never ends up in the JAR.

## SSH integration tests

[SshIntegrationTest.kt](../src/test/kotlin/bayern/kickner/dirl/ssh/SshIntegrationTest.kt) starts real OpenSSH
servers as the current user on free loopback ports, no root needed. It uses `/usr/sbin/sshd` if installed (CI
installs `openssh-server`), or an unpacked package from `DIRL_SSHD_ROOT`, and is skipped otherwise. Without root and
without installing anything:

```bash
apt-get download openssh-server openssh-sftp-server
```

```bash
for f in openssh-*.deb; do dpkg-deb -x "$f" "$HOME/sshd-root"; done
```

```bash
DIRL_SSHD_ROOT="$HOME/sshd-root" ./gradlew test
```

The tests cover trust on first use, a changed host key, the stop after three rejected logins, both jump host variants
including refused TCP remote forwarding, an IPv6 target behind a restricted jump host (skipped without IPv6 loopback),
a target that sees the jump host's address instead of Dirl's (skipped without a non-loopback IPv4 address), atomic
SFTP writes including broken transfers and kept permissions and group, downloads byte for byte around the read-ahead
block size, symlinks in listing, overwrite and delete, upload overwrite protection and the reason of a failed upload,
rename onto an existing entry or a dangling symlink, a hostile SFTP server announcing a 1 GiB packet, the terminal
WebSocket including resize, a refused terminal not using up the sessions of a connection and the explanation beyond
the session limit, closing all connections while a connect is still running (a held back handshake through
`GatedProxy`), closing for absence without losing a stop, the status poll only while somebody is present and never
twice at once for a host, the round trip of every poll (a pure jump host as well, a host behind a delaying proxy
turning the row yellow, nothing from a closed connection, forgotten when nobody is present), and `from="..."` lists:
which entries OpenSSH refuses (a space after a comma, an empty entry, a bad CIDR range), that the normalized form
works, and that the line the host page shows for several source addresses, or for none, lets Dirl in.
[PresenceWebTest.kt](../src/test/kotlin/bayern/kickner/dirl/web/PresenceWebTest.kt) starts Dirl on a real CIO server
and checks that an open presence WebSocket holds the presence, the engine detail the connection model rests on.
[LoginFlowTest.kt](../src/test/kotlin/bayern/kickner/dirl/web/LoginFlowTest.kt) runs the complete OIDC login against
the mock provider.

## Fat JAR check

```bash
unzip -p build/libs/dirl.jar META-INF/services/org.slf4j.spi.SLF4JServiceProvider
```

Must print `bayern.kickner.klogger.slf4j.KloggerServiceProvider`. Shadow's default duplicate strategy drops
duplicate service files before `mergeServiceFiles()` sees them, so [build.gradle.kts](../build.gradle.kts) uses
`INCLUDE` with an `EXCLUDE` exception for everything else. CI checks it.

## Updating dependencies

Every dependency version, including transitive ones, is locked in [gradle.lockfile](../gradle.lockfile), so a build
never picks up a new version unnoticed. Checksum verification of the artifacts (`verification-metadata.xml`, which
the concept suggested) was tried and dropped again: IntelliJ downloads source JARs and the Gradle sources for
display, and every one of them failed verification, which made the IDE sync fail. After changing a version in
`build.gradle.kts`:

```bash
./gradlew dependencies --write-locks
```

Review the diff of the lockfile before committing. Releases worth watching: sshj, Ktor, BouncyCastle, xterm.js.

Pushes to `master` submit the resolved dependencies to GitHub's dependency graph. With "Dependency graph" and
"Dependabot alerts" enabled in the repository settings (both are off by default), GitHub reports known vulnerabilities
in any of them, transitive ones included. There are no automatic update pull requests: they would change
`build.gradle.kts` without the lockfile and fail the build.

## Project layout

One package per concern under `bayern.kickner.dirl`:

| Package / file     | Content                                                                                   |
|--------------------|-------------------------------------------------------------------------------------------|
| `Main.kt`          | Argument parsing, config, logging, wiring, server start                                   |
| `UpdateCheck.kt`   | Asks GitHub at most once an hour for the newest release, version rules, answer limit      |
| `config`           | Config model and strict loader with validation                                            |
| `crypto`           | Argon2id KEK derivation, AES-GCM with explicit nonce                                      |
| `vault`            | Vault model, crash-safe store, lifecycle (setup, unlock, lockout, passphrase change, backup, restore) |
| `audit`            | Append-only JSON lines audit log                                                          |
| `auth`             | OIDC client with PKCE, ID token validation, sessions, access control                      |
| `ssh`              | Keys, routes through jump hosts, connection manager, metrics                              |
| `web`              | Security guards, layout, error pages, the routes of every page, terminal, presence, SFTP  |
| `resources/static` | `app.css`, `app.js`, `terminal.js`, `manifest.json` with the app icons, icons as SVG masks, vendored xterm.js 6.0.0 and addon-fit 0.11.0 |
| test `dev`         | Mock OIDC provider, the `devRun` and `demoRun` entry points                               |

xterm.js is vendored, not fetched at build time. The files come from the npm tarballs `@xterm/xterm@6.0.0` and
`@xterm/addon-fit@0.11.0`, checked against the registry's SHA-512 integrity values, their SHA-256 sums are in
[SHA256SUMS](../src/main/resources/static/vendor/xterm/SHA256SUMS).

Conventions follow [DemoAiProject](https://github.com/nexus421/DemoAiProject): `.not()` instead of `!`,
`runCatching` by default, expected outcomes as `ResultOf2` and sealed types, KDoc on every public declaration, no
em dashes, en dashes or semicolons in prose. Deliberate deviations, decided in the concept: the fat JAR is built
with Shadow instead of the Ktor plugin, Klogger's SLF4J provider replaces `slf4j-simple`, and the UI is
server-rendered kotlinx.html instead of Compose, because xterm.js lives in the DOM.

## Endpoints

Everything except `/login`, `/auth/start`, `/auth/callback`, `/healthz` and `/static/*` requires a session of an
allowed user. The public paths are matched exactly, only `/static/` is a prefix. While the vault is sealed only
`/unlock`, `/setup`, `/setup/restore` and `/logout` work.

| Method | Path                                                         | Purpose                                         |
|--------|--------------------------------------------------------------|-------------------------------------------------|
| GET    | `/healthz`                                                   | Liveness, returns `ok`                          |
| GET    | `/login`, `/auth/start`, `/auth/callback`                    | Login                                           |
| POST   | `/logout`                                                    | End the session                                 |
| GET    | `/unlock`                                                    | Setup or unlock form                            |
| POST   | `/setup`, `/setup/restore`, `/unlock`                        | Create, restore or unlock the vault             |
| GET    | `/`                                                          | Host overview, `?tag=` filters                  |
| GET    | `/hosts/new`, `/hosts/{id}`, `/hosts/{id}/edit`, `/hosts/arrange` | Host pages, order of the overview          |
| POST   | `/hosts`, `/hosts/{id}`, `/hosts/arrange`                    | Add, save, save the order                       |
| POST   | `/hosts/{id}/delete`, `/connect`, `/pin`, `/forget-key`, `/pinned` | Host actions, `/pinned` pins to the top   |
| GET    | `/hosts/{id}/terminal`                                       | Terminal page                                   |
| WS     | `/ws/terminal/{id}?cols=&rows=`                              | Terminal stream                                 |
| WS     | `/ws/presence`                                               | Open while a Dirl page is open, no data         |
| GET    | `/hosts/{id}/files?path=`, `/files/download`, `/files/rename` | File manager                                   |
| POST   | `/hosts/{id}/files/upload`, `/mkdir`, `/delete`, `/rename`   | File operations                                 |
| GET    | `/keys`, `/keys/{id}/export`                                 | Keys                                            |
| POST   | `/keys/generate`, `/keys/import`, `/keys/{id}/rename`, `/keys/{id}/export`, `/keys/{id}/delete` | Key actions  |
| GET    | `/snippets`, `/snippets/{id}/edit`, `/snippets/export`, `/snippets/tmux` | Snippets, export of all as JSON, preview of the tmux snippets |
| POST   | `/snippets`, `/snippets/{id}`, `/snippets/{id}/delete`, `/snippets/import` (preview), `/snippets/import/apply` | Snippet actions |
| GET    | `/audit?q=`                                                  | Audit log                                       |
| GET    | `/settings`, `/settings/backup`                              | Settings, encrypted vault download              |
| POST   | `/settings/users/allow`, `/settings/users/revoke`, `/settings/requests/dismiss`, `/settings/sessions/revoke`, `/settings/ssh`, `/settings/updates`, `/settings/passphrase`, `/vault/seal` | Settings actions |

WebSocket protocol: binary frames carry terminal bytes in both directions. Text frames are JSON control messages,
`{"type":"resize","cols":120,"rows":40}` from the browser and `{"type":"error","message":"..."}` from the server.

## Verification status

Verified:

- Build with every dependency of the concept's stack table, fat JAR with the merged Klogger SLF4J provider,
  BouncyCastle 1.86 everywhere.
- Every page clicked through in a browser, desktop and phone width, light layout and dark mode: login, setup,
  unlock with a wrong and the right passphrase, access request and grant, keys, hosts, host key confirmation for a
  jump host and a target behind it, terminal (fish shell, UTF-8, 300000 lines of output, `top`, resize to phone
  width, Ctrl+C from the key bar, snippets), files (upload with progress, rename, download,
  delete), metrics, audit log, settings, seal closing open terminals, key export, encrypted backup.
- Against OpenSSH 10.2: the restricted `authorized_keys` lines before `permitlisten`, jump host forwarding,
  `PerSourcePenalties`. Against 9.2: the current lines and the `Match` block against Unix socket forwarding.
- Login against a real Pocket ID instance as confidential client with PKCE.
- In production in an Incus LXC (1 GiB, autostart) behind Zoraxy: a terminal idle for ten minutes stays usable, the
  hardened unit runs without sandboxing errors, `memory.swap.max` is `0` with `limits.memory.swap false`.
- 166 tests: vault (round trip, lockout also on passphrase change, passphrase change including the old passphrase
  opening nothing, tampering, backups, key file, restore, KDF parameter bounds), audit log tail of a large file, OIDC
  (token checks, PKCE, client secret, the full flow, replayed callback, tampered login cookie, a flood of anonymous
  logins, a failing and a slow provider), backup restore through the UI up to the unlock, access control (including
  revokes at the same moment), idle timeout with automatic reloads, security headers, origin checks and path tricks,
  config validation including `config.example.json`, the keys page layout, the login page (the scan, one sign in, no app
  bar, an unreachable provider), the host overview (pins, the order of the vault, the arrange page and its form,
  warnings, critical values, an offline host, the health rules, round trip text, tag colors), source address lists for
  `from="..."` (normalizing, rejected entries, the switch to leave it out), presence (on a real CIO server), snippet
  folders (folded, the changed one open), snippet placeholders (what counts as one, Go templates left alone, the marks
  on the buttons, the limit, where they show), the import drop zone, snippet export and import (round trip between two
  instances, the file format and its problems, preview states, all four ways to import, refused and oversized input,
  session and origin), metrics (real output, missing parts, text from the server, the reboot rule, the choice per host
  and what each card shows), the update check (version rules, answer limit, at most once an hour, the switch, the
  footer, no version before the login), SSH integration as listed above and the limits on data read from servers.
  Without an `sshd` the 25 SSH integration tests are skipped.
- The fat JAR in production mode (`-Xmx256m -XX:+ExitOnOutOfMemoryError`, fresh data directory) against the mock
  provider and two OpenSSH servers: first login and vault setup (a weak passphrase refused), key, a jump host and a
  target behind it, host key confirmation, terminal with a snippet from a folder, every file operation, closing all
  connections about a minute after the last page was left, reconnecting on return, encrypted backup, key export with
  a wrong and the right passphrase, seal and unlock, logout. Vault, access list and audit log are `0600`, the log
  holds no errors and no secrets.
- Dependency locking of every configuration.
- Argon2id with 64 MiB and 3 passes takes 100 to 200 ms on a fast desktop. Measure on the target, the concept aims
  for 0.5 to 1 s, raise `iterations` in [crypto/Argon2Kdf.kt](../src/main/kotlin/bayern/kickner/dirl/crypto/Argon2Kdf.kt)
  if it is much faster there. Existing vaults keep their parameters until the passphrase is changed.

Still open:

- Incus: LXCFS values in `/proc/meminfo` when a container is a monitored host, so far only VMs and physical servers
  were monitored.
- vim was not installed on the test machine.

[Back to the README](../README.md)
