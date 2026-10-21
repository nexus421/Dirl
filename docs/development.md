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

The actions in both workflows are pinned to commit hashes, the comment names the version.

## Run locally without Pocket ID

```bash
./gradlew devRun
```

Starts Dirl on `http://localhost:18080` together with a mock OIDC provider on port 18081 that offers two test users.
Data lives in `build/dev`, delete it to start over (`./gradlew clean` deletes it as well). The mock lives in the test
sources and never ends up in the JAR. `DEV_PASSPHRASE` in
[DevServer.kt](../src/test/kotlin/bayern/kickner/dirl/dev/DevServer.kt) is a suggestion for the throwaway dev vault.

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

The tests cover trust on first use, a changed host key, the stop after three rejected logins, both jump host
variants, an IPv6 target behind a restricted jump host (skipped without IPv6 loopback), atomic SFTP writes including
broken transfers, symlinks in listing, editor and delete, upload overwrite protection, the terminal WebSocket
including resize, closing all connections while a connect is still running (a held back handshake through
`GatedProxy`), closing for absence without losing a stop, and the status poll only while somebody is present and
never twice at once for a host. [PresenceWebTest.kt](../src/test/kotlin/bayern/kickner/dirl/web/PresenceWebTest.kt)
starts Dirl on a real CIO server and checks that an open presence WebSocket holds the presence, the engine detail
the connection model rests on.
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
| `config`           | Config model and strict loader with validation                                            |
| `crypto`           | Argon2id KEK derivation, AES-GCM with explicit nonce                                      |
| `vault`            | Vault model, crash-safe store, lifecycle (setup, unlock, lockout, passphrase change, backup, restore) |
| `audit`            | Append-only JSON lines audit log                                                          |
| `auth`             | OIDC client with PKCE, ID token validation, sessions, access control                      |
| `ssh`              | Keys, routes through jump hosts, connection manager, metrics                              |
| `web`              | Security guards, layout, error pages, the routes of every page, terminal, presence, SFTP  |
| `resources/static` | `app.css`, `app.js`, `terminal.js`, vendored xterm.js 6.0.0 and addon-fit 0.11.0          |
| test `dev`         | Mock OIDC provider and the `devRun` entry point                                           |

xterm.js is vendored, not fetched at build time. The files come from the npm tarballs `@xterm/xterm@6.0.0` and
`@xterm/addon-fit@0.11.0`, checked against the registry's SHA-512 integrity values, their SHA-256 sums are in
[SHA256SUMS](../src/main/resources/static/vendor/xterm/SHA256SUMS).

Conventions follow [DemoAiProject](https://github.com/nexus421/DemoAiProject): `.not()` instead of `!`,
`runCatching` by default, expected outcomes as `ResultOf2` and sealed types, KDoc on every public declaration, no
em dashes, en dashes or semicolons in prose. Deliberate deviations, decided in the concept: the fat JAR is built
with Shadow instead of the Ktor plugin, Klogger's SLF4J provider replaces `slf4j-simple`, and the UI is
server-rendered kotlinx.html instead of Compose, because xterm.js lives in the DOM.

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
| POST   | `/hosts`, `/hosts/{id}`                                      | Add, save                                       |
| POST   | `/hosts/{id}/delete`, `/connect`, `/pin`, `/forget-key`      | Host actions                                    |
| GET    | `/hosts/{id}/terminal`                                       | Terminal page                                   |
| WS     | `/ws/terminal/{id}?cols=&rows=`                              | Terminal stream                                 |
| WS     | `/ws/presence`                                               | Open while a Dirl page is open, no data         |
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

## Verification status

Verified:

- Build with every dependency of the concept's stack table, fat JAR with the merged Klogger SLF4J provider,
  BouncyCastle 1.86 everywhere.
- Every page clicked through in a browser, desktop and phone width, light layout and dark mode: login, setup,
  unlock with a wrong and the right passphrase, access request and grant, keys, hosts, host key confirmation for a
  jump host and a target behind it, terminal (fish shell, UTF-8, 300000 lines of output, `top`, resize to phone
  width, Ctrl+C from the key bar, snippets), files (upload with progress, CRLF preserving edit, rename, download,
  delete), metrics, audit log, settings, seal closing open terminals, key export, encrypted backup.
- Against OpenSSH 10.2: the restricted `authorized_keys` lines, jump host forwarding, `PerSourcePenalties`.
- 53 tests: vault (round trip, lockout, passphrase change including the old passphrase opening nothing, tampering,
  backups, key file, restore), audit log tail of a large file, OIDC (token checks, PKCE, the full flow, replayed
  callback, tampered login cookie, a flood of anonymous logins, a failing and a slow provider), backup restore through the UI up to the unlock,
  access control, idle timeout with automatic reloads, security headers, origin checks and path tricks, SSH integration as listed above plus both jump
  host variants, the upload overwrite protection and the limits on data read from servers.
- Dependency locking of every configuration.
- Argon2id with 64 MiB and 3 passes takes 100 to 200 ms on a fast desktop. Measure on the target, the concept aims
  for 0.5 to 1 s, raise `iterations` in [crypto/Argon2Kdf.kt](../src/main/kotlin/bayern/kickner/dirl/crypto/Argon2Kdf.kt)
  if it is much faster there. Existing vaults keep their parameters until the passphrase is changed.

Still open:

- Pocket ID itself: PKCE, group restriction, `prompt=login` (the protocol is covered by the mock provider tests).
- Ten minutes idle behind Zoraxy.
- Incus: LXCFS values in `/proc/meminfo`, `memory.swap.max`, systemd sandboxing.
- vim was not installed on the test machine.

[Back to the README](../README.md)
