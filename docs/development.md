# Development

JDK 25 (Amazon Corretto is the pinned toolchain, Gradle downloads it if missing). Always use the Gradle wrapper.

## Build and test

```bash
./gradlew build
```

Compiles, runs all tests and builds `build/libs/dirl.jar` (`./gradlew shadowJar` alone skips the tests). CI runs the
same on every push, with the SSH integration tests. The tests of the placeholder code in `terminal.js` need `node`.

```bash
docker build --tag dirl:test .
DIRL_DOCKER_IMAGE=dirl:test ./gradlew dockerImageTest
```

The [Dockerfile](../Dockerfile) packs the finished JAR, so `build` comes first.
[DockerImageTest.kt](../src/test/kotlin/bayern/kickner/dirl/DockerImageTest.kt) starts the image with the restrictions
of [deploy/docker-compose.yml](../deploy/docker-compose.yml) and goes through a whole first start against the mock
provider and a local sshd. CI runs it after the build.

## SSH integration tests

[SshIntegrationTest.kt](../src/test/kotlin/bayern/kickner/dirl/ssh/SshIntegrationTest.kt) starts real OpenSSH
servers as the current user on loopback. It uses `/usr/sbin/sshd` or an unpacked package from `DIRL_SSHD_ROOT` and is
skipped without one. Without root:

```bash
apt-get download openssh-server openssh-sftp-server
```

```bash
for f in openssh-*.deb; do dpkg-deb -x "$f" "$HOME/sshd-root"; done
```

```bash
DIRL_SSHD_ROOT="$HOME/sshd-root" ./gradlew test
```

## Run locally

```bash
./gradlew devRun
```

Dirl on `http://localhost:18080` with a mock OIDC provider on port 18081 and two test users, data in `build/dev`.
`DEV_PASSPHRASE` in [DevServer.kt](../src/test/kotlin/bayern/kickner/dirl/dev/DevServer.kt) suggests a passphrase.

```bash
./gradlew demoRun
```

Dirl on `http://localhost:18090` with demo data: "Sign in" logs in right away, the vault unlocks with a key file, the
hosts are real OpenSSH servers on loopback (a jump host, a slow host, warnings, an offline host, an unconfirmed host
key). Needs an sshd like the integration tests, or an unpacked `openssh-server` in `build/sshd-root`. Every start
begins from scratch in `build/demo`.

Both live in the test sources and never end up in the JAR. Not on shared machines: they listen on loopback only, but
there anyone on the machine is logged in without a password.

## Release

1. Set `version` in `build.gradle.kts`, commit and push.
2. Publish a release on GitHub with the tag `v<version>`.

[release.yml](../.github/workflows/release.yml) checks that tag and version match, runs all tests, attaches `dirl.jar`
and `dirl.jar.sha256` to the release and pushes the image for amd64 and arm64 to `ghcr.io/nexus421/dirl` as
`<version>` and, unless it is a pre-release, `latest`. Should the package show up as private after the first release,
set it to public once in its settings on GitHub.

The actions are pinned to commit hashes. `gradle/actions/setup-gradle` caches through a closed-source component under
the [Gradle Terms of Use](https://gradle.com/legal/terms-of-use/), `cache-provider: basic` would avoid that.

## Updating dependencies

Every version, transitive ones included, is locked in [gradle.lockfile](../gradle.lockfile). After changing a version
in `build.gradle.kts`:

```bash
./gradlew dependencies --write-locks
```

Review the lockfile diff. Worth watching: sshj, Ktor, BouncyCastle, xterm.js. There is no `verification-metadata.xml`,
it broke the IntelliJ sync. Pushes to `master` submit the dependency graph to GitHub for Dependabot alerts.

The wrapper checks the downloaded Gradle against `distributionSha256Sum`. A Gradle update needs the checksum from
`https://services.gradle.org/distributions/gradle-<version>-bin.zip.sha256`, run this twice:

```bash
./gradlew wrapper --gradle-version <version> --gradle-distribution-sha256-sum <checksum>
```

After a change of dependencies or of the Shadow config, check the merged SLF4J service file (CI does as well):

```bash
unzip -p build/libs/dirl.jar META-INF/services/org.slf4j.spi.SLF4JServiceProvider
```

It must print `bayern.kickner.klogger.slf4j.KloggerServiceProvider`.

xterm.js 6.0.0 and addon-fit 0.11.0 are vendored from the npm tarballs, checked against the registry's integrity
values, with their SHA-256 sums in [SHA256SUMS](../src/main/resources/static/vendor/xterm/SHA256SUMS).

## Project layout

| Package / file     | Content                                                                         |
|--------------------|---------------------------------------------------------------------------------|
| `Main.kt`          | Arguments, config, logging, wiring, server start                                |
| `UpdateCheck.kt`   | Asks GitHub for the newest release                                              |
| `config`           | Config model and strict loader                                                  |
| `crypto`           | Argon2id key derivation, AES-GCM with explicit nonce                            |
| `vault`            | Vault model, crash-safe store, setup, unlock, lockout, passphrase change, backup |
| `audit`            | Append-only audit log                                                           |
| `auth`             | OIDC client, ID token checks, sessions, access control                          |
| `ssh`              | Keys, jump host routes, connection manager, metrics                             |
| `web`              | Guards, layout, error pages, the routes of every page, terminal, presence, SFTP |
| `resources/static` | `app.css`, `app.js`, `terminal.js`, manifest and icons, vendored xterm.js       |
| test `dev`         | Mock OIDC provider, `devRun` and `demoRun`                                      |

Conventions follow [DemoAiProject](https://github.com/nexus421/DemoAiProject). Deliberate deviations: Shadow instead
of the Ktor plugin, Klogger's SLF4J provider instead of `slf4j-simple`, server-rendered kotlinx.html instead of
Compose, because xterm.js lives in the DOM.

## Endpoints

Everything except `/login`, `/auth/start`, `/auth/callback`, `/healthz` and `/static/*` needs a session of an allowed
user. While the vault is sealed only `/unlock`, `/setup`, `/setup/restore` and `/logout` work.

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
| POST   | `/hosts/{id}/delete`, `/connect`, `/pin`, `/forget-key`, `/pinned` | Host actions                              |
| GET    | `/hosts/{id}/terminal`                                       | Terminal page                                   |
| WS     | `/ws/terminal/{id}?cols=&rows=`                              | Terminal stream                                 |
| WS     | `/ws/presence`                                               | Open while a Dirl page is open, no data         |
| GET    | `/hosts/{id}/files?path=`, `/files/download`, `/files/rename` | File manager                                   |
| POST   | `/hosts/{id}/files/upload`, `/mkdir`, `/delete`, `/rename`   | File operations                                 |
| GET    | `/keys`, `/keys/{id}/export`                                 | Keys                                            |
| POST   | `/keys/generate`, `/keys/import`, `/keys/{id}/rename`, `/keys/{id}/export`, `/keys/{id}/delete` | Key actions  |
| GET    | `/snippets`, `/snippets/{id}/edit`, `/snippets/export`, `/snippets/tmux` | Snippets, export, tmux preview  |
| POST   | `/snippets`, `/snippets/{id}`, `/snippets/{id}/delete`, `/snippets/import`, `/snippets/import/apply` | Snippet actions |
| GET    | `/audit?q=`                                                  | Audit log                                       |
| GET    | `/settings`, `/settings/backup`                              | Settings, encrypted vault download              |
| POST   | `/settings/users/allow`, `/settings/users/revoke`, `/settings/requests/dismiss`, `/settings/sessions/revoke`, `/settings/ssh`, `/settings/updates`, `/settings/passphrase`, `/vault/seal` | Settings actions |

The terminal WebSocket carries terminal bytes as binary frames, text frames are JSON control messages:
`{"type":"resize","cols":120,"rows":40}` from the browser, `{"type":"error","message":"..."}` from the server.

## Verification status

Verified:

- 226 tests, 32 of them against real sshd. They cover every route against the guards, the vault and its key file,
  OIDC including a flood of logins and a slow provider, access control including revokes during a request, uploads
  (broken transfers, planted temporary files, kept modes), a hostile SFTP server, the `authorized_keys` lines and the
  command that installs them in real shells, `from=` lists against OpenSSH, snippets and their import, metrics, the
  update check and the log format.
- Every page in a browser at desktop and phone width, light and dark.
- `authorized_keys` lines and the `Match` block against OpenSSH 9.2 and 10.2.
- Login against a real Pocket ID instance.
- In production in an Incus LXC behind Zoraxy, with `DynamicUser=yes`: idle terminals stay usable, the sandboxing
  works, `memory.swap.max` is `0`.
- The fat JAR with `-Xmx256m` through a whole session against the mock provider and two OpenSSH servers.
- Argon2id with 64 MiB and 3 passes takes 100 to 200 ms on a fast desktop. The concept aims for 0.5 to 1 s, raise
  `iterations` in [crypto/Argon2Kdf.kt](../src/main/kotlin/bayern/kickner/dirl/crypto/Argon2Kdf.kt) on fast targets.

Still open:

- LXCFS values in `/proc/meminfo` of a monitored Incus container.
- The Docker image only in CI, not yet on a real host with a real provider.
- The unit's `LoadCredential` and `MemorySwapMax=0` only with `systemd-analyze verify`, not yet on a running system.

[Back to the README](../README.md)
