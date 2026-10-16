# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

Dirl, a self-hosted web SSH client (Kotlin, Ktor CIO, sshj, xterm.js) that replaces Termix. Everything is managed in
the browser, the config file only holds what is needed before login. The German concept
[termix-eigenbau-konzept.md](termix-eigenbau-konzept.md) is the source of the design decisions, [README.md](README.md)
documents behaviour, configuration, endpoints, deployment and the verification status in English. Read both before
changing security-relevant code (vault, auth, access control, web guards, host key handling).

## Commands

Use the Gradle wrapper.

```bash
./gradlew build shadowJar
```

```bash
./gradlew devRun
```

`devRun` starts Dirl on `http://localhost:18080` with the mock OIDC provider from the test sources (port 18081),
data in `build/dev`. `.claude/launch.json` has it as `dirl-dev` for the browser preview.

```bash
DIRL_SSHD_ROOT=/path/to/unpacked/openssh-server ./gradlew test
```

The SSH integration tests need an `sshd` binary (system `/usr/sbin/sshd` or `DIRL_SSHD_ROOT`) and are skipped without
one, see README.md "Development". JUnit silently skips test methods that do not return `Unit`, so write
`fun x(): Unit = runBlocking { ... }` and `fun x(): Unit = testApplication { ... }`.

Dependencies are locked (`gradle.lockfile`). After a version change run `./gradlew dependencies --write-locks`, see
README.md "Updating dependencies". There is deliberately no `verification-metadata.xml`, it broke the IntelliJ sync.

The fat JAR is `build/libs/dirl.jar`. After changing dependencies or the Shadow config, check that
`unzip -p build/libs/dirl.jar META-INF/services/org.slf4j.spi.SLF4JServiceProvider` prints
`bayern.kickner.klogger.slf4j.KloggerServiceProvider`.

## Toolchain

- Kotlin 2.4.21, Gradle 9.8.1, Shadow 9.6.1. Toolchain Amazon Corretto 25, bytecode and API level 21
  (`-Xjdk-release=21`) because the target runs Debian 13's OpenJDK 21.
- `bayern.kickner` libraries from `https://maven.kickner.bayern/releases`: Klogger 0.5.0 (with SLF4J provider),
  KotNexLib 4.4.1.
- BouncyCastle is pinned to 1.86 through its BOM, sshj and KotNexLib pull older versions.
- `BuildConfig` (`VERSION`, `BUILD_TIME`) is generated into `build/` on every build, never commit it.
- xterm.js and addon-fit are vendored under `src/main/resources/static/vendor/xterm` with `SHA256SUMS`. Update them
  from the npm tarballs and verify the registry integrity value.

## Architecture

`Main.kt` wires everything into one `web.Dirl` object that all routes receive (`createDirl` takes a `clock` for
tests). Packages: `config`, `crypto`, `vault`, `audit`, `auth`, `ssh`, `web`, see README.md "Development".

Security invariants, keep them when adding code:

- New routes are protected by default. `web/Security.kt` (`installGuards`) requires a session of an allowed user for
  everything outside `/login`, `/auth/`, `/static/`, `/healthz`, an unlocked vault for everything outside `/unlock`,
  `/setup`, `/setup/restore`, `/logout`, and a matching `Origin` for every non-GET request and every WebSocket
  upgrade. Keep `Referrer-Policy: same-origin`, `no-referrer` makes browsers send `Origin: null` on form posts.
- Never `unsafe {}` or raw HTML in kotlinx.html, never `innerHTML` in JavaScript, no inline scripts (CSP). Success
  messages after a redirect go through the fixed `?done=` keys in `web/Layout.kt`, never through text in the URL.
- Always create the GCM nonce yourself (`crypto.Aead.seal`), never use KotNexLib's default nonce argument.
- Never log terminal data, passphrases, keys or tokens. Audit actions go through `AuditLog.record`.
- Host keys are pinned per host ID and a mismatch is never accepted automatically.
- Connection attempts go through `ConnectionManager.connection`, which enforces backoff and the stop after three
  authentication failures.
- Users, hosts, keys, snippets and settings live in the vault (`VaultContent`), not in the config file. Anything new
  that users configure belongs there and gets a UI.

## Code style

Same conventions as [DemoAiProject](https://github.com/nexus421/DemoAiProject): `.not()` instead of `!`, small `if`s
without braces, `runCatching` by default, expected outcomes as `ResultOf2` and sealed types instead of exceptions,
injectable `clock`, `staticLog` with `private const val TAG` in top-level code and receiver helpers in classes,
timestamps through `timestampFormat` in `Common.kt`, KDoc on every public declaration. No em dashes, no en dashes and
no semicolons in prose (README, KDoc, comments, UI strings). Code, KDoc, comments and README are English, the concept
stays German.

UI: page building blocks (`page`, `pageHeader`, `card`, `postButton`, `copyBlock`, form fields) are in
`web/Layout.kt`, styles in `static/app.css` (light and dark through CSS variables, tables stack on phones). Check new
pages in the browser at desktop and phone width.

Deliberate deviations from DemoAiProject, decided in the concept: Shadow instead of the Ktor Gradle plugin for the
fat JAR, Klogger's SLF4J provider instead of `slf4j-simple`, server-rendered kotlinx.html instead of Compose.

Keep README.md and KDoc in sync with the code in the same change.
