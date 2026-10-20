# Termix-Eigenbau in Kotlin/Ktor (Konzept)

Stand: 15.10.2026 · Status: Konzept, noch nichts gebaut · Arbeitstitel offen

Kennzeichnung: **[geprüft]** = am Quellcode, an der Doku oder per Test in einer Sandbox belegt. **[Spike]** = erst im Spike prüfbar. Alle Kotlin-Snippets sind **ungetestet**, weil Maven Central aus der Prüfumgebung gesperrt war und kein JVM-Build lief.

## Rahmen (Entscheidungen)
- Nur für mich. Wen ich in Pocket ID freigebe, kommt in **denselben** Account (keine Nutzertrennung, ggf. V2).
- Ein **Fat-JAR**, `java -jar`, kein Docker. Läuft im Incus-LXC hinter Zoraxy.
- Kotlin, wo sinnvoll. Nicht-JVM nur, wo nötig (xterm.js).
- **Klogger** ist Pflicht, **Ktor mit CIO**, **KotNexLib** für Krypto.
- Nur aktuell gepflegte Bibliotheken. Termix-Code wird nicht angeschaut oder portiert, das Datenmodell entsteht neu passend zum kleinen Umfang.

## Umfang
| Drin | Raus |
|---|---|
| Hosts (flache Tags), Jump-Host (max. 2 Hops) | Plugin-System, Desktop/Mobile-Apps, Sync |
| Terminal (xterm.js) | RDP/VNC, Docker, Tunnels, Automations, KI, tmux-Integration |
| SFTP-Dateimanager | Rollen/Sharing, mehrere Accounts |
| SSH-Keys erzeugen/importieren, Public Key anzeigen | LDAP/GitHub/Google, lokale Logins |
| Snippets | Passkey/TOTP im Tool (macht Pocket ID) |
| Server-Status: erreichbar, CPU, RAM, Swap, Platte | Alarme (später ggf. Webhook an KNot) |
| Host-Key-Pinning, Audit-Log | Datenbank-Server, i18n, Themes, Telemetrie |

## Stack (Versionen Stand 15.10.2026, aus Git-Tags bzw. npm) [geprüft]
| Baustein | Version | Anmerkung |
|---|---|---|
| Kotlin | 2.4.21 | Kompatibilität mit Ktor 3.6 im Spike bestätigen |
| Ktor (Server **CIO**, WebSockets) | 3.6.0 (16.09.2026) | CIO hat **kein TLS** (kein TLS-Code in `ktor-server-cio`), TLS macht Zoraxy |
| sshj | 0.41.2 (21.09.2026) | aktiv gepflegt; Terrapin-Schutz (strict kex) im Code |
| BouncyCastle | 1.86 (11.09.2026) | sshj zieht 1.84, KotNexLib 1.85.2 → **1.86 explizit pinnen** |
| kotlinx.html | 0.12.0 | serverseitiges HTML in Kotlin |
| kotlinx.serialization | aktuell | JSON |
| Klogger | 0.5.0 | SLF4J-2.x-Provider eingebaut (`META-INF/services/…SLF4JServiceProvider`) |
| KotNexLib | 4.4.1 | `AES.GCM`, Argon2 (über BC) |
| xterm.js + addon-fit | 6.0.0 / 0.11.0 | MIT, ~480 KB, im JAR mitgeliefert |
| Shadow (Gradle) | 9.6.1 | Fat-JAR |
| JDK | 21 LTS | aus den Debian-Paketen (Paketstand im Spike prüfen) |
| Ausweichoption SSH | Apache MINA SSHD 2.20.0 | hat ML-KEM, aber komplexere API |

Gezielt nicht genutzt: JWT-Bibliothek (nicht nötig, siehe OIDC), Datenbank, Frontend-Framework.

## Architektur
- Ein Prozess, Ktor CIO auf `127.0.0.1:<port>` bzw. intern im LXC. Zoraxy terminiert TLS.
- **Verbindungs-Manager:** pro Host genau eine langlebige SSH-Verbindung. Terminal, SFTP und Metriken laufen als Channels darauf.
  - Zustände: verbunden, verbindet, Auth fehlgeschlagen, gestoppt.
  - Reconnect mit Backoff von 30 s bis 15 min. **Stopp nach 3 Auth-Fehlern**, damit fail2ban/K4Ban die Termix-IP nicht bannt.
  - Keepalive: `KeepAliveProvider.KEEP_ALIVE` (erkennt tote Verbindungen). Der sshj-Default `HEARTBEAT` sendet nur Pakete und erkennt nichts. [geprüft im sshj-Code]
- Warum keine TCP-Pings wie Termix: Ein nackter TCP-Check erzeugt im sshd-Log `kex_exchange_identification: … Connection reset`. Darauf kann fail2ban im ddos/aggressive-Modus anspringen. [geprüft, Logzeile per Test erzeugt]
- **WebSocket-Protokoll:** Binary-Frames = Terminaldaten, Text-Frames = JSON-Steuerung (`resize`).

```kotlin
install(WebSockets) {
    pingPeriod = 20.seconds        // Default: aus. Hält Zoraxy-Idle-Timeouts offen
    timeout = 15.seconds
    maxFrameSize = 1L * 1024 * 1024 // Default ist Long.MAX_VALUE → Speicher-DoS
}
```

## Dateien
```
/etc/termix/config.json      # unverschlüsselt, 0400: Port, publicUrl, OIDC (issuer, clientId), unlockMode
/var/lib/termix/vault.json   # verschlüsselt: Hosts, Keys, Host-Key-Pins, Snippets
/var/lib/termix/audit.jsonl  # Append-only, eine Zeile pro Aktion (OIDC-sub, Name, Aktion, Host, Zeit)
```
- **JSON statt SQLite**: Für ~20 Hosts gibt es keine Abfragen und nur einen Schreiber. Der ganze Store wird ohnehin als ein Blob verschlüsselt. Damit entfällt die native JNI-Bibliothek von sqlite-jdbc, die beim Start nach `/tmp` entpackt wird. SQLite erst, wenn Metrik-Verläufe dauerhaft gespeichert werden sollen.
- Schreiben atomar: Temp-Datei, `fsync`, `rename`. Die letzten 3 Versionen behalten.
- Metrik-Verläufe nur im RAM (Ringpuffer, 24 h × 1/min ≈ 1440 Punkte pro Host).

## Verschlüsselung und Entsperren

### Aufbau
- **DEK**: zufälliger 256-Bit-Datenschlüssel. Er verschlüsselt den **gesamten** Vault-Inhalt mit AES-256-GCM, bei jedem Speichern mit neuer Nonce.
- GCM schützt auch die Integrität. Gepinnte Host-Keys im Vault kann niemand mit Schreibzugriff unbemerkt austauschen (MITM-Vorbereitung).
- Der DEK liegt nur verschlüsselt („eingewickelt“) im Vault. Der **KEK** dafür kommt aus der Passphrase (Argon2id). Passphrase ändern = DEK neu einwickeln, Daten bleiben.
- 2³² Verschlüsselungen pro Key mit zufälliger 96-Bit-Nonce (NIST-Grenze) erreicht ein Vault, der bei jeder Änderung neu geschrieben wird, praktisch nie.

```json
{
  "format": 1,
  "kdf": { "alg": "argon2id", "memKiB": 65536, "iterations": 3, "parallelism": 1, "salt": "<b64>" },
  "wrappedDek": { "passphrase": { "nonce": "<b64>", "ct": "<b64>" },
                  "keyfile":    { "nonce": "<b64>", "ct": "<b64>" } },
  "data": { "nonce": "<b64>", "ct": "<b64>" }
}
```
`keyfile` existiert nur, wenn der Keyfile-Modus aktiv ist.

### KotNexLib richtig benutzen [geprüft im Code von `kotnexlib/crypto/AES.kt`]
Positiv: AES/GCM/NoPadding, 128-Bit-Tag, 12-Byte-Zufallsnonce, 256-Bit-Keys, PBKDF2 mit Default 600.000 (entspricht OWASP).

Falle: `AES.GCM.encrypt(data, key, nonce = generateNonce())` gibt **nur den Chiffretext** zurück. Mit der Default-Nonce ist der Text **nicht mehr entschlüsselbar**. Die Nonce immer selbst erzeugen und mitspeichern:

```kotlin
val dek = AES.Common.generateAESKey()                    // einmalig beim Setup
val nonce = AES.Common.generateNonce()                    // 12 Byte, bei JEDEM Speichern neu
val ct = AES.GCM.encrypt(plainBytes, dek, nonce).getOrThrow()          // compress = false lassen
val plain = AES.GCM.decryptToByteArray(ct, dek, nonce).getOrThrow()    // ByteArray, nicht String
```
Weitere Regeln:
- `compress = false` lassen. Kompression vor Verschlüsselung verrät Längeninformationen.
- `generateSecureRandom` nutzt `SecureRandom.getInstanceStrong()` (unter Linux `/dev/random`). Ab Kernel 5.6 blockiert das nach dem Init nicht mehr, auf Debian 13 also unkritisch.

Wunschliste für KotNexLib, nicht blockierend:
1. `encrypt` liefert `nonce || ct` zusammen zurück (nimmt die Falle weg).
2. Optionaler `aad`-Parameter.
3. `Argon2.deriveKey(passphrase, salt, mKiB, t, p): ByteArray`.

Bis dahin direkt mit BC, das ohnehin im Classpath ist:
```kotlin
val gen = Argon2BytesGenerator().apply {
    init(Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withMemoryAsKB(65536).withIterations(3).withParallelism(1)
        .withSalt(salt).build())
}
val kek = ByteArray(32).also { gen.generateBytes(passphrase /* CharArray */, it) }
```
Die Parameter liegen deutlich über dem OWASP-Minimum (19 MiB, t=2). Die Dauer misst der Spike, Ziel 0,5–1 s. Die 64 MiB werden kurz im Heap belegt, darauf ist `-Xmx` ausgelegt.

### Entsperren nach Neustart
**Default: Passphrase im Browser.**
1. Der Prozess startet versiegelt. Erreichbar sind nur `/login`, der OIDC-Callback und `/unlock`.
2. Login per Pocket ID, dann die Passphrase eingeben (aus dem Passwortmanager). Daraus entsteht per Argon2id der KEK, der den DEK entschlüsselt. Der DEK liegt danach nur im RAM. Passphrase und KEK werden sofort überschrieben (ByteArray/CharArray, best effort).
3. Bei falscher Eingabe schlägt der GCM-Tag fehl. Nach 5 Fehlversuchen ist 15 min gesperrt, und es gibt einen Audit-Eintrag.

Erst-Setup: Passphrase festlegen, mindestens 5 Diceware-Wörter oder 20 Zeichen.

Solange versiegelt, gibt es keine SSH-Verbindungen und keine Metriken. Nach einem Absturz (`Restart=on-failure`) ist der Prozess wieder versiegelt.

**Alternative `unlockMode = "keyfile"`**: 32 Zufallsbytes in `/etc/termix/kek` (0400, Besitzer `termix`) als zweiter KEK, startet ohne Eingabe. systemd-creds bringt ohne TPM nichts zusätzlich und entfällt.

| Szenario | Passphrase | Keyfile |
|---|---|---|
| Hetzner-Backup oder Incus-Snapshot des ganzen Systems geleakt | geschützt | **nicht** geschützt |
| tar-Backup nur von `/var/lib/termix` geleakt | geschützt | geschützt, solange `/etc/termix` nicht im Backup liegt |
| Root oder RCE im laufenden Prozess | nicht geschützt | nicht geschützt |
| Ungeplanter Neustart | einmal entsperren | automatisch |

**Notzugang bleibt immer erhalten**, das Tool ist nie der einzige Weg: SSH-Keys im Passwortmanager plus Hetzner-Firewall kurz für die eigene IP öffnen, ggf. Hetzner-Konsole.

### Schutz gegen einen geklauten Tool-Key [geprüft mit OpenSSH 9.6 in einer Sandbox]
Im laufenden Prozess liegen Keys immer im Klartext im RAM. Wichtiger als die Ablage-Verschlüsselung ist deshalb, was ein geklauter Key anrichten kann.

Normale Zielserver:
```
restrict,pty,from="<Termix-IP>" ssh-ed25519 AAAA… termix
```
Getestet: Befehl ausführen ✔, PTY ✔, SFTP-Upload ✔. Port-Forwarding wird abgelehnt, andere Quell-IP wird abgelehnt. Agent- und X11-Forwarding schaltet `restrict` laut `man sshd` ebenfalls ab (nicht separat getestet).

Reiner Jump-Host:
```
restrict,port-forwarding,permitopen="<Ziel-IP>:22",command="/bin/false",from="<Termix-IP>" ssh-ed25519 AAAA… termix
```
Getestet: Forwarding zum erlaubten Ziel ✔, anderes Ziel abgelehnt, PTY abgelehnt, Befehle laufen ins Leere.

Ist der Jump-Host selbst auch Terminal-Ziel, `command="/bin/false"` weglassen und `pty` ergänzen.

Weitere Regeln:
- Ein **eigener** Key nur für das Tool, nicht der persönliche.
- Der Key wird im Tool erzeugt. Die UI zeigt die fertige `authorized_keys`-Zeile zum Kopieren.
- Auf dem Jump-Host muss `AllowTcpForwarding` an sein (Default `yes`).

## Login (OIDC mit Pocket ID 2.18) [geprüft im Pocket-ID-Code bzw. in der Doku]
- Authorization Code Flow mit **PKCE S256**. Pocket ID kennt pro Client `PkceEnabled` und `IsPublic`.
- `state`, `nonce` und `code_verifier` in einem kurzlebigen Cookie mit `SameSite=Lax` (muss den Rücksprung von Pocket ID überleben).
- ID-Token-Prüfung ohne JWT-Bibliothek. Laut OIDC Core §3.1.3.7 darf bei direktem Empfang vom Token-Endpoint über TLS die TLS-Prüfung die Signaturprüfung ersetzen. Weiterhin prüfen: `iss` exakt, `aud` = Client-ID, `exp`, `nonce`.
- HTTP-Aufrufe mit `java.net.http.HttpClient` (JDK).
- **Zugriff in Pocket ID steuern**: im Client unter Access „Selected user groups“ eine Gruppe `termix` wählen. Nicht-Mitglieder bekommen „You are not allowed to access this service“. Zusätzlich im Tool eine `sub`-Allowlist in `config.json` (doppelt hält besser).
- **Optional Re-Auth erzwingen**: Client-Option „Requires Re-Authentication“ oder `prompt=login`. Dann ist bei jedem Login in das Tool ein frischer Passkey nötig, auch bei bestehender Pocket-ID-Sitzung. Empfehlung: an.
- Session: `__Host-session`-Cookie (`Secure; HttpOnly; SameSite=Strict; Path=/`), 256-Bit-Zufallstoken, Map im RAM, Idle-Timeout 60 min (am 20.10.2026 von 30 min erhöht, ein offenes Terminal neben anderer Arbeit lief sonst zu oft ab), maximal 12 h.
- Login-Button als normaler Link, kein Formular (sonst blockt `form-action` den Redirect).

### Web-Härtung
CSP:
```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self';
font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```
- `style-src 'unsafe-inline'` ist **nötig**: xterm.js 6.0 legt `<style>`-Elemente für Theme und Zellmaße an (4× `createElement("style")` im Bundle) und unterstützt keine Nonce. [geprüft im npm-Paket]
- `script-src` bleibt streng: kein `eval`, kein Inline-JS.
- Kein `innerHTML`, das Links-Addon weglassen. Die Terminalausgabe eines kompromittierten Servers ist Angreifer-Input.
- WebSocket: Ktor prüft den Origin nicht selbst → beim Upgrade `Origin` == `publicUrl` prüfen, sonst 403.
- Weitere Header: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.

## SSH im Detail
- **Keys erzeugen mit BC** und im OpenSSH-Format im Vault ablegen, genauso wie importierte Keys. Damit gibt es nur einen Ladeweg in sshj, und die Keys sind exportierbar. [API in BC 1.86 geprüft: `OpenSSHPrivateKeyUtil.encodePrivateKey` unterstützt Ed25519]
```kotlin
val kp = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
val blob = OpenSSHPrivateKeyUtil.encodePrivateKey(kp.private)
val pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
    Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(blob) +
    "\n-----END OPENSSH PRIVATE KEY-----\n"
val pubLine = "ssh-ed25519 " + Base64.getEncoder().encodeToString(OpenSSHPublicKeyUtil.encodePublicKey(kp.public)) + " termix"
// Laden: ssh.authPublickey(user, ssh.loadKeys(pem, null, null))
```
- **Host-Key-Pinning (TOFU)**: Beim ersten Verbinden Fingerprint anzeigen und bestätigen, dann im Vault speichern. Bei Änderung hart blockieren, nie stillschweigend akzeptieren.
- **Jump-Host**: `jump.newDirectConnection(ziel, 22)` → `client.connectVia(tunnel)`. Eigener Host-Key-Check pro Hop, Zyklus-Erkennung, maximal 2 Hops, Referenzzählung auf die Jump-Verbindung. [`connectVia(DirectConnection)` im sshj-Code vorhanden]
- **Terminal**: `allocatePTY("xterm-256color", …)`, Resize über `Shell.changeWindowDimensions(cols, rows, w, h)` [vorhanden]. Keine tmux-Integration mehr (entfernt am 20.10.2026): Der Sitzungsname `dirl-<host>` hatte keine Nutzerkennung, zwei Nutzer landeten in derselben Shell. Wer tmux will, startet es selbst im Terminal.
- **SFTP**: Up- und Download als gestreamte Bytes, ohne Encoding-Raten. Speichern über Temp-Datei und Rename. Texteditor nur bis 1 MiB.
- **Kryptographie der Verbindung**: sshj kann **kein ML-KEM/sntrup** (nur curve25519 u. a.). OpenSSH 10.0 auf Debian 13 bietet curve25519 weiter an, das funktioniert also. Die Verbindungen sind aber nicht post-quanten-sicher. Für interne Hops akzeptiert. Wäre PQ Pflicht, müsste MINA SSHD statt sshj her.

### Metriken [Befehl geprüft]
Alle 60 s ein `exec`-Channel, der zugleich als Lebenszeichen dient:
```bash
LC_ALL=C sh -c 'cat /proc/uptime /proc/loadavg; head -n1 /proc/stat; grep -E "^(MemTotal|MemAvailable|SwapTotal|SwapFree):" /proc/meminfo; timeout 5 df -PlkT -x tmpfs -x devtmpfs -x squashfs -x overlay'
```
- CPU als Delta zweier `/proc/stat`-Zeilen: `busy = total − idle − iowait`. RAM = `MemTotal − MemAvailable`.
- `-l` lässt Netzwerk- und FUSE-Mounts weg, `timeout 5` verhindert Hänger bei toten Mounts.
- LXC-Container zeigen in `/proc/meminfo` nur mit LXCFS die Container-Werte [Spike].

## Frontend
- **Weg A**: Seiten serverseitig mit kotlinx.html (Kotlin), dazu ~300 Zeilen Vanilla-JS für Terminal, Upload und Fortschritt. xterm.js liegt als statische Datei mit Prüfsumme im JAR.
- Handy: Tastenleiste für Ctrl, Esc, Tab und Pfeile über dem Terminal.
- **Compose für Web nur als Experiment außerhalb des kritischen Pfads**: Die Web-Variante ist seit 1.9 (Sept. 2025) Beta, in 1.12 gibt es keinen Hinweis auf Stable. Compose rendert in ein Canvas, xterm.js ist DOM, Copy und Paste, Handy-Tastatur und Upload laufen über Interop, das Bundle hat mehrere MB. Wenn, dann zum Beispiel die Host-Übersicht unter `/x/`. Login, Unlock, Terminal und Dateien bleiben Weg A.

## Build und Betrieb

### Fat-JAR [Shadow 9.6.1 im Quellcode geprüft]
```kotlin
tasks.shadowJar {
    archiveFileName.set("termix.jar")
    // Shadow-Default EXCLUDE verwirft doppelte Service-Dateien VOR dem Merge → INCLUDE + gezielt EXCLUDE
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    mergeServiceFiles()
    filesNotMatching("META-INF/services/**") { duplicatesStrategy = DuplicatesStrategy.EXCLUDE }
    manifest { attributes("Main-Class" to "app.MainKt") }
}
```
- Signaturdateien (`*.SF`, `*.DSA`, `*.RSA`) schließt Shadow **schon standardmäßig** aus. BouncyCastle läuft auf OpenJDK unsigniert als Provider.
- Nach dem Build prüfen:
```bash
unzip -p build/libs/termix.jar META-INF/services/org.slf4j.spi.SLF4JServiceProvider   # erwartet: bayern.kickner.klogger.slf4j.KloggerServiceProvider
```

### Logging
```kotlin
KLogger.configure {
    logToFile(File("/var/lib/termix/logs/app.log"), maxFileSize = 5L * 1024 * 1024)
    slf4jBridge { minLevel = KLogger.Level.INFO
                  level("net.schmizz", KLogger.Level.WARN); level("com.hierynomus", KLogger.Level.WARN) }
}
```
Nie Terminaldaten, Passphrasen oder Keys loggen.

### systemd-Unit (im LXC)
```ini
[Unit]
Description=Web-SSH (Eigenbau)
After=network-online.target
Wants=network-online.target

[Service]
User=termix
WorkingDirectory=/var/lib/termix
ExecStart=/usr/bin/java -Xmx256m -XX:+ExitOnOutOfMemoryError -jar /opt/termix/termix.jar
Restart=on-failure
UMask=0077
LimitCORE=0
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/termix

[Install]
WantedBy=multi-user.target
```
[Spike]: Sandboxing-Optionen können im unprivilegierten LXC mit `status=226/NAMESPACE` scheitern. Dann `incus config set <ct> security.nesting true` oder die betroffenen Optionen streichen.

### Incus
```bash
incus config set <ct> limits.memory 512MiB
incus config set <ct> limits.memory.swap false            # Keys landen nicht im Swap
cat /sys/fs/cgroup/lxc.payload.<ct>/memory.swap.max        # auf dem Host, erwartet: 0 [Spike]
```

### Backup
`tar czf termix-$(date +%F).tgz -C /var/lib/termix .` reicht, der Vault ist verschlüsselt. `/etc/termix/kek` (nur Keyfile-Modus) **nicht** mit in dasselbe Backup legen.

## Plan
**Phase 0, Spike (1 Tag)**
1. Gradle-Projekt mit allen Abhängigkeiten aus der Stack-Tabelle, Fat-JAR bauen, Service-Datei per `unzip -p` prüfen, Start mit Klogger-Ausgabe.
2. Ktor-CIO-WebSocket ↔ sshj ↔ xterm.js: Resize, UTF-8, vim, htop, `cat` einer großen Datei.
3. 10 min Idle hinter Zoraxy: Bleibt die Verbindung offen?
4. Jump-Host über `connectVia`, mit den `authorized_keys`-Zeilen von oben.
5. BC-erzeugter Ed25519-Key per `loadKeys(pem)` gegen OpenSSH 10.0 (Debian 13).
6. Argon2id-Dauer mit 64 MiB / t=3 messen.
7. Pocket ID: PKCE, Gruppen-Beschränkung, `prompt=login`.
8. Incus: LXCFS-Werte im Container, `memory.swap.max`, systemd-Sandboxing.

**Phase 1, Fundament**: Config, Vault (Setup, Unlock, Passphrase ändern, atomares Schreiben), OIDC, Session, CSP/Origin, Audit-Log.

**Phase 2, SSH-Kern**: Hosts, Keys (erzeugen/importieren, `authorized_keys`-Zeile anzeigen), Host-Key-Pinning, Verbindungs-Manager mit Backoff/Stopp, Jump-Host, Terminal.

**Phase 3, Dateien, Snippets, Status**: SFTP-UI, Snippets, Metrik-Poller, Host-Übersicht.

**Phase 4, Härtung und Umstieg**: Tests gegen mehrere OpenSSH-Versionen, langsames MOTD, fremde Shells. systemd/Incus wie oben. Mehrere Wochen Parallelbetrieb mit Termix, dann Termix abschalten.

Dauerhaft:
- Gradle-Lockfile und Prüfsummen: `./gradlew --write-verification-metadata sha256 help`.
- Releases von sshj, Ktor, BC und xterm.js beobachten.

## Prüfprotokoll 15.10.2026 (Korrekturen gegenüber dem Chat)
| Punkt | Ergebnis |
|---|---|
| KotNexLib GCM, „immer Default-Nonce nutzen“ | **falsch**: Die Default-Nonce wird nicht zurückgegeben, der Text ist danach nicht entschlüsselbar. Nonce selbst erzeugen und speichern. |
| Shadow: Signaturdateien manuell ausschließen | unnötig, Shadow macht das per Default |
| Shadow: `mergeServiceFiles()` reicht | **falsch**: Mit dem Default `EXCLUDE` werden Duplikate vorher verworfen. `INCLUDE` + Ausnahme nötig. |
| „strikte CSP“ | `style-src` braucht `'unsafe-inline'` wegen xterm.js. `script-src` bleibt streng. |
| sshj und ML-KEM | sshj hat **kein** ML-KEM, Fallback auf curve25519 funktioniert |
| Versionen | Ktor ist 3.6.0 (nicht 3.4.x), sshj 0.41.2, BC 1.86 |
| Ktor WebSockets | `maxFrameSize` ist per Default unbegrenzt, Ping per Default aus → beides setzen |
| Pocket ID | PKCE, Public Client, Gruppen-Beschränkung pro Client und Re-Auth existieren |
| authorized_keys `restrict`/`permitopen`/`from` | per Test bestätigt, Jump-Host zusätzlich mit `command="/bin/false"` |
| Metrik-Befehl | funktioniert, ergänzt um `-l` und `timeout 5` |
| OIDC ohne Signaturprüfung | durch OIDC Core §3.1.3.7 gedeckt (direkter Token-Endpoint über TLS) |
| Debian 13 OpenSSH | 10.0p1 bestätigt |
| JVM-Build in der Prüfumgebung | **nicht möglich** (Maven Central gesperrt) → Snippets ungetestet, siehe Spike |

## Offene Punkte und Risiken
- sshj hat im Wesentlichen einen Hauptmaintainer. Ausweichplan ist MINA SSHD.
- Ktor CIO ist weniger verbreitet als Netty. Hinter Zoraxy und mit Frame-Limit vertretbar.
- Ich bin der einzige Reviewer für sicherheitskritischen Code → Umfang klein halten, Tests für Vault und OIDC.
- Handy-Bedienung des Dateimanagers ist der größte UI-Aufwand.
- Name des Projekts ist offen.
