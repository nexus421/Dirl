# Deployment

Dirl runs as a service with systemd or as a Docker container, in both cases behind a reverse proxy that does TLS.

## Install with systemd

Take `dirl.jar` from a [GitHub release](https://github.com/nexus421/Dirl/releases) (check it with
`sha256sum -c dirl.jar.sha256`) or build it with `./gradlew build` (`build/libs/dirl.jar`). Take
[deploy/dirl.service](../deploy/dirl.service) and write `config.json` from [config.example.json](../config.example.json),
then as root:

```bash
install -Dm 0644 dirl.jar /opt/dirl/dirl.jar
install -Dm 0600 config.json /etc/dirl/config.json
install -Dm 0644 dirl.service /etc/systemd/system/dirl.service
systemctl enable --now dirl
```

Open `publicUrl` right away and create the vault, see [Quick start](../README.md#quick-start).

## Docker

Put [deploy/docker-compose.yml](../deploy/docker-compose.yml) and a `config.json` from
[config.example.json](../config.example.json) into one directory. In `config.json` set `publicUrl`, `oidc` and
`"host": "0.0.0.0"` and leave `dataDir` at its default. The compose file publishes the port only on `127.0.0.1` of
the host. Then:

```bash
sudo install -d -o 10001 -g 10001 -m 0700 data
sudo chown 10001:10001 config.json
sudo chmod 0400 config.json
docker compose up -d
```

Open `publicUrl` and create the vault. Update with `docker compose pull` and `docker compose up -d`.

## Reverse proxy

Proxy `publicUrl` to Dirl with WebSocket support: to `port` from the config under systemd, to `127.0.0.1:8080` with
Docker. If the proxy runs in a container too, put both into one Docker network and drop the port mapping. Keep the plain HTTP hop
from the proxy to Dirl on one machine, see [Network between the proxy and Dirl](#network-between-the-proxy-and-dirl).

## Optional hardening

- Keep the keys out of swap in an Incus container: `incus config set <container> limits.memory 512MiB` and
  `incus config set <container> limits.memory.swap false`. The systemd unit and the compose file do this already,
  see [The systemd unit](#the-systemd-unit).
- Let only the proxy reach Dirl: listen on the address the proxy uses, allow the port only from it, see
  [Network between the proxy and Dirl](#network-between-the-proxy-and-dirl).
- Key file mode for unattended restarts: [Unlocking](configuration.md#unlocking). With systemd enable the
  `LoadCredential=kek` line of the unit, with Docker give the key to UID 10001 with `0400` and enable the `kek` line of
  the compose file.
- Without the unit, for example a plain `java -jar`: start Dirl with `umask 077`. Otherwise data directory and log
  follow the shell's umask and other users on the machine can read the log (host and user names, no secrets).
- No outgoing connection to GitHub: turn the update check off under Settings, see [Update check](security.md#update-check).

## Backup and starting over

- Backup: the encrypted download under Settings, or `tar czf dirl-$(date +%F).tgz -C /var/lib/dirl .` (with Docker the
  `data` directory). Both are useless without the passphrase, and in key file mode without the key file. Either of the
  two opens them. Keep the key file out of that backup.
- Starting over, after a forgotten passphrase or a restored file that does not belong to its passphrase: stop Dirl and
  delete `vault.json`, `vault.json.*` and `access.json` in the data directory. The next login creates a new vault, the
  old data is lost.

## Details

### The systemd unit

[deploy/dirl.service](../deploy/dirl.service) runs with `-Xmx256m` (Argon2 briefly needs 64 MiB), `UMask=0077`, no
core dumps, no swap and systemd sandboxing.

- No user to create: `DynamicUser=yes` makes one that only exists while Dirl runs. Its data directory `/var/lib/dirl`
  is created by systemd with mode `0700` and lives behind it in `/var/lib/private/dirl`, which no other user can enter.
- The config stays root's own file (`0600`). `LoadCredential` hands Dirl a read-only copy in unswappable memory under
  `/run/credentials/dirl.service/`, only Dirl and root can read it. The key file goes the same way.
- An install with the earlier unit (a `dirl` user created by hand) keeps working, there is no need to switch.
- No swap (`MemorySwapMax=0`): the decrypted keys never reach the disk. The kernel cannot move Dirl out of memory
  either, on a machine that runs out of memory it ends Dirl, which restarts sealed in passphrase mode. An existing
  install gets the line by copying the unit again, `systemctl show dirl -p MemorySwapMax` shows it.
- In an unprivileged container the sandboxing options can fail with `status=226/NAMESPACE`. Enable
  `security.nesting` for the container or drop the failing options.
- Each connected host costs about 0.3 MiB heap and two threads (measured with 100 hosts), so 256 MiB are enough for a
  few hundred hosts. Raise `-Xmx` beyond that.

### The Docker image

- Every release publishes `ghcr.io/nexus421/dirl` for amd64 and arm64, tagged with its version (e.g. `0.6.0`) and the
  newest as `latest`. It holds the same `dirl.jar` on Corretto 21 and runs as UID 10001 with the paths of the systemd
  install: config `/etc/dirl/config.json`, data `/var/lib/dirl`.
- Inside the container Dirl listens on all of its interfaces (`0.0.0.0`), only the port mapping decides who reaches it.
- The compose file restricts the container like the systemd unit: read-only file system except `data` and a `tmpfs`
  for `/tmp`, no capabilities, `no-new-privileges`, no core dumps and 512 MiB without swap. The key file stays outside
  `data`, so it never ends up in the same backup.
- A version tag only changes when you change it in the compose file. Security updates of the base image arrive with
  the next Dirl release, a published image is never rebuilt.
- A rejected config stops Dirl with exit code 78. Compose cannot exclude an exit code from `restart`, so the container
  restarts over and over, `docker compose logs` shows the reason.
- CI builds the image on every push and runs a whole first start against it with exactly these restrictions, see
  [Development](development.md#build-and-test).

### Network between the proxy and Dirl

TLS ends at the proxy (for example Zoraxy). From there to Dirl the traffic is plain HTTP and carries session cookies,
the vault passphrase when unlocking and everything typed into terminals. Keep that hop off any physical network:

- Proxy on the same machine or in a container on the same host: Dirl listens on the container's address on the
  Incus bridge, the traffic never leaves the host. Set `host` in the config to that address, not `0.0.0.0`.
- Allow the port only from the proxy, e.g. with a firewall rule in the container or an Incus network ACL.
- Proxy on another machine: do not send plain HTTP across the network. Put Dirl behind a proxy on its own host, or
  tunnel the hop (WireGuard, an SSH tunnel).

Requests that bypass the proxy cannot log in anyway (the session cookies are `Secure` and every form post must carry
the `publicUrl` origin), but anyone on the path between the two could read along. The 20 second WebSocket ping keeps
idle terminals and the presence WebSocket of every open page open through the proxy.

### Outgoing connections

Dirl connects to the identity provider, the SSH hosts and, for the update check, `api.github.com` on port 443.

### Logs

Logs go to the console (journald) and to `dataDir/logs/app.log` (5 MiB, rotated). Libraries log through Klogger's
SLF4J provider, sshj only from WARN on. Three sshj loggers are off, they report every normal disconnect and every new
host key as ERROR with a stack trace. Dirl logs the cases that matter itself. Control characters in a message show as
escapes such as `\x1b` and further lines of a message are indented, see [security](security.md#logs).

[Back to the README](../README.md)
