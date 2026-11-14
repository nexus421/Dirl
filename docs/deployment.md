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
Docker. A proxy in a container joins Dirl's Docker network instead. Keep the plain HTTP hop from the proxy to Dirl on
one machine, see [Network between the proxy and Dirl](#network-between-the-proxy-and-dirl).

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
- No connection to GitHub: turn the update check off under Settings, see [Update check](security.md#update-check).

## Backup and starting over

- Backup: the encrypted download under Settings, or `tar czf dirl-$(date +%F).tgz -C /var/lib/dirl .` (with Docker the
  `data` directory). Both are useless without the passphrase, and in key file mode without the key file. Either of the
  two opens them. Keep the key file out of that backup.
- Starting over, after a forgotten passphrase or a restored file that does not belong to its passphrase: stop Dirl and
  delete `vault.json`, `vault.json.*` and `access.json` in the data directory. The next login creates a new vault, the
  old data is lost.

## Details

### The systemd unit

[deploy/dirl.service](../deploy/dirl.service) runs Dirl with `-Xmx256m`, no core dumps, no swap and sandboxing.

- `DynamicUser=yes`: a user that only exists while Dirl runs. Its data directory `/var/lib/dirl` (`0700`) is created
  by systemd and lives in `/var/lib/private/dirl`, which no other user can enter.
- `LoadCredential`: the config stays root's file, Dirl gets a read-only copy in unswappable memory under
  `/run/credentials/dirl.service/`. The key file can go the same way.
- `MemorySwapMax=0`: the decrypted keys never reach the disk. Out of memory the kernel ends Dirl instead, it restarts
  sealed in passphrase mode.
- An install with the earlier unit (a `dirl` user created by hand) keeps working.
- In an unprivileged container the sandboxing can fail with `status=226/NAMESPACE`: enable `security.nesting` or drop
  the failing options.
- About 0.3 MiB heap per connected host, so 256 MiB are enough for a few hundred hosts.

### The Docker image

- `ghcr.io/nexus421/dirl` for amd64 and arm64, tagged with the version and `latest`. Same `dirl.jar` on Corretto 21,
  UID 10001, config `/etc/dirl/config.json`, data `/var/lib/dirl`.
- The compose file restricts the container like the unit: read-only file system except `data`, no capabilities, no
  core dumps, 512 MiB without swap.
- Base image updates arrive with the next Dirl release, a published image is never rebuilt.
- A rejected config exits with code 78 and Compose restarts it over and over, `docker compose logs` shows why.

### Network between the proxy and Dirl

From the proxy to Dirl the traffic is plain HTTP with session cookies, the passphrase and everything typed into
terminals. Keep that hop on one machine: let Dirl listen on the address the proxy uses (for example the container's
address on the Incus bridge, not `0.0.0.0`) and allow the port only from the proxy. A proxy on another machine needs a
tunnel (WireGuard, SSH). The 20 second WebSocket ping keeps idle terminals open through the proxy.

### Outgoing connections and logs

Dirl connects to the identity provider, the SSH hosts and `api.github.com` (update check). Logs go to journald and
`dataDir/logs/app.log` (5 MiB, rotated), see [Logs](security.md#logs).

[Back to the README](../README.md)
