# Deployment

Take `dirl.jar` from a [GitHub release](https://github.com/nexus421/Dirl/releases) (check it with
`sha256sum -c dirl.jar.sha256`) or build it with `./gradlew build` (then it is `build/libs/dirl.jar`). Write
`config.json` from [config.example.json](../config.example.json). Inside an Incus LXC behind Zoraxy:

```bash
useradd --system --home /var/lib/dirl --shell /usr/sbin/nologin dirl
install -d -o dirl -g dirl -m 0700 /var/lib/dirl
install -d -m 0755 /etc/dirl /opt/dirl
install -o dirl -g dirl -m 0400 config.json /etc/dirl/config.json
install -m 0644 dirl.jar /opt/dirl/dirl.jar
install -m 0644 deploy/dirl.service /etc/systemd/system/dirl.service
systemctl daemon-reload
systemctl enable --now dirl
```

Then open `publicUrl` right away and create the vault, see [Quick start](../README.md#quick-start).

[deploy/dirl.service](../deploy/dirl.service) runs with `-Xmx256m` (Argon2 briefly needs 64 MiB), `UMask=0077`, no
core dumps and systemd sandboxing. In an unprivileged container the sandboxing options can fail with
`status=226/NAMESPACE`. Then enable `security.nesting` for the container or drop the failing options.

Without the unit, for example with a plain `java -jar`, the data directory, `logs/` and `logs/app.log` follow the
shell's umask. With the common `022` other users on the machine can read the log, which holds host and user names but
no passphrases, keys or tokens. Start Dirl with `umask 077` there, then they get `0700` and `0600` like under the unit.

Each connected host costs about 0.3 MiB heap and two threads (measured with 100 hosts), so 256 MiB are enough for a
few hundred hosts. Raise `-Xmx` beyond that.

Keep the keys out of swap:

```bash
incus config set <container> limits.memory 512MiB
incus config set <container> limits.memory.swap false
```

Zoraxy: proxy `publicUrl` to Dirl's port with WebSocket support. The 20 second WebSocket ping keeps idle terminals
and the presence WebSocket of every open page open.

## Docker

Every release publishes the image `ghcr.io/nexus421/dirl` for amd64 and arm64, tagged with its version (e.g.
`0.6.0`) and, the newest one, as `latest`. It holds the same `dirl.jar` as the release on Corretto 21 and runs as UID
10001 with the paths of the systemd install: config `/etc/dirl/config.json`, data `/var/lib/dirl`.

Put [deploy/docker-compose.yml](../deploy/docker-compose.yml) and a `config.json` from
[config.example.json](../config.example.json) into one directory. In `config.json` set `publicUrl`, `oidc` and
`"host": "0.0.0.0"`, and leave `dataDir` at its default. Inside the container Dirl has to listen on all of its
interfaces, the compose file publishes the port only on `127.0.0.1` of the host. Then:

```bash
sudo install -d -o 10001 -g 10001 -m 0700 data
sudo chown 10001:10001 config.json
sudo chmod 0400 config.json
docker compose up -d
```

Open `publicUrl` and create the vault, see [Quick start](../README.md#quick-start).

The compose file restricts the container like [deploy/dirl.service](../deploy/dirl.service): read-only file system
except `data` and a `tmpfs` for `/tmp`, no capabilities, `no-new-privileges`, no core dumps and 512 MiB without swap.
For `"unlockMode": "keyfile"` create the key as in [Unlocking](configuration.md#unlocking), give it to UID 10001 with
`0400` and enable the `kek` line. It stays outside `data`, so it never ends up in the same backup.

Point the reverse proxy at `127.0.0.1:8080`. If the proxy runs in a container itself, put both into one Docker network
and drop the port mapping. [Network between Zoraxy and Dirl](#network-between-zoraxy-and-dirl) applies the same way.

Updating: `docker compose pull` and `docker compose up -d`. A version tag only changes when you change it in the
compose file. Security updates of the base image arrive with the next Dirl release, a published image is never
rebuilt.

A rejected config stops Dirl with exit code 78. Compose cannot exclude an exit code from `restart`, so the container
restarts over and over, `docker compose logs` shows the reason. Backups and starting over work as described below,
with `data` as the data directory.

CI builds the image on every push and runs a whole first start against it with exactly these restrictions, see
[Development](development.md#build-and-test).

## Network between Zoraxy and Dirl

TLS ends at Zoraxy. From there to Dirl the traffic is plain HTTP and carries session cookies, the vault passphrase
when unlocking and everything typed into terminals. Keep that hop off any physical network:

- Zoraxy on the same machine or in a container on the same host: Dirl listens on the container's address on the
  Incus bridge, the traffic never leaves the host. Set `host` in the config to that address, not `0.0.0.0`.
- Allow the port only from Zoraxy, e.g. with a firewall rule in the container or an Incus network ACL. Nobody else
  should be able to reach Dirl without going through Zoraxy.
- Zoraxy on another machine: do not proxy plain HTTP across the network. Put Dirl behind a reverse proxy on its own
  host instead, or tunnel the hop (WireGuard, an SSH tunnel).

Requests that bypass Zoraxy cannot log in anyway (the session cookies are `Secure` and every form post must carry
the `publicUrl` origin), but anyone on the path between the two could read along.

Outgoing, Dirl connects to the identity provider, the SSH hosts and, for the update check, `api.github.com` on port
443. The update check can be turned off under Settings, see [security](security.md#update-check).

Backup: the encrypted download under Settings, or `tar czf dirl-$(date +%F).tgz -C /var/lib/dirl .`. Both are
useless without the passphrase.

Starting over: if the vault cannot be unlocked any more (forgotten passphrase, or a restored file that does not
belong to its passphrase), stop the service and delete `vault.json`, `vault.json.*` and `access.json` in the data
directory. The next login creates a new vault. Without the passphrase the old data is lost, that is the point.

Logs go to the console (journald) and to `dataDir/logs/app.log` (5 MiB, rotated). Libraries log through Klogger's
SLF4J provider, sshj only from WARN on. Three sshj loggers are off, they report every normal disconnect and every new
host key as ERROR with a stack trace. Dirl logs the cases that matter itself.

[Back to the README](../README.md)
