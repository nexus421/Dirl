# Deployment

Take `dirl.jar` from a [GitHub release](https://github.com/nexus421/Dirl/releases) (check it with
`sha256sum -c dirl.jar.sha256`) or build it with `./gradlew build`. Inside an Incus LXC behind Zoraxy:

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

Then open `publicUrl` right away and create the vault, see [Quick start](../README.md#quick-start).

[deploy/dirl.service](../deploy/dirl.service) runs with `-Xmx256m` (Argon2 briefly needs 64 MiB), `UMask=0077`, no
core dumps and systemd sandboxing. In an unprivileged container the sandboxing options can fail with
`status=226/NAMESPACE`. Then enable `security.nesting` for the container or drop the failing options.

Each connected host costs about 0.3 MiB heap and two threads (measured with 100 hosts), so 256 MiB are enough for a
few hundred hosts. Raise `-Xmx` beyond that.

Keep the keys out of swap:

```bash
incus config set <container> limits.memory 512MiB
incus config set <container> limits.memory.swap false
```

Zoraxy: proxy `publicUrl` to Dirl's port with WebSocket support. The 20 second WebSocket ping keeps idle terminals
and the presence WebSocket of every open page open.

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

Backup: the encrypted download under Settings, or `tar czf dirl-$(date +%F).tgz -C /var/lib/dirl .`. Both are
useless without the passphrase.

Starting over: if the vault cannot be unlocked any more (forgotten passphrase, or a restored file that does not
belong to its passphrase), stop the service and delete `vault.json`, `vault.json.*` and `access.json` in the data
directory. The next login creates a new vault. Without the passphrase the old data is lost, that is the point.

Logs go to the console (journald) and to `dataDir/logs/app.log` (5 MiB, rotated). Libraries log through Klogger's
SLF4J provider, sshj only from WARN on.

[Back to the README](../README.md)
