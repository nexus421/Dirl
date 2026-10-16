# Deployment

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

Then open `publicUrl` right away and create the vault, see [Quick start](../README.md#quick-start).

[deploy/dirl.service](../deploy/dirl.service) runs with `-Xmx256m` (Argon2 briefly needs 64 MiB), `UMask=0077`, no
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

[Back to the README](../README.md)
