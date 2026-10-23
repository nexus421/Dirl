# Configuration

## Command line

Arguments are `key=value` pairs and bare words.

| Argument        | Default                 | Meaning                      |
|-----------------|-------------------------|------------------------------|
| `config=<path>` | `/etc/dirl/config.json` | Config file                  |
| `check`         |                         | Validate the config and exit |

| Exit code | Meaning                                                                         |
|-----------|---------------------------------------------------------------------------------|
| `0`       | Success (only with `check`, the server runs until stopped)                      |
| `1`       | Unexpected failure                                                              |
| `78`      | Config rejected or port cannot be bound (`EX_CONFIG`). systemd does not restart |

## Config file

The config file only holds what is needed before anybody can log in: where to listen, how to reach the identity
provider and how the vault is unlocked. Everything else (users, hosts, keys, snippets, Dirl's source address,
passphrase) is managed in the UI and stored in the encrypted vault.

The file is read once at startup. Unknown keys are errors and all problems are reported at once. It holds no secret
except the OIDC client secret, so `0400` and owned by the service user.

| Field        | Type   | Default         | Description                                                                              |
|--------------|--------|-----------------|------------------------------------------------------------------------------------------|
| `host`       | string | `127.0.0.1`     | Bind address. TLS is done by the reverse proxy                                           |
| `port`       | int    | `8080`          | HTTP port                                                                                |
| `publicUrl`  | string | required        | URL in the browser, no trailing slash, lower case host, no default port (`:443`). OIDC redirect base and the only accepted `Origin` |
| `dataDir`    | string | `/var/lib/dirl` | Vault, backups, access list copy, audit log, logs                                        |
| `unlockMode` | string | `passphrase`    | `passphrase` or `keyfile`, see [Unlocking](#unlocking)                                   |
| `keyFile`    | string | `/etc/dirl/kek` | 32 random bytes, only read in `keyfile` mode                                             |
| `oidc`       | object | required        | See below                                                                                |
| `session`    | object | see below       | See below                                                                                |

`oidc`:

| Field             | Type     | Default                 | Description                                                                      |
|-------------------|----------|-------------------------|----------------------------------------------------------------------------------|
| `issuer`          | string   | required                | Issuer exactly as in the discovery document. `https` (or `http` on localhost)    |
| `clientId`        | string   | required                | Client ID in Pocket ID                                                           |
| `clientSecret`    | string   | required                | Secret of the confidential client, sent to the token endpoint with HTTP Basic    |
| `allowedSubjects` | string[] | `[]`                    | Break-glass list, always allowed. Only needed if nobody in the UI list can log in |
| `forceReauth`     | bool     | `true`                  | Sends `prompt=login`, so every login needs a fresh passkey                       |
| `scopes`          | string[] | `["openid", "profile"]` | Must contain `openid`                                                            |

`session`:

| Field                | Type | Default | Description                               |
|----------------------|------|---------|-------------------------------------------|
| `idleTimeoutMinutes` | int  | `60`    | Session expires after this much idle time |
| `maxAgeHours`        | int  | `12`    | Session expires this long after the login |

Pocket ID client setup: callback URL `<publicUrl>/auth/callback`, PKCE enabled, **not** a public client (Dirl
authenticates with the client secret in addition to PKCE), under Access "Selected user groups" a group like `dirl`.
Optionally "Requires Re-Authentication".

## Unlocking

| Scenario                                      | `passphrase` (default) | `keyfile`                                |
|-----------------------------------------------|------------------------|------------------------------------------|
| Full system backup or snapshot leaked         | protected              | **not** protected                        |
| tar of `/var/lib/dirl` leaked                 | protected              | protected while `/etc/dirl` is not in it |
| Root or code execution in the running process | not protected          | not protected                            |
| Unplanned restart                             | unlock once            | automatic                                |

In passphrase mode the process starts sealed: no SSH connections, no metrics, only login and unlock. Five wrong
passphrases lock unlocking for 15 minutes (counter in memory) and are written to the audit log. The passphrase checks
before a key export and a passphrase change count towards the same lockout.

Key file mode: create the key with `head -c 32 /dev/urandom > /etc/dirl/kek`, `chmod 0400`, owner `dirl`, before
the vault is set up. The passphrase keeps working as fallback. Never put `/etc/dirl/kek` into the same backup as
`/var/lib/dirl`.

[Back to the README](../README.md)
