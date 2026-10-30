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
| `publicUrl`  | string | required        | URL in the browser, scheme, host and optional port only (no path, no trailing slash), lower case host, no default port (`:443`). OIDC redirect base and the only accepted `Origin` |
| `dataDir`    | string | `/var/lib/dirl` | Vault, backups, access list copy, audit log, logs                                        |
| `unlockMode` | string | `passphrase`    | `passphrase` or `keyfile`, see [Unlocking](#unlocking)                                   |
| `keyFile`    | string | `/etc/dirl/kek` | 32 random bytes, only read in `keyfile` mode                                             |
| `oidc`       | object | required        | See below                                                                                |
| `session`    | object | see below       | See below                                                                                |

`oidc`:

| Field             | Type     | Default                 | Description                                                                      |
|-------------------|----------|-------------------------|----------------------------------------------------------------------------------|
| `issuer`          | string   | required                | Issuer exactly as in the discovery document. `https` (or `http` on localhost)    |
| `clientId`        | string   | required                | Client ID at the provider                                                        |
| `clientSecret`    | string   | required                | Secret of the confidential client, sent to the token endpoint with HTTP Basic    |
| `allowedSubjects` | string[] | `[]`                    | Always allowed (break-glass). If set, only these may create the vault            |
| `forceReauth`     | bool     | `true`                  | Sends `prompt=login`, so every login needs a fresh sign-in at the provider       |
| `scopes`          | string[] | `["openid", "profile"]` | Must contain `openid`                                                            |

`allowedSubjects` holds `sub` values, not user names: the stable user ID of the provider, at most providers shown in
its admin UI. Dirl shows it under Settings for every user and access request. Set it before the first start to
decide who may create the vault, otherwise the first user the provider lets through does.

`session`:

| Field                | Type | Default | Description                               |
|----------------------|------|---------|-------------------------------------------|
| `idleTimeoutMinutes` | int  | `60`    | Session expires after this much idle time |
| `maxAgeHours`        | int  | `12`    | Session expires this long after the login |

## OIDC provider

Any OpenID Connect provider works if it offers:

- a discovery document at `<issuer>/.well-known/openid-configuration`
- the Authorization Code Flow with PKCE (S256) for a confidential client with `client_secret_basic`
- `sub`, `aud`, `exp`, `iat` and `nonce` in the ID token, and `name` or `preferred_username` for the display name
- a token endpoint over `https`. Dirl takes the ID token straight from it and relies on TLS instead of the token
  signature, see [Security](security.md#login-and-web-hardening)

Client setup at the provider: callback URL `<publicUrl>/auth/callback`, PKCE enabled, **not** a public client (Dirl
authenticates with the client secret in addition to PKCE). Copy `issuer` from the discovery document, a missing or
extra trailing slash fails every login. Restrict the client to a group like `dirl` if the provider can do that, see
[Security](security.md#access).

Only Pocket ID is tested so far. There: under Access "Selected user groups" a group like `dirl`, optionally
"Requires Re-Authentication". The issuer is the base URL, e.g. `https://id.example.com`. Other providers use longer
issuers, e.g. `https://auth.example.com/application/o/dirl/` in Authentik or `https://kc.example.com/realms/home` in
Keycloak.

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
