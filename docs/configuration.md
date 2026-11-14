# Configuration

## Minimal config

```json
{
  "publicUrl": "https://ssh.example.com",
  "oidc": {
    "issuer": "https://id.example.com",
    "clientId": "dirl",
    "clientSecret": "secret from the OIDC provider"
  }
}
```

Everything else has a default. Users, hosts, keys, snippets and Dirl's source address are set in the UI and live in
the encrypted vault. `java -jar dirl.jar config=config.json check` validates the file and exits.

At the provider register a confidential client (not public) with PKCE and the callback URL
`<publicUrl>/auth/callback`. Copy `issuer` exactly from the discovery document, a missing or extra trailing slash fails
every login.

## All fields

| Field        | Default         | Description                                                                                  |
|--------------|-----------------|----------------------------------------------------------------------------------------------|
| `host`       | `127.0.0.1`     | Bind address, TLS is the reverse proxy's job                                                 |
| `port`       | `8080`          | HTTP port                                                                                    |
| `publicUrl`  | required        | URL in the browser: scheme, lower case host, optional port, no path, no trailing slash, no `:443`. The only accepted `Origin` |
| `dataDir`    | `/var/lib/dirl` | Vault, backups, access list copy, audit log, logs                                            |
| `unlockMode` | `passphrase`    | `passphrase` or `keyfile`, see [Unlocking](#unlocking)                                       |
| `keyFile`    | `/etc/dirl/kek` | 32 random bytes, only read in `keyfile` mode                                                 |

`oidc`:

| Field             | Default                 | Description                                                                       |
|-------------------|-------------------------|-----------------------------------------------------------------------------------|
| `issuer`          | required                | As in the discovery document, `https` (`http` only on localhost)                  |
| `clientId`        | required                | Client ID at the provider                                                         |
| `clientSecret`    | required                | Secret of the confidential client                                                 |
| `allowedSubjects` | `[]`                    | `sub` values that are always allowed (break-glass). If set, only they may create the vault |
| `forceReauth`     | `true`                  | Asks the provider for a fresh sign-in on every login (`prompt=login`)             |
| `scopes`          | `["openid", "profile"]` | Must contain `openid`                                                             |

`session`: `idleTimeoutMinutes` (default `60`) and `maxAgeHours` (default `12`).

The file is read once at startup, unknown keys are errors. Its only secret is the client secret: keep it `0600` and
owned by root, the systemd unit hands Dirl a copy. `sub` is the provider's stable user ID, Dirl shows it under Settings
for every user and access request. Without `allowedSubjects` the first user the provider lets through creates the vault.

## Command line

`config=<path>` (default `/etc/dirl/config.json`) and `check` (validate and exit). Exit codes: `0` success with
`check`, `1` unexpected failure, `78` config rejected or port in use, which systemd does not restart.

## OIDC provider

Any provider works that offers a discovery document at `<issuer>/.well-known/openid-configuration`, the Authorization
Code Flow with PKCE (S256) for a confidential client with `client_secret_basic`, an ID token with `sub`, `aud`, `exp`,
`iat`, `nonce` and `name` or `preferred_username`, and a token endpoint over `https`. Restrict the client to a group
like `dirl` if the provider can, see [Security](security.md#access).

Tested with Pocket ID: under Access "Selected user groups", optionally "Requires Re-Authentication", the issuer is the
base URL (`https://id.example.com`). Authentik and Keycloak use longer issuers such as
`https://auth.example.com/application/o/dirl/` or `https://kc.example.com/realms/home`.

## Unlocking

| Scenario                              | `passphrase` (default) | `keyfile`                                |
|---------------------------------------|------------------------|------------------------------------------|
| Full backup or snapshot leaked        | protected              | **not** protected                        |
| tar of `/var/lib/dirl` leaked         | protected              | protected while `/etc/dirl` is not in it |
| Root or code execution in the process | not protected          | not protected                            |
| Unplanned restart                     | unlock once            | automatic                                |

In passphrase mode Dirl starts sealed: no SSH connections and no metrics until somebody unlocks. Five wrong
passphrases lock unlocking for 15 minutes.

Key file mode: `head -c 32 /dev/urandom > /etc/dirl/kek` and `chmod 0400` before the vault is set up. With systemd
enable the unit's `LoadCredential=kek` line and set `"keyFile": "/run/credentials/dirl.service/kek"`, with Docker see
[Deployment](deployment.md#optional-hardening). The passphrase keeps working. Never back up `/etc/dirl/kek` together
with `/var/lib/dirl`.

### Changing the mode or the key file

After a switch of `unlockMode`, a new key file or a restored backup from another server the key file in the vault no
longer fits: the old one would still open it, a new one opens nothing. The unlock page says so and offers:

| Situation                                     | Button                  | What happens                                               |
|-----------------------------------------------|-------------------------|------------------------------------------------------------|
| Switched to `passphrase`, old key file left   | Unlock and re-encrypt   | New data key, only the passphrase opens it, backups deleted |
| New key file, or a backup from another server | Unlock and re-encrypt   | New data key for passphrase and key file, backups deleted  |
| Switched to `keyfile`                         | Unlock and add key file | The key file is added, nothing else changes                |
| Any of these                                  | Only unlock (Enter)     | Nothing changes, the page asks again next time             |

Nothing is lost as long as you know the passphrase. Destroy the old key file afterwards, earlier downloads and copies
of the data directory still open with it.

[Back to the README](../README.md)
