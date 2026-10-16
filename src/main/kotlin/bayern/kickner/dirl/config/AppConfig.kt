package bayern.kickner.dirl.config

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Contents of `config.json`, read once at startup. It only holds what is needed before anybody can log in: where to
 * listen, how to reach the identity provider and how the vault is unlocked. Everything else is managed in the UI
 * and stored in the encrypted vault. The file holds no secret apart from an optional OIDC client secret, so it is
 * `0400` and owned by the service user.
 *
 * @property host Address the HTTP server binds to. Defaults to loopback because TLS is terminated by the reverse
 *   proxy (Zoraxy) in front of Dirl, Ktor CIO has no TLS support of its own.
 * @property port TCP port of the HTTP server.
 * @property publicUrl The URL users type into the browser, e.g. `https://ssh.example.com`, without trailing slash.
 *   Used for the OIDC redirect URI and as the only accepted `Origin` for WebSockets and form posts.
 * @property dataDir Directory holding `vault.json`, its backups, `audit.jsonl` and the log files.
 * @property unlockMode How the vault is unlocked after a restart, see [UnlockMode].
 * @property keyFile Path of the 32 byte key file, only read in [UnlockMode.KEYFILE].
 * @property oidc Login through the OpenID Connect provider (Pocket ID).
 * @property session Lifetime of browser sessions.
 */
@Serializable
data class AppConfig(
    val host: String = "127.0.0.1",
    val port: Int = 8080,
    val publicUrl: String,
    val dataDir: String = "/var/lib/dirl",
    val unlockMode: UnlockMode = UnlockMode.PASSPHRASE,
    val keyFile: String = "/etc/dirl/kek",
    val oidc: OidcConfig,
    val session: SessionConfig = SessionConfig(),
)

/** How the vault's data encryption key is unwrapped after a (re)start. */
@Serializable
enum class UnlockMode {
    /** Default. The process starts sealed until the passphrase is entered in the browser. */
    @SerialName("passphrase")
    PASSPHRASE,

    /**
     * The process unlocks itself at startup with the key file. Convenient, but a full system backup or snapshot
     * then contains both the vault and the key to open it. See README.md for the trade-offs.
     */
    @SerialName("keyfile")
    KEYFILE,
}

/**
 * OpenID Connect settings for the login.
 *
 * @property issuer Issuer URL exactly as the provider reports it in its discovery document, e.g.
 *   `https://id.example.com`. The `iss` claim of every ID token must match it byte for byte.
 * @property clientId Client ID registered in the provider.
 * @property clientSecret Only for a confidential client. Pocket ID supports public clients with PKCE, so this is
 *   usually `null`.
 * @property allowedSubjects Break-glass list of `sub` claims that are always allowed, in addition to the users
 *   managed in the UI. Normally empty: the user who creates the vault is allowed automatically and grants access
 *   to others under Settings. Only needed when nobody in the UI list can log in any more.
 * @property forceReauth Sends `prompt=login` so the provider asks for a fresh passkey on every login, even with an
 *   existing provider session.
 * @property scopes Requested scopes. `openid` is mandatory, `profile` provides the display name.
 */
@Serializable
data class OidcConfig(
    val issuer: String,
    val clientId: String,
    val clientSecret: String? = null,
    val allowedSubjects: List<String> = emptyList(),
    val forceReauth: Boolean = true,
    val scopes: List<String> = listOf("openid", "profile"),
)

/**
 * Lifetime of browser sessions. Sessions only live in memory, a restart logs everybody out.
 *
 * @property idleTimeoutMinutes A session without requests for this long expires.
 * @property maxAgeHours A session expires this long after the login, active or not.
 */
@Serializable
data class SessionConfig(
    val idleTimeoutMinutes: Int = 30,
    val maxAgeHours: Int = 12,
)
