package bayern.kickner.dirl.vault

import bayern.kickner.dirl.crypto.KdfParams
import bayern.kickner.dirl.crypto.SealedBox
import kotlinx.serialization.Serializable

/**
 * The file `vault.json` as stored on disk. Only [kdf] is readable without a key, everything else is ciphertext.
 *
 * @property format Version of this layout, bumped on incompatible changes.
 * @property kdf Parameters to derive the passphrase KEK.
 * @property wrappedDek The data encryption key, encrypted once per unlock method.
 * @property data The serialized [VaultContent], encrypted with the DEK.
 */
@Serializable
data class VaultEnvelope(
    val format: Int = 1,
    val kdf: KdfParams,
    val wrappedDek: WrappedDek,
    val data: SealedBox,
)

/**
 * The DEK encrypted with each available KEK. The passphrase wrap always exists, so the vault can always be opened
 * with the passphrase, even in key file mode.
 *
 * @property passphrase DEK encrypted with the Argon2id key derived from the passphrase.
 * @property keyfile DEK encrypted with the key file contents, only present in key file mode.
 */
@Serializable
data class WrappedDek(
    val passphrase: SealedBox,
    val keyfile: SealedBox? = null,
)

/**
 * Everything Dirl stores, decrypted. Lives only in memory while the vault is unlocked.
 *
 * @property hosts SSH targets and jump hosts.
 * @property keys SSH private keys used to log in.
 * @property snippets Reusable commands for the terminal.
 * @property settings Everything configurable in the UI.
 */
@Serializable
data class VaultContent(
    val hosts: List<Host> = emptyList(),
    val keys: List<SshKey> = emptyList(),
    val snippets: List<Snippet> = emptyList(),
    val settings: VaultSettings = VaultSettings(),
) {
    /** Looks up a host by [id]. */
    fun host(id: String): Host? = hosts.firstOrNull { it.id == id }

    /** Looks up a key by [id]. */
    fun key(id: String): SshKey? = keys.firstOrNull { it.id == id }
}

/**
 * One SSH server.
 *
 * @property id Random ID, stable across renames.
 * @property name Display name, e.g. `web-01`.
 * @property address Host name or IP as seen from Dirl, or from the jump host if [jumpHostId] is set.
 * @property port SSH port.
 * @property username Login user.
 * @property keyId The [SshKey] to log in with.
 * @property jumpHostId Optional host to tunnel through. At most two hops in total, see `ssh/Route.kt`.
 * @property tags Flat tags for grouping in the overview.
 * @property useTmux No longer used. Older versions could start the terminal in tmux. The field stays so their vaults
 *   still load, because the vault JSON rejects unknown fields. Saving the host form drops it.
 * @property jumpOnly Only used as jump host: no terminal, no files, no metrics, and its `authorized_keys` line runs
 *   `command="/bin/false"`. A jump host that is also a terminal target leaves this off.
 * @property pinnedHostKey The host key accepted on first contact (TOFU). `null` until confirmed in the UI.
 */
@Serializable
data class Host(
    val id: String,
    val name: String,
    val address: String,
    val port: Int = 22,
    val username: String,
    val keyId: String,
    val jumpHostId: String? = null,
    val tags: List<String> = emptyList(),
    @Deprecated("tmux support was removed, the field only keeps older vaults loadable")
    val useTmux: Boolean = false,
    val jumpOnly: Boolean = false,
    val pinnedHostKey: PinnedHostKey? = null,
)

/**
 * A host key confirmed by the user. Every later connection must present exactly this key, a different one is
 * blocked hard and never accepted silently.
 *
 * Pinned per host ID, not per address: the same internal IP behind two different jump hosts are two machines.
 *
 * @property keyType SSH key type, e.g. `ssh-ed25519`.
 * @property fingerprint `SHA256:` fingerprint in the format `ssh-keygen -lf` prints.
 * @property pinnedAt Unix milliseconds of the confirmation.
 */
@Serializable
data class PinnedHostKey(
    val keyType: String,
    val fingerprint: String,
    val pinnedAt: Long,
)

/**
 * An SSH key pair, private part in OpenSSH format (unencrypted, the vault encrypts it).
 *
 * Generated and imported keys are stored the same way, so there is exactly one way to load them into sshj and every
 * key can be exported again.
 *
 * @property id Random ID.
 * @property name Display name.
 * @property privateKeyPem `-----BEGIN OPENSSH PRIVATE KEY-----` block.
 * @property publicKey Public key line without comment, e.g. `ssh-ed25519 AAAA...`.
 * @property createdAt Unix milliseconds of generation or import.
 */
@Serializable
data class SshKey(
    val id: String,
    val name: String,
    val privateKeyPem: String,
    val publicKey: String,
    val createdAt: Long,
)

/**
 * A reusable command, sent to the terminal on click.
 *
 * @property id Random ID.
 * @property name Display name.
 * @property command Text sent to the terminal. A trailing newline executes it right away.
 * @property folder Optional folder, a menu of its own above the terminal. A folder exists as long as a snippet names
 *   it, there is nothing to create or delete.
 */
@Serializable
data class Snippet(
    val id: String,
    val name: String,
    val command: String,
    val folder: String? = null,
)

/**
 * Settings managed in the UI. They live in the vault, so they are authenticated by GCM like everything else.
 *
 * @property allowedUsers Who may use Dirl. Checked on every request while the vault is unlocked.
 * @property sshSourceAddress The address target servers see Dirl connecting from. Only used to prefill the
 *   `from="..."` restriction in the `authorized_keys` lines. `null` shows a placeholder.
 */
@Serializable
data class VaultSettings(
    val allowedUsers: List<AllowedUser> = emptyList(),
    val sshSourceAddress: String? = null,
)

/**
 * A user allowed to log in.
 *
 * @property sub The OIDC `sub` claim.
 * @property name Display name at the time access was granted.
 * @property addedAt Unix milliseconds.
 */
@Serializable
data class AllowedUser(val sub: String, val name: String, val addedAt: Long)
