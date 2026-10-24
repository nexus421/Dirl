package bayern.kickner.dirl.auth

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.restrictToOwner
import bayern.kickner.dirl.vault.AllowedUser
import bayern.kickner.dirl.vault.Vault
import bayern.kickner.dirl.vault.VaultState
import bayern.kickner.klogger.warnLog
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotnexlib.ResultOf2
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.CopyOnWriteArrayList

/**
 * A login that was rejected because the user is not allowed yet. Shown under Settings, where it can be allowed
 * with one click.
 *
 * @property sub The OIDC `sub` claim.
 * @property name Display name from the ID token.
 * @property time Unix milliseconds of the latest attempt.
 */
data class AccessRequest(val sub: String, val name: String, val time: Long)

/** Why a user could not be removed. */
sealed interface RevokeError {
    /** The vault is not unlocked. */
    data object NotUnlocked : RevokeError

    /** Removing the last user would lock everybody out. */
    data object LastUser : RevokeError
}

/**
 * Decides who may use Dirl. Pocket ID's group restriction is the first gate, this is the second one.
 *
 * - While the vault is unlocked, the list in the vault ([bayern.kickner.dirl.vault.VaultSettings.allowedUsers]) is
 *   authoritative. It is authenticated by GCM, nobody can add themselves by editing a file.
 * - While the vault is sealed, a plain copy of that list (`dataDir/access.json`) decides who may reach the unlock
 *   page. Tampering with the copy only gives access to the passphrase prompt, nothing else, and the copy is
 *   rewritten from the vault on every unlock.
 * - Before the vault exists, every user the provider lets through may set it up (first-run bootstrap). The user who
 *   creates the vault becomes the first allowed user. Set up the vault right after deployment.
 * - `oidc.allowedSubjects` in the config is a break-glass list that is always allowed.
 *
 * Rejected logins are kept in memory as [requests] (at most [MAX_REQUESTS]) so they can be allowed in the UI.
 *
 * @property config The `oidc` section with the break-glass list.
 * @property vault Source of the authoritative list.
 * @property mirror The plain copy, usually `dataDir/access.json`.
 * @property audit Receives grants and revocations.
 * @property clock Unix milliseconds.
 */
class AccessControl(
    private val config: OidcConfig,
    private val vault: Vault,
    private val mirror: File,
    private val audit: AuditLog,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val pending = CopyOnWriteArrayList<AccessRequest>()

    init {
        // A fresh unlock rewrites the copy, so it never drifts from the vault for long.
        vault.listeners += { state -> if (state is VaultState.Unlocked) writeMirror(state.content.settings.allowedUsers) }
    }

    /** Rejected logins, newest first. */
    val requests: List<AccessRequest> get() = pending.sortedByDescending { it.time }

    /** True while no vault exists, any user passing the provider may set it up. */
    val isBootstrap: Boolean get() = vault.state == VaultState.Uninitialized

    /** True if [sub] may use Dirl right now. */
    fun isAllowed(sub: String): Boolean {
        if (sub in config.allowedSubjects) return true
        return when (val state = vault.state) {
            VaultState.Uninitialized -> true
            VaultState.Sealed -> readMirror().any { it.sub == sub }
            is VaultState.Unlocked -> state.content.settings.allowedUsers.any { it.sub == sub }
        }
    }

    /** Remembers a rejected login for the access requests list. */
    fun recordRequest(sub: String, name: String) {
        pending.removeIf { it.sub == sub }
        pending += AccessRequest(sub, name, clock())
        while (pending.size > MAX_REQUESTS) pending.remove(pending.minBy { it.time })
    }

    /** Dismisses a request without granting access. */
    fun dismissRequest(sub: String) {
        pending.removeIf { it.sub == sub }
    }

    /**
     * Grants access to [sub]. Used by the UI and for the user who creates the vault.
     *
     * @return false if the vault is not unlocked.
     */
    fun allow(sub: String, name: String, actor: Actor): Boolean {
        val updated = vault.update { content ->
            val users = content.settings.allowedUsers.filterNot { it.sub == sub } + AllowedUser(sub, name, clock())
            content.copy(settings = content.settings.copy(allowedUsers = users))
        } ?: return false
        writeMirror(updated.settings.allowedUsers)
        pending.removeIf { it.sub == sub }
        audit.record(actor, AuditAction.USER_ALLOWED, detail = "$name ($sub)")
        return true
    }

    /**
     * Lets [sub] reach the unlock page of a vault that was just restored from a backup. Without this the person who
     * restored it would be locked out at once: the restored vault is sealed, and no copy of its user list exists on
     * this machine yet. After the unlock the list inside the vault decides again, so a user who is not in it loses
     * access right there.
     */
    fun allowUntilUnlock(sub: String, name: String) {
        val users = readMirror().filterNot { it.sub == sub } + AllowedUser(sub, name, clock())
        writeMirror(users)
    }

    /**
     * Removes [sub]. The last user cannot be removed, someone has to be able to log in. A [sub] that is not in the
     * list counts as removed, nothing is written or audited.
     *
     * The new list is computed before [Vault.update], so an [allow] at the same moment can get lost. Accepted: the
     * outcome is one access too few, never one too many, and there are rarely two admins clicking at once.
     */
    fun revoke(sub: String, actor: Actor): ResultOf2<Unit, RevokeError> {
        val users = vault.content?.settings?.allowedUsers ?: return ResultOf2.Failure(RevokeError.NotUnlocked)
        // Nothing to remove is the wanted outcome already, without a write and an audit entry.
        val removed = users.firstOrNull { it.sub == sub } ?: return ResultOf2.Success(Unit)
        val remaining = users.filterNot { it.sub == sub }
        if (remaining.isEmpty()) return ResultOf2.Failure(RevokeError.LastUser)
        vault.update { content -> content.copy(settings = content.settings.copy(allowedUsers = remaining)) }
            ?: return ResultOf2.Failure(RevokeError.NotUnlocked)
        writeMirror(remaining)
        audit.record(actor, AuditAction.USER_REVOKED, detail = "${removed.name} ($sub)")
        return ResultOf2.Success(Unit)
    }

    private fun readMirror(): List<AllowedUser> = runCatching {
        if (mirror.isFile.not()) emptyList() else json.decodeFromString(AccessMirror.serializer(), mirror.readText()).users
    }.getOrElse {
        warnLog { "Cannot read ${mirror.absolutePath}, only break-glass users can log in while sealed: ${it.message}" }
        emptyList()
    }

    private fun writeMirror(users: List<AllowedUser>) {
        runCatching {
            mirror.parentFile?.mkdirs()
            val tmp = File(mirror.parentFile, mirror.name + ".tmp")
            tmp.writeText(json.encodeToString(AccessMirror.serializer(), AccessMirror(users)))
            restrictToOwner(tmp)
            Files.move(tmp.toPath(), mirror.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        }.onFailure { warnLog { "Cannot write ${mirror.absolutePath}: ${it.message}" } }
    }

    @Serializable
    private data class AccessMirror(val users: List<AllowedUser>)

    companion object {
        /** Rejected logins kept for the UI. */
        const val MAX_REQUESTS = 20
    }
}
