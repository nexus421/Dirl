package bayern.kickner.dirl.audit

import bayern.kickner.dirl.restrictToOwner
import bayern.kickner.klogger.errorLog
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.io.FileOutputStream
import java.time.Instant

/**
 * Who did something: the logged-in user from the OIDC ID token, or the system itself.
 *
 * @property sub Stable `sub` claim, `system` for actions without a user (e.g. key file unlock at startup).
 * @property name Display name from the `name` or `preferred_username` claim, only for humans reading the log.
 */
@Serializable
data class Actor(val sub: String, val name: String) {
    companion object {
        /** Actions Dirl takes on its own. */
        val SYSTEM = Actor("system", "system")
    }
}

/** Everything that ends up in the audit log. Terminal contents are never logged, only that a terminal was opened. */
enum class AuditAction {
    LOGIN, LOGIN_REJECTED, LOGOUT, SESSION_REVOKED, USER_ALLOWED, USER_REVOKED,
    VAULT_SETUP, VAULT_RESTORED, VAULT_EXPORTED, VAULT_UNLOCKED, VAULT_UNLOCK_FAILED, VAULT_LOCKED_OUT, VAULT_LOCKED,
    PASSPHRASE_CHANGED, SETTINGS_CHANGED,
    HOST_ADDED, HOST_UPDATED, HOST_DELETED,
    KEY_GENERATED, KEY_IMPORTED, KEY_RENAMED, KEY_EXPORTED, KEY_DELETED,
    HOST_KEY_PINNED, HOST_KEY_MISMATCH,
    TERMINAL_OPENED, TERMINAL_CLOSED,
    SFTP_DOWNLOAD, SFTP_UPLOAD, SFTP_EDIT, SFTP_MKDIR, SFTP_RENAME, SFTP_DELETE,
    SNIPPET_ADDED, SNIPPET_UPDATED, SNIPPET_DELETED,
    CONNECTION_STOPPED,
}

/**
 * One line of `audit.jsonl`.
 *
 * @property time ISO-8601 instant in UTC.
 * @property sub The actor's `sub` claim.
 * @property name The actor's display name.
 * @property action What happened.
 * @property host Name of the affected host, if any.
 * @property detail Free text, e.g. a file path or the reason of a failure. Never a secret.
 */
@Serializable
data class AuditEntry(
    val time: String,
    val sub: String,
    val name: String,
    val action: AuditAction,
    val host: String? = null,
    val detail: String? = null,
)

/**
 * Append-only audit log, one JSON object per line. The file is opened in append mode for every entry and flushed
 * right away, so nothing is lost on a crash and external tools (`tail -f`, `jq`) can read it at any time.
 *
 * @property file Usually `dataDir/audit.jsonl`.
 * @property clock Source of the timestamp, injectable for tests.
 */
class AuditLog(private val file: File, private val clock: () -> Instant = Instant::now) {

    private val json = Json { explicitNulls = false }

    /** Appends one entry. A failing write is logged but never breaks the action that triggered it. */
    @Synchronized
    fun record(actor: Actor, action: AuditAction, host: String? = null, detail: String? = null) {
        val entry = AuditEntry(clock().toString(), actor.sub, actor.name, action, host, detail)
        runCatching {
            file.parentFile?.mkdirs()
            val isNew = file.exists().not()
            FileOutputStream(file, true).use { out ->
                out.write((json.encodeToString(AuditEntry.serializer(), entry) + "\n").toByteArray(Charsets.UTF_8))
                out.fd.sync()
            }
            if (isNew) restrictToOwner(file)
        }.onFailure { errorLog("Could not write audit entry $action", it) }
    }

    /** Returns the last [limit] entries, newest first. Lines that cannot be parsed are skipped. */
    @Synchronized
    fun tail(limit: Int = 100): List<AuditEntry> {
        if (file.isFile.not()) return emptyList()
        return file.readLines().takeLast(limit).reversed().mapNotNull {
            runCatching { json.decodeFromString(AuditEntry.serializer(), it) }.getOrNull()
        }
    }
}
