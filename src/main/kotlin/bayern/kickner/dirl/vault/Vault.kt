package bayern.kickner.dirl.vault

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.crypto.Aead
import bayern.kickner.dirl.crypto.KdfParams
import bayern.kickner.dirl.crypto.SealedBox
import bayern.kickner.dirl.crypto.deriveKek
import bayern.kickner.dirl.wipe
import bayern.kickner.klogger.infoLog
import bayern.kickner.klogger.warnLog
import kotlinx.serialization.json.Json
import kotnexlib.ResultOf2
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import javax.crypto.SecretKey
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/** Lifecycle of the vault. The process starts in [Uninitialized] or [Sealed], never unlocked. */
sealed interface VaultState {
    /** No `vault.json` yet, the first login leads to the setup page. */
    data object Uninitialized : VaultState

    /** The vault exists but the DEK is not in memory. No SSH connections, no metrics. */
    data object Sealed : VaultState

    /**
     * The DEK is in memory and the content is decrypted.
     *
     * @property content Current decrypted content.
     */
    class Unlocked internal constructor(internal val dek: SecretKey, val content: VaultContent) : VaultState
}

/** Why [Vault.setup] was rejected. */
sealed interface SetupError {
    /** A vault already exists. Setup never overwrites one. */
    data object AlreadySetUp : SetupError

    /** @property reason Shown to the user. */
    data class PassphraseTooWeak(val reason: String) : SetupError

    /** Key file mode is configured, but the key file cannot be used. @property reason Shown to the user. */
    data class KeyFileUnavailable(val reason: String) : SetupError
}

/** Why an unlock was rejected. */
sealed interface UnlockError {
    /** The vault is not sealed (not set up yet, or already unlocked). */
    data object NotSealed : UnlockError

    /** @property attemptsLeft Attempts before the lockout starts. */
    data class WrongPassphrase(val attemptsLeft: Int) : UnlockError

    /** Too many failed attempts. @property untilMillis Unix milliseconds when attempts are accepted again. */
    data class LockedOut(val untilMillis: Long) : UnlockError

    /** The vault file or the key file is unreadable. @property reason Shown to the user and logged. */
    data class Unusable(val reason: String) : UnlockError
}

/** Why [Vault.changePassphrase] was rejected. */
sealed interface ChangePassphraseError {
    /** Only possible while unlocked. */
    data object NotUnlocked : ChangePassphraseError

    /** The current passphrase did not match. */
    data object WrongPassphrase : ChangePassphraseError

    /** @property reason Shown to the user. */
    data class TooWeak(val reason: String) : ChangePassphraseError

    /** Key file mode is configured, but the key file cannot be read to wrap the new data key. @property reason Shown. */
    data class KeyFileUnavailable(val reason: String) : ChangePassphraseError
}

/**
 * The encrypted store for hosts, keys, host key pins and snippets.
 *
 * A random 256 bit data encryption key (DEK) encrypts the whole content with AES-256-GCM, with a new nonce on every
 * write. The DEK itself is stored only wrapped: encrypted with a key encryption key (KEK) derived from the passphrase
 * with Argon2id, and in key file mode additionally with the key file. Changing the passphrase creates a new DEK and
 * deletes the local backups, see [changePassphrase].
 *
 * After [MAX_ATTEMPTS] wrong passphrases further attempts are refused for [lockoutDuration] without even running
 * Argon2. The counter is kept in memory only, a restart resets it, which costs an attacker a restart per five tries.
 *
 * All methods are blocking (Argon2 takes up to a second) and thread-safe. Call them off the request thread.
 *
 * @property store File access.
 * @property audit Receives every setup, unlock, lockout and passphrase change.
 * @property keyFile The key file in key file mode, otherwise `null`.
 * @property clock Unix milliseconds, injectable for tests.
 * @property lockoutDuration How long unlocking is refused after [MAX_ATTEMPTS] failures.
 * @property kdfParams Creates the Argon2 parameters for a new vault or a new passphrase. Tests use cheap ones.
 */
class Vault(
    private val store: VaultStore,
    private val audit: AuditLog,
    private val keyFile: File? = null,
    private val clock: () -> Long = System::currentTimeMillis,
    private val lockoutDuration: Duration = 15.minutes,
    private val kdfParams: () -> KdfParams = { KdfParams.generate() },
) {
    private val json = Json { ignoreUnknownKeys = false }
    private val lock = Any()
    private var failedAttempts = 0
    private var lockedUntil = 0L

    /** The envelope as last read or written, so a content update does not need to reread the file. */
    private var envelope: VaultEnvelope? = null

    /** Current state. Reads are lock-free, changes happen under the lock. */
    @Volatile
    var state: VaultState = if (store.exists()) VaultState.Sealed else VaultState.Uninitialized
        private set

    /** Called after every state change, outside the lock. The connection manager closes everything on seal. */
    val listeners: MutableList<(VaultState) -> Unit> = CopyOnWriteArrayList()

    /** The decrypted content, or `null` if the vault is not unlocked. */
    val content: VaultContent? get() = (state as? VaultState.Unlocked)?.content

    /**
     * Creates a new vault and leaves it unlocked. [actor] becomes the first allowed user, in the same write, so there
     * is no moment in which nobody is allowed. In key file mode the DEK is wrapped with the key file as well.
     * [passphrase] is wiped before returning.
     */
    fun setup(passphrase: CharArray, actor: Actor): ResultOf2<Unit, SetupError> {
        val result = synchronized(lock) {
            if (state != VaultState.Uninitialized || store.exists()) return@synchronized ResultOf2.Failure(SetupError.AlreadySetUp)
            val weak = checkPassphrase(passphrase)
            if (weak != null) return@synchronized ResultOf2.Failure(SetupError.PassphraseTooWeak(weak))

            val keyFileKek = keyFile?.let { file ->
                readKeyFile(file).getOrElse { return@synchronized ResultOf2.Failure(SetupError.KeyFileUnavailable(it.message ?: "unreadable")) }
            }

            val dek = Aead.generateKey()
            val params = kdfParams()
            val wrapped = WrappedDek(
                passphrase = wrapDek(dek, passphrase, params),
                keyfile = keyFileKek?.let { kek -> wrapWith(dek, kek).also { kek.wipe() } },
            )
            val owner = AllowedUser(actor.sub, actor.name, clock())
            val content = VaultContent(settings = VaultSettings(allowedUsers = listOf(owner)))
            val newEnvelope = VaultEnvelope(kdf = params, wrappedDek = wrapped, data = encryptContent(content, dek))
            store.write(newEnvelope)
            envelope = newEnvelope
            state = VaultState.Unlocked(dek, content)
            ResultOf2.Success(Unit)
        }
        passphrase.wipe()
        if (result is ResultOf2.Success) {
            audit.record(actor, AuditAction.VAULT_SETUP)
            infoLog { "Vault created and unlocked" }
            notifyListeners()
        }
        return result
    }

    /** Unlocks with the passphrase. [passphrase] is wiped before returning. */
    fun unlock(passphrase: CharArray, actor: Actor): ResultOf2<Unit, UnlockError> {
        val result = synchronized(lock) {
            if (state != VaultState.Sealed) return@synchronized ResultOf2.Failure(UnlockError.NotSealed)
            val now = clock()
            if (now < lockedUntil) return@synchronized ResultOf2.Failure(UnlockError.LockedOut(lockedUntil))

            val current = readEnvelope().getOrElse { return@synchronized ResultOf2.Failure(UnlockError.Unusable(it.message ?: "unreadable")) }
            val kek = deriveKek(passphrase, current.kdf)
            val dek = Aead.open(current.wrappedDek.passphrase, Aead.keyOf(kek)).also { kek.wipe() }

            dek.fold(
                onSuccess = { openWith(current, it) },
                onFailure = { registerFailure(now, actor) },
            )
        }
        passphrase.wipe()
        if (result is ResultOf2.Success) {
            audit.record(actor, AuditAction.VAULT_UNLOCKED)
            notifyListeners()
        }
        return result
    }

    /** Unlocks with the key file, used once at startup in key file mode. */
    fun unlockWithKeyFile(): ResultOf2<Unit, UnlockError> {
        val file = keyFile ?: return ResultOf2.Failure(UnlockError.Unusable("Key file mode is not configured"))
        val result = synchronized(lock) {
            if (state != VaultState.Sealed) return@synchronized ResultOf2.Failure(UnlockError.NotSealed)
            val current = readEnvelope().getOrElse { return@synchronized ResultOf2.Failure(UnlockError.Unusable(it.message ?: "unreadable")) }
            val wrapped = current.wrappedDek.keyfile
                ?: return@synchronized ResultOf2.Failure(UnlockError.Unusable("The vault has no key file wrap, it was set up in passphrase mode"))
            val kek = readKeyFile(file).getOrElse { return@synchronized ResultOf2.Failure(UnlockError.Unusable(it.message ?: "unreadable")) }
            val dek = Aead.open(wrapped, Aead.keyOf(kek)).also { kek.wipe() }
            dek.fold(
                onSuccess = { openWith(current, it) },
                onFailure = { ResultOf2.Failure(UnlockError.Unusable("The key file does not match this vault")) },
            )
        }
        if (result is ResultOf2.Success) {
            audit.record(Actor.SYSTEM, AuditAction.VAULT_UNLOCKED, detail = "key file")
            notifyListeners()
        }
        return result
    }

    /**
     * Checks the passphrase while unlocked, before sensitive actions such as exporting a private key. Failures count
     * towards the same lockout as unlock attempts, so this is no way around it. [passphrase] is wiped.
     */
    fun verifyPassphrase(passphrase: CharArray, actor: Actor): ResultOf2<Unit, UnlockError> {
        val result = synchronized(lock) {
            if (state !is VaultState.Unlocked) return@synchronized ResultOf2.Failure(UnlockError.NotSealed)
            val now = clock()
            if (now < lockedUntil) return@synchronized ResultOf2.Failure(UnlockError.LockedOut(lockedUntil))
            val current = envelope ?: return@synchronized ResultOf2.Failure(UnlockError.Unusable("No vault loaded"))
            val kek = deriveKek(passphrase, current.kdf)
            val ok = Aead.open(current.wrappedDek.passphrase, Aead.keyOf(kek)).onSuccess { it.wipe() }.isSuccess
            kek.wipe()
            if (ok) {
                failedAttempts = 0
                ResultOf2.Success(Unit)
            } else registerFailure(now, actor)
        }
        passphrase.wipe()
        return result
    }

    /** The encrypted vault file as stored on disk, for a backup download. `null` if there is no vault. */
    fun exportEncrypted(): ByteArray? = synchronized(lock) { if (store.exists()) store.file.readBytes() else null }

    /**
     * Restores a vault from an encrypted backup ([exportEncrypted] or a copy of `vault.json`). Only possible before
     * a vault exists. The vault is sealed afterwards and needs the passphrase it was created with.
     *
     * @return `null` on success, otherwise a reason to show.
     */
    fun restore(bytes: ByteArray, actor: Actor): String? {
        val error = synchronized(lock) {
            if (state != VaultState.Uninitialized || store.exists()) return@synchronized "A vault already exists"
            val parsed = runCatching { json.decodeFromString(VaultEnvelope.serializer(), bytes.decodeToString()) }
                .getOrElse { return@synchronized "This is not a Dirl vault file" }
            parsed.kdf.problem()?.let { return@synchronized "This backup has unusable KDF parameters: $it" }
            store.write(parsed)
            envelope = null
            state = VaultState.Sealed
            null
        }
        if (error == null) {
            audit.record(actor, AuditAction.VAULT_RESTORED)
            notifyListeners()
        }
        return error
    }

    /** Drops the DEK and the decrypted content from memory. */
    fun seal(actor: Actor) {
        val wasUnlocked = synchronized(lock) {
            val unlocked = state is VaultState.Unlocked
            if (unlocked) state = VaultState.Sealed
            unlocked
        }
        if (wasUnlocked.not()) return
        audit.record(actor, AuditAction.VAULT_LOCKED)
        notifyListeners()
    }

    /**
     * Applies [transform] to the content and writes the result. Concurrent updates are serialized, each one sees the
     * result of the previous one.
     *
     * @return the new content, or `null` if the vault is not unlocked.
     */
    fun update(transform: (VaultContent) -> VaultContent): VaultContent? = synchronized(lock) {
        val unlocked = state as? VaultState.Unlocked ?: return@synchronized null
        val current = envelope ?: return@synchronized null
        val newContent = transform(unlocked.content)
        val newEnvelope = current.copy(data = encryptContent(newContent, unlocked.dek))
        store.write(newEnvelope)
        envelope = newEnvelope
        state = VaultState.Unlocked(unlocked.dek, newContent)
        newContent
    }

    /**
     * Replaces the passphrase. A passphrase is usually changed because the old one may be known to someone, so this
     * makes sure the old one opens nothing on this machine any more:
     *
     * - A new random DEK encrypts the content. Rewrapping the old DEK would not be enough: every older copy of the
     *   file would still give the old passphrase the very key that encrypts the current vault.
     * - The local backups `vault.json.1` to `.N` are deleted, they hold the old wrap and the old data.
     * - In key file mode the new DEK is wrapped with the key file as well, otherwise any key file wrap is dropped.
     *
     * Encrypted backups downloaded earlier still open with the old passphrase and contain the data of that time. Both
     * arrays are wiped before returning.
     */
    fun changePassphrase(old: CharArray, new: CharArray, actor: Actor): ResultOf2<Unit, ChangePassphraseError> {
        val result = synchronized(lock) {
            val unlocked = state as? VaultState.Unlocked ?: return@synchronized ResultOf2.Failure(ChangePassphraseError.NotUnlocked)
            val current = envelope ?: return@synchronized ResultOf2.Failure(ChangePassphraseError.NotUnlocked)
            val weak = checkPassphrase(new)
            if (weak != null) return@synchronized ResultOf2.Failure(ChangePassphraseError.TooWeak(weak))

            val oldKek = deriveKek(old, current.kdf)
            val matches = Aead.open(current.wrappedDek.passphrase, Aead.keyOf(oldKek)).isSuccess.also { oldKek.wipe() }
            if (matches.not()) return@synchronized ResultOf2.Failure(ChangePassphraseError.WrongPassphrase)

            val keyFileKek = keyFile?.let { file ->
                readKeyFile(file).getOrElse { return@synchronized ResultOf2.Failure(ChangePassphraseError.KeyFileUnavailable(it.message ?: "unreadable")) }
            }
            val dek = Aead.generateKey()
            val params = kdfParams()
            val newEnvelope = VaultEnvelope(
                kdf = params,
                wrappedDek = WrappedDek(
                    passphrase = wrapDek(dek, new, params),
                    keyfile = keyFileKek?.let { kek -> wrapWith(dek, kek).also { kek.wipe() } },
                ),
                data = encryptContent(unlocked.content, dek),
            )
            store.write(newEnvelope)
            store.deleteBackups()
            envelope = newEnvelope
            state = VaultState.Unlocked(dek, unlocked.content)
            ResultOf2.Success(Unit)
        }
        old.wipe()
        new.wipe()
        if (result is ResultOf2.Success) audit.record(actor, AuditAction.PASSPHRASE_CHANGED)
        return result
    }

    private fun openWith(current: VaultEnvelope, dekBytes: ByteArray): ResultOf2<Unit, UnlockError> {
        val dek = Aead.keyOf(dekBytes).also { dekBytes.wipe() }
        val plain = Aead.open(current.data, dek).getOrElse {
            return ResultOf2.Failure(UnlockError.Unusable("The vault data does not match its key, restore a backup"))
        }
        val content = runCatching { json.decodeFromString(VaultContent.serializer(), plain.decodeToString()) }
            .also { plain.wipe() }
            .getOrElse { return ResultOf2.Failure(UnlockError.Unusable("Cannot parse the vault content: ${it.message}")) }

        envelope = current
        failedAttempts = 0
        state = VaultState.Unlocked(dek, content)
        infoLog { "Vault unlocked with ${content.hosts.size} host(s) and ${content.keys.size} key(s)" }
        return ResultOf2.Success(Unit)
    }

    private fun registerFailure(now: Long, actor: Actor): ResultOf2<Unit, UnlockError> {
        failedAttempts++
        val lockedOut = failedAttempts >= MAX_ATTEMPTS
        if (lockedOut.not()) {
            audit.record(actor, AuditAction.VAULT_UNLOCK_FAILED, detail = "attempt $failedAttempts of $MAX_ATTEMPTS")
            return ResultOf2.Failure(UnlockError.WrongPassphrase(MAX_ATTEMPTS - failedAttempts))
        }
        failedAttempts = 0
        lockedUntil = now + lockoutDuration.inWholeMilliseconds
        audit.record(actor, AuditAction.VAULT_LOCKED_OUT, detail = "$MAX_ATTEMPTS wrong passphrases")
        warnLog { "Vault unlock locked for $lockoutDuration after $MAX_ATTEMPTS wrong passphrases" }
        return ResultOf2.Failure(UnlockError.LockedOut(lockedUntil))
    }

    /** Reads the file and refuses KDF parameters that would exhaust the heap or hang the unlock. */
    private fun readEnvelope(): Result<VaultEnvelope> = runCatching {
        store.read().also { read -> read.kdf.problem()?.let { error("The vault file has unusable KDF parameters: $it") } }
    }

    private fun wrapDek(dek: SecretKey, passphrase: CharArray, params: KdfParams): SealedBox {
        val kek = deriveKek(passphrase, params)
        return wrapWith(dek, kek).also { kek.wipe() }
    }

    private fun wrapWith(dek: SecretKey, kek: ByteArray): SealedBox {
        val raw = dek.encoded
        return Aead.seal(raw, Aead.keyOf(kek)).also { raw.wipe() }
    }

    private fun encryptContent(content: VaultContent, dek: SecretKey): SealedBox {
        val plain = json.encodeToString(VaultContent.serializer(), content).toByteArray(Charsets.UTF_8)
        return Aead.seal(plain, dek).also { plain.wipe() }
    }

    private fun notifyListeners() {
        val current = state
        listeners.forEach { listener -> runCatching { listener(current) } }
    }

    companion object {
        /** Wrong passphrases before the lockout starts. */
        const val MAX_ATTEMPTS = 5

        /** Expected size of the key file in bytes. */
        const val KEY_FILE_SIZE = 32

        /** Reads the key file and checks its size. Create it with `head -c 32 /dev/urandom > /etc/dirl/kek`. */
        fun readKeyFile(file: File): Result<ByteArray> = runCatching {
            val bytes = file.readBytes()
            require(bytes.size == KEY_FILE_SIZE) { "Key file ${file.absolutePath} must contain exactly $KEY_FILE_SIZE bytes, has ${bytes.size}" }
            bytes
        }
    }
}
