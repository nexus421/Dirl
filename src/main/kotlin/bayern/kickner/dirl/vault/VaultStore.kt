package bayern.kickner.dirl.vault

import bayern.kickner.klogger.warnLog
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions

/**
 * Reads and writes `vault.json` crash-safely.
 *
 * Every write goes to a temporary file in the same directory, is flushed to disk with `fsync` and then renamed over
 * the old file. A crash at any point leaves either the old or the new version, never a half-written file. The
 * previous [backups] versions are kept as `vault.json.1` (newest) to `vault.json.N`.
 *
 * Not thread-safe on its own, [Vault] serializes all writes.
 *
 * @property dir Directory of the vault, usually `dataDir`.
 * @property backups Number of previous versions to keep.
 */
class VaultStore(private val dir: File, private val backups: Int = 3) {

    /** The current vault file. */
    val file: File = File(dir, "vault.json")

    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = false
        // The format number must be in the file even though it has a default, future versions read it.
        encodeDefaults = true
    }

    /** True once a vault has been set up. */
    fun exists(): Boolean = file.isFile

    /** Reads the envelope. Throws if the file is missing or not a valid vault. */
    fun read(): VaultEnvelope = json.decodeFromString(VaultEnvelope.serializer(), file.readText())

    /** Atomically replaces the vault with [envelope] and rotates the backups. */
    fun write(envelope: VaultEnvelope) {
        dir.mkdirs()
        val tmp = File(dir, "vault.json.tmp")
        val bytes = json.encodeToString(VaultEnvelope.serializer(), envelope).toByteArray(Charsets.UTF_8)

        FileChannel.open(
            tmp.toPath(),
            setOf(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
        ).use { channel ->
            channel.write(java.nio.ByteBuffer.wrap(bytes))
            channel.force(true)
        }

        rotateBackups()
        Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        syncDirectory()
    }

    /** Shifts `vault.json.N-1` to `.N` and so on, then copies the current file to `.1`. */
    private fun rotateBackups() {
        if (exists().not()) return
        for (i in backups downTo 2) {
            val older = File(dir, "vault.json.${i - 1}")
            if (older.isFile) Files.move(older.toPath(), File(dir, "vault.json.$i").toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
        Files.copy(file.toPath(), File(dir, "vault.json.1").toPath(), StandardCopyOption.REPLACE_EXISTING)
    }

    /** Flushes the directory entry so the rename itself survives a power loss. Linux only, ignored elsewhere. */
    private fun syncDirectory() {
        runCatching { FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) } }
            .onFailure { warnLog { "Could not fsync directory ${dir.absolutePath}: ${it.message}" } }
    }
}
