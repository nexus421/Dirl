package bayern.kickner.dirl.vault

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.crypto.Aead
import bayern.kickner.dirl.crypto.KdfParams
import kotlinx.serialization.json.Json
import kotnexlib.ResultOf2
import java.io.File
import java.nio.file.Files
import kotlin.test.*

/** The key file wrap after a mode change, a replaced key file or a restore, see [Vault.keyFileWrap]. */
class KeyFileWrapTest {
    private val dir: File = Files.createTempDirectory("dirl-keyfile").toFile()
    private val actor = Actor("sub-1", "Tester")
    private val passphrase = "correct horse battery staple extra"
    private val host = Host(id = "h1", name = "web", address = "10.0.0.1", username = "root", keyId = "k1")
    private val oldKey = ByteArray(32) { it.toByte() }
    private val newKey = ByteArray(32) { (it + 100).toByte() }

    /** Cheap Argon2 parameters, the real ones take a second per derivation. */
    private fun vault(keyFile: File? = null, where: File = dir) = Vault(
        store = VaultStore(where),
        audit = AuditLog(File(where, "audit.jsonl"), clock = { 1L }),
        keyFile = keyFile,
        clock = { 1L },
        kdfParams = { KdfParams.generate().copy(memKiB = 64, iterations = 1) },
    )

    private fun keyFile(bytes: ByteArray, where: File = dir) = File(where, "kek").apply { writeBytes(bytes) }

    private fun otherDir() = Files.createTempDirectory("dirl-keyfile-other").toFile()

    /** True if [key] alone decrypts the content of [file], as somebody with a leaked copy and the key file would try. */
    private fun opens(key: ByteArray, file: File): Boolean {
        val envelope = Json.decodeFromString<VaultEnvelope>(file.readText())
        val dek = envelope.wrappedDek.keyfile?.let { Aead.open(it, Aead.keyOf(key)).getOrNull() } ?: return false
        return Aead.open(envelope.data, Aead.keyOf(dek)).isSuccess
    }

    /** True if [key] opens `vault.json` or one of its local backups in [where]. */
    private fun anyCopyOpens(key: ByteArray, where: File = dir) =
        (listOf("vault.json") + (1..3).map { "vault.json.$it" }).map { File(where, it) }.filter { it.isFile }.any { opens(key, it) }

    private fun unlock(v: Vault, fix: Boolean) = assertIs<ResultOf2.Success<Unit>>(v.unlock(passphrase.toCharArray(), actor, fixKeyFileWrap = fix))

    @Test
    fun `a vault that fits its mode is reported as fitting and never rewritten`() {
        val file = keyFile(oldKey)
        vault(file).setup(passphrase.toCharArray(), actor)
        val before = File(dir, "vault.json").readBytes()
        assertEquals(KeyFileWrap.FITS, vault(file).keyFileWrap())
        unlock(vault(file), fix = true)
        assertContentEquals(before, File(dir, "vault.json").readBytes())

        val plain = otherDir()
        vault(null, plain).setup(passphrase.toCharArray(), actor)
        val plainBefore = File(plain, "vault.json").readBytes()
        assertEquals(KeyFileWrap.FITS, vault(null, plain).keyFileWrap())
        unlock(vault(null, plain), fix = true)
        assertContentEquals(plainBefore, File(plain, "vault.json").readBytes())
    }

    @Test
    fun `after a switch to passphrase mode the old key file opens nothing once the user confirms`() {
        vault(keyFile(oldKey)).setup(passphrase.toCharArray(), actor)
        vault(keyFile(oldKey)).also { unlock(it, fix = false) }.update { it.copy(hosts = listOf(host)) }
        assertEquals(KeyFileWrap.LEFT_OVER, vault(null).keyFileWrap())

        // Only unlocking changes nothing, the page asks again next time.
        unlock(vault(null), fix = false)
        assertTrue(anyCopyOpens(oldKey))
        assertEquals(KeyFileWrap.LEFT_OVER, vault(null).keyFileWrap())

        val v = vault(null)
        unlock(v, fix = true)
        assertEquals(KeyFileWrap.FITS, v.keyFileWrap())
        assertTrue((1..3).none { File(dir, "vault.json.$it").exists() }, "the backups hold the old DEK and must be gone")
        v.update { it.copy(snippets = listOf(Snippet("s", "n", "c"))) }
        assertFalse(anyCopyOpens(oldKey))

        val restarted = vault(null)
        unlock(restarted, fix = false)
        assertEquals(listOf(host), restarted.content?.hosts)
        assertEquals(1, restarted.content?.snippets?.size)
    }

    @Test
    fun `a replaced key file opens the vault again after one confirmed passphrase unlock`() {
        val file = keyFile(oldKey)
        vault(file).setup(passphrase.toCharArray(), actor)
        vault(file).also { unlock(it, fix = false) }.update { it.copy(hosts = listOf(host)) }
        file.writeBytes(newKey)

        assertIs<ResultOf2.Failure<UnlockError>>(vault(file).unlockWithKeyFile())
        assertEquals(KeyFileWrap.FOREIGN, vault(file).keyFileWrap())
        unlock(vault(file), fix = true)

        assertFalse(anyCopyOpens(oldKey), "the old key file must open no copy")
        val restarted = vault(file)
        assertIs<ResultOf2.Success<Unit>>(restarted.unlockWithKeyFile(), "the new key file must unlock after a restart")
        assertEquals(listOf(host), restarted.content?.hosts)
    }

    @Test
    fun `a key file backup restored into passphrase mode drops the other server's key file`() {
        val source = vault(keyFile(oldKey))
        source.setup(passphrase.toCharArray(), actor)
        source.update { it.copy(hosts = listOf(host)) }
        val target = otherDir()
        val restored = vault(null, target)
        assertNull(restored.restore(source.exportEncrypted()!!, actor))
        assertEquals(KeyFileWrap.LEFT_OVER, restored.keyFileWrap())

        unlock(restored, fix = true)
        restored.update { it.copy(snippets = listOf(Snippet("s", "n", "c"))) }
        assertFalse(anyCopyOpens(oldKey, target))
        assertEquals(listOf(host), restored.content?.hosts)
    }

    @Test
    fun `a key file backup restored into a server with another key file switches to that key file`() {
        val source = vault(keyFile(oldKey))
        source.setup(passphrase.toCharArray(), actor)
        val target = otherDir()
        val targetKey = keyFile(newKey, target)
        val restored = vault(targetKey, target)
        assertNull(restored.restore(source.exportEncrypted()!!, actor))
        assertEquals(KeyFileWrap.FOREIGN, restored.keyFileWrap())

        unlock(restored, fix = true)
        assertFalse(anyCopyOpens(oldKey, target))
        assertIs<ResultOf2.Success<Unit>>(vault(targetKey, target).unlockWithKeyFile())
    }

    @Test
    fun `a switch to key file mode only adds the key file and keeps the backups`() {
        vault(null).setup(passphrase.toCharArray(), actor)
        repeat(2) { i -> vault(null).also { unlock(it, fix = false) }.update { it.copy(snippets = listOf(Snippet("s$i", "n", "c"))) } }
        val file = keyFile(newKey)
        assertEquals(KeyFileWrap.MISSING, vault(file).keyFileWrap())
        val dataBefore = VaultStore(dir).read().data

        unlock(vault(file), fix = true)
        assertEquals(dataBefore, VaultStore(dir).read().data, "the data and its DEK stay")
        assertTrue(File(dir, "vault.json.2").isFile, "nothing to retire, the backups stay")
        assertIs<ResultOf2.Success<Unit>>(vault(file).unlockWithKeyFile())
    }

    @Test
    fun `an unreadable key file is reported as unknown and changes nothing`() {
        vault(keyFile(oldKey)).setup(passphrase.toCharArray(), actor)
        val missing = File(dir, "gone")
        val before = File(dir, "vault.json").readBytes()
        assertEquals(KeyFileWrap.UNKNOWN, vault(missing).keyFileWrap())
        unlock(vault(missing), fix = true)
        assertContentEquals(before, File(dir, "vault.json").readBytes())
        assertEquals(KeyFileWrap.UNKNOWN, vault(null, otherDir()).keyFileWrap(), "no vault yet")
    }
}
