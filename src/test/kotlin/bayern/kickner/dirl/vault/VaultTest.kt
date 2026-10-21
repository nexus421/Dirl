package bayern.kickner.dirl.vault

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.crypto.KdfParams
import bayern.kickner.dirl.crypto.deriveKek
import bayern.kickner.dirl.crypto.Aead
import kotlinx.serialization.json.Json
import kotnexlib.ResultOf2
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VaultTest {
    private val dir: File = Files.createTempDirectory("dirl-vault").toFile()
    private val actor = Actor("sub-1", "Tester")
    private val passphrase = "correct horse battery staple extra"
    private var now = 1_000_000L

    /** Cheap Argon2 parameters, the real ones take a second per derivation. */
    private fun vault(keyFile: File? = null) = Vault(
        store = VaultStore(dir),
        audit = AuditLog(File(dir, "audit.jsonl")),
        keyFile = keyFile,
        clock = { now },
        kdfParams = { KdfParams.generate().copy(memKiB = 64, iterations = 1) },
    )

    private val host = Host(id = "h1", name = "web", address = "10.0.0.1", username = "root", keyId = "k1")

    @Test
    fun `setup, update and unlock in a new process keep the content`() {
        val first = vault()
        assertIs<VaultState.Uninitialized>(first.state)
        assertIs<ResultOf2.Success<Unit>>(first.setup(passphrase.toCharArray(), actor))
        first.update { it.copy(hosts = listOf(host)) }

        val second = vault()
        assertIs<VaultState.Sealed>(second.state)
        assertNull(second.content)
        assertIs<ResultOf2.Success<Unit>>(second.unlock(passphrase.toCharArray(), actor))
        assertEquals(listOf(host), second.content?.hosts)
    }

    @Test
    fun `the file on disk contains no plaintext`() {
        vault().apply {
            setup(passphrase.toCharArray(), actor)
            update { it.copy(hosts = listOf(host)) }
        }
        val raw = File(dir, "vault.json").readText()
        assertTrue("10.0.0.1" !in raw && "web" !in raw)
    }

    @Test
    fun `setup rejects a weak passphrase and never overwrites`() {
        val v = vault()
        assertIs<ResultOf2.Failure<SetupError.PassphraseTooWeak>>(v.setup("short".toCharArray(), actor))
        v.setup(passphrase.toCharArray(), actor)
        assertEquals(SetupError.AlreadySetUp, (vault().setup(passphrase.toCharArray(), actor) as ResultOf2.Failure).value)
    }

    @Test
    fun `five wrong passphrases lock unlocking until the lockout ends`() {
        vault().setup(passphrase.toCharArray(), actor)
        val v = vault()
        repeat(4) { i ->
            val error = (v.unlock("wrong passphrase number $i!!".toCharArray(), actor) as ResultOf2.Failure).value
            assertEquals(UnlockError.WrongPassphrase(4 - i), error)
        }
        assertIs<UnlockError.LockedOut>((v.unlock("still wrong passphrase!!".toCharArray(), actor) as ResultOf2.Failure).value)
        // Locked even with the right passphrase.
        assertIs<UnlockError.LockedOut>((v.unlock(passphrase.toCharArray(), actor) as ResultOf2.Failure).value)

        now += 16 * 60 * 1000
        assertIs<ResultOf2.Success<Unit>>(v.unlock(passphrase.toCharArray(), actor))
    }

    @Test
    fun `changing the passphrase keeps the data and retires the old passphrase`() {
        val v = vault()
        v.setup(passphrase.toCharArray(), actor)
        v.update { it.copy(hosts = listOf(host)) }
        val newPassphrase = "another very long passphrase 42"
        assertIs<ResultOf2.Success<Unit>>(v.changePassphrase(passphrase.toCharArray(), newPassphrase.toCharArray(), actor))

        assertIs<ResultOf2.Failure<UnlockError>>(vault().unlock(passphrase.toCharArray(), actor))
        val reopened = vault()
        assertIs<ResultOf2.Success<Unit>>(reopened.unlock(newPassphrase.toCharArray(), actor))
        assertEquals(listOf(host), reopened.content?.hosts)
    }

    @Test
    fun `after a passphrase change the old passphrase opens nothing on disk`() {
        val v = vault()
        v.setup(passphrase.toCharArray(), actor)
        v.update { it.copy(hosts = listOf(host)) }
        val oldCopy = VaultStore(dir).read()
        val newPassphrase = "another very long passphrase 42"
        assertIs<ResultOf2.Success<Unit>>(v.changePassphrase(passphrase.toCharArray(), newPassphrase.toCharArray(), actor))

        assertTrue((1..3).none { File(dir, "vault.json.$it").exists() }, "local backups must be deleted")
        // An attacker with the old passphrase and an old copy of the file gets the old data key, which no longer
        // decrypts the current vault.
        val oldDek = Aead.open(oldCopy.wrappedDek.passphrase, Aead.keyOf(deriveKek(passphrase.toCharArray(), oldCopy.kdf))).getOrThrow()
        assertTrue(Aead.open(VaultStore(dir).read().data, Aead.keyOf(oldDek)).isFailure)

        // The vault keeps working in this process and after a restart.
        v.update { it.copy(snippets = listOf(Snippet("s", "n", "c"))) }
        val reopened = vault()
        assertIs<ResultOf2.Success<Unit>>(reopened.unlock(newPassphrase.toCharArray(), actor))
        assertEquals(listOf(host), reopened.content?.hosts)
        assertEquals(1, reopened.content?.snippets?.size)
    }

    @Test
    fun `a passphrase change in key file mode keeps the key file working`() {
        val keyFile = File(dir, "kek").apply { writeBytes(ByteArray(32) { it.toByte() }) }
        val v = vault(keyFile)
        v.setup(passphrase.toCharArray(), actor)
        assertIs<ResultOf2.Success<Unit>>(v.changePassphrase(passphrase.toCharArray(), "another very long passphrase 42".toCharArray(), actor))
        assertIs<ResultOf2.Success<Unit>>(vault(keyFile).unlockWithKeyFile())
    }

    @Test
    fun `a modified ciphertext is detected`() {
        vault().setup(passphrase.toCharArray(), actor)
        val file = File(dir, "vault.json")
        val json = Json { prettyPrint = true }
        val envelope = json.decodeFromString(VaultEnvelope.serializer(), file.readText())
        val ct = envelope.data.ct
        val flipped = (if (ct[5] == 'A') 'B' else 'A').let { ct.substring(0, 5) + it + ct.substring(6) }
        file.writeText(json.encodeToString(VaultEnvelope.serializer(), envelope.copy(data = envelope.data.copy(ct = flipped))))

        assertIs<UnlockError.Unusable>((vault().unlock(passphrase.toCharArray(), actor) as ResultOf2.Failure).value)
    }

    @Test
    fun `writes keep three backups`() {
        val v = vault()
        v.setup(passphrase.toCharArray(), actor)
        repeat(5) { i -> v.update { it.copy(snippets = listOf(Snippet("s$i", "n", "c"))) } }
        assertTrue(File(dir, "vault.json.3").isFile)
        assertTrue(File(dir, "vault.json.4").exists().not())
        assertTrue(File(dir, "vault.json.tmp").exists().not())
    }

    @Test
    fun `key file mode unlocks without passphrase and still accepts the passphrase`() {
        val keyFile = File(dir, "kek").apply { writeBytes(ByteArray(32) { it.toByte() }) }
        vault(keyFile).setup(passphrase.toCharArray(), actor)

        assertIs<ResultOf2.Success<Unit>>(vault(keyFile).unlockWithKeyFile())
        assertIs<ResultOf2.Success<Unit>>(vault(keyFile).unlock(passphrase.toCharArray(), actor))

        keyFile.writeBytes(ByteArray(32))
        assertIs<ResultOf2.Failure<UnlockError>>(vault(keyFile).unlockWithKeyFile())
    }

    @Test
    fun `the creator is the first allowed user`() {
        val v = vault()
        v.setup(passphrase.toCharArray(), actor)
        assertEquals(listOf(actor.sub), v.content?.settings?.allowedUsers?.map { it.sub })
    }

    @Test
    fun `passphrase checks while unlocked share the lockout`() {
        val v = vault()
        v.setup(passphrase.toCharArray(), actor)
        assertIs<ResultOf2.Success<Unit>>(v.verifyPassphrase(passphrase.toCharArray(), actor))
        repeat(4) { assertIs<UnlockError.WrongPassphrase>((v.verifyPassphrase("wrong passphrase for export".toCharArray(), actor) as ResultOf2.Failure).value) }
        assertIs<UnlockError.LockedOut>((v.verifyPassphrase("wrong passphrase for export".toCharArray(), actor) as ResultOf2.Failure).value)
        assertIs<UnlockError.LockedOut>((v.verifyPassphrase(passphrase.toCharArray(), actor) as ResultOf2.Failure).value)
    }

    @Test
    fun `an exported backup restores into a fresh installation`() {
        val v = vault()
        v.setup(passphrase.toCharArray(), actor)
        v.update { it.copy(hosts = listOf(host)) }
        val backup = v.exportEncrypted()!!

        val freshDir = Files.createTempDirectory("dirl-restore").toFile()
        val fresh = Vault(VaultStore(freshDir), AuditLog(File(freshDir, "audit.jsonl")), kdfParams = { KdfParams.generate().copy(memKiB = 64, iterations = 1) })
        assertTrue(fresh.restore("not a vault".toByteArray(), actor) != null)
        assertNull(fresh.restore(backup, actor))
        assertIs<VaultState.Sealed>(fresh.state)
        assertIs<ResultOf2.Success<Unit>>(fresh.unlock(passphrase.toCharArray(), actor))
        assertEquals(listOf(host), fresh.content?.hosts)
        assertTrue(fresh.restore(backup, actor) != null, "restore must never overwrite an existing vault")
    }

    @Test
    fun `KDF parameters outside the bounds are refused`() {
        val good = KdfParams.generate()
        assertNull(good.problem())
        assertNull(good.copy(memKiB = 64, iterations = 1).problem(), "the cheap test parameters must stay usable")
        listOf(
            good.copy(alg = "scrypt"),
            good.copy(memKiB = 4_000_000),
            good.copy(memKiB = 4),
            good.copy(iterations = 0),
            good.copy(iterations = 1_000_000),
            good.copy(parallelism = 0),
            good.copy(parallelism = 64),
            good.copy(salt = "not base64!"),
            good.copy(salt = ""),
        ).forEach { assertTrue(it.problem() != null, "should be refused: $it") }
    }

    @Test
    fun `a vault file with unusable KDF parameters is refused before Argon2 runs`() {
        vault().setup(passphrase.toCharArray(), actor)
        val file = File(dir, "vault.json")

        // Without the check this would allocate about 4 GB and kill the process.
        file.writeText(file.readText().replace(Regex("\"memKiB\": *\\d+"), "\"memKiB\": 4000000"))
        val tooBig = vault().unlock(passphrase.toCharArray(), actor)
        assertTrue(((tooBig as ResultOf2.Failure).value as UnlockError.Unusable).reason.contains("KDF"), "was: $tooBig")

        // Without the check BouncyCastle throws, which ended as an internal error instead of a message.
        file.writeText(file.readText().replace(Regex("\"memKiB\": *\\d+"), "\"memKiB\": 64").replace(Regex("\"parallelism\": *\\d+"), "\"parallelism\": 0"))
        val broken = vault().unlock(passphrase.toCharArray(), actor)
        assertIs<UnlockError.Unusable>((broken as ResultOf2.Failure).value)
    }

    @Test
    fun `a backup with unusable KDF parameters is not restored`() {
        val v = vault()
        v.setup(passphrase.toCharArray(), actor)
        val backup = v.exportEncrypted()!!.decodeToString().replace(Regex("\"memKiB\": *\\d+"), "\"memKiB\": 4000000").toByteArray()

        val freshDir = Files.createTempDirectory("dirl-restore").toFile()
        val fresh = Vault(VaultStore(freshDir), AuditLog(File(freshDir, "audit.jsonl")))
        assertTrue(fresh.restore(backup, actor).orEmpty().contains("KDF"))
        assertIs<VaultState.Uninitialized>(fresh.state)
        assertTrue(File(freshDir, "vault.json").exists().not())
    }

    @Test
    fun `the audit page reads only the end of a large log`() {
        val log = File(dir, "big-audit.jsonl")
        // About 2.5 MiB of entries, more than the tail window, so the read starts in the middle of a line.
        log.bufferedWriter().use { out ->
            repeat(12_000) { i -> out.write("""{"time":"t$i","sub":"s","name":"n","action":"LOGIN","detail":"${"x".repeat(150)}"}""" + "\n") }
        }
        assertTrue(log.length() > AuditLog.TAIL_BYTES)
        val tail = AuditLog(log).tail(50)
        assertEquals((11_999 downTo 11_950).map { "t$it" }, tail.map { it.time })
    }

    @Test
    fun `passphrase policy accepts long phrases and Diceware words`() {
        assertNull(checkPassphrase("a".repeat(20).toCharArray()))
        assertNull(checkPassphrase("tug-fox-elm-jar-ivy".toCharArray()))
        assertTrue(checkPassphrase("tug-tug-tug-tug-tug".toCharArray()) != null)
        assertTrue(checkPassphrase("Sh0rt!".toCharArray()) != null)
    }
}
