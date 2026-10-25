package bayern.kickner.dirl

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.crypto.KdfParams
import bayern.kickner.dirl.vault.Vault
import bayern.kickner.dirl.vault.VaultStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UpdateCheckTest {
    private val dir: File = Files.createTempDirectory("dirl-update").toFile()
    private var now = 1_000_000L
    private val vault = Vault(
        store = VaultStore(dir),
        audit = AuditLog(File(dir, "audit.jsonl")),
        keyFile = null,
        clock = { now },
        kdfParams = { KdfParams.generate().copy(memKiB = 64, iterations = 1) },
    )
    private val scope = CoroutineScope(Dispatchers.IO)
    private val fetches = AtomicInteger()
    private var answer: () -> String? = { "0.3.0" }
    private val check = UpdateCheck(vault, clock = { now }, current = "0.2.0", fetchLatest = { fetches.incrementAndGet(); answer() })

    private fun unlock() {
        vault.setup("correct horse battery staple extra".toCharArray(), Actor("u", "U"))
    }

    private fun checkNow() = runBlocking { check.checkIfDue(scope)?.join() }

    @Test
    fun `only tags of the form v1_2_3 count as release`() {
        assertEquals("1.2.3", releaseVersion("v1.2.3"))
        assertEquals("0.10.0", releaseVersion("v0.10.0"))
        listOf("1.2.3", "v1.2", "v1.2.3-rc1", "v1.2.3\n", " v1.2.3", "v1.2.3.4", "v<b>1</b>.2.3", "", "v1..3").forEach {
            assertNull(releaseVersion(it), it)
        }
    }

    @Test
    fun `versions compare by number, not by text`() {
        assertTrue(isNewerVersion("0.10.0", "0.9.0"))
        assertTrue(isNewerVersion("1.0.0", "0.99.99"))
        assertTrue(isNewerVersion("0.2.1", "0.2.0"))
        assertFalse(isNewerVersion("0.2.0", "0.2.0"))
        assertFalse(isNewerVersion("0.1.9", "0.2.0"))
        // A build that is no plain release, for example from a branch, never asks for an update.
        assertFalse(isNewerVersion("9.9.9", "0.2.0-dev"))
        assertFalse(isNewerVersion("not a version", "0.2.0"))
    }

    @Test
    fun `the release is read from tag_name of GitHub's answer`() {
        assertEquals("0.3.0", latestReleaseOf("""{"url":"x","tag_name":"v0.3.0","name":"Dirl 0.3.0","assets":[]}""".toByteArray()))
        assertNull(latestReleaseOf("""{"name":"v0.3.0"}""".toByteArray()), "no tag_name")
        assertNull(latestReleaseOf("""{"tag_name":"<script>"}""".toByteArray()), "not a version")
        assertNull(latestReleaseOf("""{"tag_name":3}""".toByteArray()), "wrong type")
        assertNull(latestReleaseOf("not json".toByteArray()))
        assertNull(latestReleaseOf(null), "too large or unreadable")
    }

    @Test
    fun `an answer larger than the limit is not read to the end`() {
        val huge = ByteArrayInputStream(ByteArray(MAX_RELEASE_ANSWER_BYTES + 1) { 'a'.code.toByte() })
        assertNull(readReleaseAnswer(huge))
        assertEquals("0.3.0", readReleaseAnswer(ByteArrayInputStream("""{"tag_name":"v0.3.0"}""".toByteArray())))
    }

    @Test
    fun `nothing is asked while the vault is not unlocked`() {
        checkNow()
        assertEquals(0, fetches.get())
        assertNull(check.available())
    }

    @Test
    fun `GitHub is asked at most once an hour and only when a page asks`() {
        unlock()
        checkNow()
        assertEquals(1, fetches.get())
        assertEquals("0.3.0", check.available())

        now += UPDATE_CHECK_INTERVAL_MILLIS - 1
        checkNow()
        assertEquals(1, fetches.get(), "not again within the hour")

        now += 1
        checkNow()
        assertEquals(2, fetches.get(), "again after an hour")
    }

    @Test
    fun `a failed check waits an hour as well and keeps the last known release`() {
        unlock()
        checkNow()
        answer = { error("GitHub unreachable") }
        now += UPDATE_CHECK_INTERVAL_MILLIS
        checkNow()
        assertEquals(2, fetches.get())
        assertEquals("0.3.0", check.available(), "a failure does not forget the release")
        checkNow()
        assertEquals(2, fetches.get(), "no retry right after a failure")
    }

    @Test
    fun `turned off in the settings nothing is asked and nothing shown`() {
        unlock()
        checkNow()
        vault.update { it.copy(settings = it.settings.copy(updateCheck = false)) }
        now += UPDATE_CHECK_INTERVAL_MILLIS
        checkNow()
        assertEquals(1, fetches.get())
        assertNull(check.available(), "a release found before is not shown any more")
    }

    @Test
    fun `the running version or an older release is no update`() {
        unlock()
        answer = { "0.2.0" }
        checkNow()
        assertNull(check.available())
        answer = { "0.1.0" }
        now += UPDATE_CHECK_INTERVAL_MILLIS
        checkNow()
        assertNull(check.available())
    }

    @Test
    fun `many pages at the same moment ask GitHub once`() {
        unlock()
        val start = CountDownLatch(1)
        val jobs = (1..20).map { thread { start.await(); runBlocking { check.checkIfDue(scope)?.join() } } }
        start.countDown()
        jobs.forEach { it.join(5000) }
        assertEquals(1, fetches.get())
    }
}
