package bayern.kickner.dirl.auth

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import kotnexlib.ResultOf2
import java.io.File
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AccessControlTest {
    private val dataDir = Files.createTempDirectory("dirl-access").toFile()
    private val dirl = createDirl(
        AppConfig(
            publicUrl = "https://ssh.example.com",
            dataDir = dataDir.absolutePath,
            oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret"),
        ),
        File(dataDir.absolutePath),
    )
    private val ada = Actor("ada", "Ada")

    private fun allowedSubs() = dirl.vault.content!!.settings.allowedUsers.map { it.sub }.toSet()

    /**
     * Revokes [subs] so that every call reads the user list before any of them writes: a helper holds the vault lock
     * until all revoking threads wait for that lock. The threads are daemons and the lock is always released, so a
     * failing test cannot hang the test run.
     */
    private fun revokeAtOnce(vararg subs: String): Map<String, ResultOf2<*, RevokeError>> {
        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holder = thread(isDaemon = true) { dirl.vault.update { held.countDown(); release.await(); it } }
        val results = ConcurrentHashMap<String, ResultOf2<*, RevokeError>>()
        val revokers = mutableListOf<Thread>()
        try {
            assertTrue(held.await(5, TimeUnit.SECONDS))
            subs.mapTo(revokers) { sub -> thread(isDaemon = true) { results[sub] = dirl.access.revoke(sub, ada) } }
            // BLOCKED alone could also be a class loading monitor, the owner of the awaited lock has to be the holder.
            val threads = ManagementFactory.getThreadMXBean()
            fun waitsForHolder(t: Thread) = threads.getThreadInfo(t.threadId())?.lockOwnerId == holder.threadId()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (revokers.any { waitsForHolder(it).not() } && System.nanoTime() < deadline) Thread.sleep(5)
            assertTrue(revokers.all { waitsForHolder(it) }, "every revoke must wait for the vault lock")
        } finally {
            release.countDown()
        }
        (revokers + holder).forEach { it.join(5000) }
        return results
    }

    private fun setUp(vararg others: String) {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), ada)
        others.forEach { dirl.access.allow(it, it, ada) }
    }

    @Test
    fun `revokes at the same moment remove every user`(): Unit {
        setUp("bob", "carol")
        val results = revokeAtOnce("bob", "carol")
        assertTrue(results.values.all { it is ResultOf2.Success }, "both were reported as removed: $results")
        assertEquals(setOf("ada"), allowedSubs(), "a revoke must not bring back a user another revoke removed")
    }

    @Test
    fun `revoking the last two users at the same moment keeps one`(): Unit {
        setUp("bob")
        val results = revokeAtOnce("ada", "bob")
        assertEquals(1, allowedSubs().size, "somebody has to be able to log in")
        assertEquals(1, results.values.count { it is ResultOf2.Failure && it.value == RevokeError.LastUser }, "$results")
        val kept = allowedSubs().single()
        assertTrue(results.getValue(kept) is ResultOf2.Failure, "the kept user must not be reported as removed")
    }
}
