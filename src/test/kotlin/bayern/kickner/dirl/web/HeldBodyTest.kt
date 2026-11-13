package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Requests whose body arrives after the user was removed or logged out, on a real CIO server: the guards checked the
 * headers while access still existed, the action must not happen anyway.
 */
class HeldBodyTest {
    private val dir = Files.createTempDirectory("dirl-held").toFile()
    private val admin = Actor("admin", "Admin")
    private val mallory = Actor("mallory", "Mallory")
    private val dirl = createDirl(
        AppConfig(
            publicUrl = "https://ssh.example.com",
            dataDir = dir.absolutePath,
            oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret", allowedSubjects = listOf(admin.sub)),
        ),
        dir,
    ).also {
        it.vault.setup("correct horse battery staple extra".toCharArray(), admin)
        it.access.allow(mallory.sub, mallory.name, admin)
    }

    @AfterTest
    fun cleanUp() {
        dir.deleteRecursively()
    }

    /**
     * Sends the head of a POST to [path] as [mallory], waits, runs [meanwhile] and only then sends [body].
     *
     * @return the status line of the answer.
     */
    private fun heldPost(path: String, contentType: String, body: String, meanwhile: () -> Unit): String {
        val token = dirl.sessions.create(mallory).token
        val server = embeddedServer(CIO, port = 0, host = "127.0.0.1") { dirlModule(dirl) }.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().first().port }
            return Socket("127.0.0.1", port).use { socket ->
                socket.soTimeout = 10_000
                val out = socket.getOutputStream()
                out.write(
                    ("POST $path HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://ssh.example.com\r\nCookie: $SESSION_COOKIE=$token\r\n" +
                        "Connection: close\r\nContent-Type: $contentType\r\nContent-Length: ${body.toByteArray().size}\r\n\r\n").toByteArray()
                )
                out.flush()
                Thread.sleep(500)
                meanwhile()
                out.write(body.toByteArray())
                out.flush()
                val answer = ByteArrayOutputStream()
                runCatching { socket.getInputStream().copyTo(answer) }
                answer.toString(Charsets.UTF_8).lineSequence().first()
            }
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test
    fun `a removed user cannot grant access with a request held back over the removal`() {
        dirl.access.recordRequest("mallory-2", "Mallory Two")
        val answer = heldPost("/settings/users/allow", "application/x-www-form-urlencoded", "sub=mallory-2") {
            dirl.access.revoke(mallory.sub, admin)
            dirl.sessions.removeAllFor(mallory.sub)
        }
        assertTrue(answer.startsWith("HTTP/1.1 401"), answer)
        assertFalse(dirl.access.isAllowed("mallory-2"), "the second identity must not get access")
        assertTrue(dirl.access.requests.any { it.sub == "mallory-2" }, "the request stays open for the others")
    }

    @Test
    fun `allow decides again whether the actor is still allowed`() {
        dirl.access.revoke(mallory.sub, admin)
        assertFalse(dirl.access.allow("mallory-2", "Mallory Two", mallory))
        assertFalse(dirl.access.isAllowed("mallory-2"))
    }

    @Test
    fun `a snippet import that arrives after the logout shows nothing`() {
        val body = "--B\r\nContent-Disposition: form-data; name=\"json\"\r\n\r\n{\"snippets\":[]}\r\n--B--\r\n"
        val answer = heldPost("/snippets/import", "multipart/form-data; boundary=B", body) { dirl.sessions.removeAllFor(mallory.sub) }
        assertTrue(answer.startsWith("HTTP/1.1 401"), answer)
    }

    @Test
    fun `a request held back without any removal still works`() {
        dirl.access.recordRequest("bob", "Bob")
        val answer = heldPost("/settings/users/allow", "application/x-www-form-urlencoded", "sub=bob") { }
        assertTrue(answer.startsWith("HTTP/1.1 302"), answer)
        assertTrue(dirl.access.isAllowed("bob"))
        assertEquals(setOf(admin.sub, mallory.sub, "bob"), dirl.vault.content!!.settings.allowedUsers.map { it.sub }.toSet())
    }
}
