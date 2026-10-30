package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.auth.RevokeError
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.dev.MockOidcProvider
import bayern.kickner.dirl.dev.MockUser
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.http.contentType
import io.ktor.http.Headers
import io.ktor.http.ContentType
import io.ktor.client.request.setBody
import io.ktor.client.request.post
import io.ktor.client.request.forms.submitFormWithBinaryData
import io.ktor.client.request.forms.formData
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotnexlib.ResultOf2
import java.io.File
import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The complete login against the mock provider, plus access control around it. */
class LoginFlowTest {
    private val ada = MockUser("dev-ada", "Ada Lovelace")
    private val bob = MockUser("dev-bob", "Bob Builder")
    private val mock = MockOidcProvider(autoLogin = ada)
    private val dataDir: File = Files.createTempDirectory("dirl-login").toFile()
    private val dirl = createDirl(
        AppConfig(
            publicUrl = "https://ssh.example.com",
            dataDir = dataDir.absolutePath,
            oidc = OidcConfig(issuer = mock.issuer, clientId = "dirl", clientSecret = mock.clientSecret),
        ),
        dataDir,
    )
    private val jdk = java.net.http.HttpClient.newBuilder().followRedirects(java.net.http.HttpClient.Redirect.NEVER).build()

    @AfterTest
    fun close() = mock.close()

    /**
     * Runs the browser's part of the flow: start, provider, callback.
     *
     * @return the session cookie value, or `null` if the callback did not create a session.
     */
    private suspend fun login(client: HttpClient, user: MockUser): Pair<HttpStatusCode, String?> {
        mock.autoLogin = user
        val start = client.get("/auth/start")
        assertEquals(HttpStatusCode.Found, start.status)
        val loginCookie = start.headers.getAll(HttpHeaders.SetCookie)!!.first { it.startsWith(LOGIN_COOKIE) }.substringBefore(';')
        assertTrue(loginCookie.contains("SameSite").not())

        val provider = jdk.send(HttpRequest.newBuilder(URI(start.headers[HttpHeaders.Location]!!)).build(), HttpResponse.BodyHandlers.discarding())
        val callback = URI(provider.headers().firstValue("Location").get())
        assertEquals("/auth/callback", callback.path)

        val result = client.get("${callback.path}?${callback.rawQuery}") { header(HttpHeaders.Cookie, loginCookie) }
        val session = result.headers.getAll(HttpHeaders.SetCookie).orEmpty()
            .firstOrNull { it.startsWith("$SESSION_COOKIE=") && it.startsWith("$SESSION_COOKIE=;").not() }
        if (session != null) {
            assertTrue(session.contains("SameSite=Strict") && session.contains("Secure") && session.contains("HttpOnly"), session)
        }
        return result.status to session?.substringBefore(';')
    }

    @Test
    fun `the first user sets up the vault, others need to be allowed`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }

        val (status, adaCookie) = login(client, ada)
        assertEquals(HttpStatusCode.OK, status)
        assertNotNull(adaCookie, "bootstrap login must create a session")
        assertEquals("/unlock", client.get("/") { header(HttpHeaders.Cookie, adaCookie) }.headers[HttpHeaders.Location])

        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor(ada.sub, ada.name))
        assertEquals(HttpStatusCode.OK, client.get("/") { header(HttpHeaders.Cookie, adaCookie) }.status)

        val (bobStatus, bobCookie) = login(client, bob)
        assertEquals(HttpStatusCode.Forbidden, bobStatus)
        assertEquals(null, bobCookie)
        assertEquals(listOf(bob.sub), dirl.access.requests.map { it.sub })

        dirl.access.allow(bob.sub, bob.name, Actor(ada.sub, ada.name))
        val (_, bobAllowed) = login(client, bob)
        assertNotNull(bobAllowed)
        assertEquals(HttpStatusCode.OK, client.get("/") { header(HttpHeaders.Cookie, bobAllowed) }.status)

        // Revoking ends Bob's existing session on his next request.
        assertEquals(true, (dirl.access.revoke(bob.sub, Actor(ada.sub, ada.name)) as ResultOf2.Success).value)
        assertEquals("/login", client.get("/") { header(HttpHeaders.Cookie, bobAllowed) }.headers[HttpHeaders.Location])
        assertEquals(RevokeError.LastUser, (dirl.access.revoke(ada.sub, Actor(ada.sub, ada.name)) as ResultOf2.Failure).value)
        // Removing somebody who is not in the list changes nothing and leaves no audit entry.
        val audited = dirl.audit.tail().size
        assertEquals(false, (dirl.access.revoke("nobody", Actor(ada.sub, ada.name)) as ResultOf2.Success).value)
        assertEquals(audited, dirl.audit.tail().size)
    }

    @Test
    fun `with allowedSubjects only those users may set up the vault`(): Unit = testApplication {
        val otherDir = Files.createTempDirectory("dirl-bootstrap").toFile()
        val restricted = createDirl(
            AppConfig(
                publicUrl = "https://ssh.example.com",
                dataDir = otherDir.absolutePath,
                oidc = OidcConfig(issuer = mock.issuer, clientId = "dirl", clientSecret = mock.clientSecret, allowedSubjects = listOf(ada.sub)),
            ),
            otherDir,
        )
        application { dirlModule(restricted) }
        val client = createClient { followRedirects = false }

        // Bob passes the provider but is not on the list, so he gets no session and cannot reach /setup.
        val (bobStatus, bobCookie) = login(client, bob)
        assertEquals(HttpStatusCode.Forbidden, bobStatus)
        assertEquals(null, bobCookie)
        assertEquals(listOf(bob.sub), restricted.access.requests.map { it.sub })

        val (adaStatus, adaCookie) = login(client, ada)
        assertEquals(HttpStatusCode.OK, adaStatus)
        assertNotNull(adaCookie)
        assertTrue(client.get("/unlock") { header(HttpHeaders.Cookie, adaCookie) }.bodyAsText().contains("Create vault"))
    }

    @Test
    fun `a wrong client secret creates no session`(): Unit = testApplication {
        val otherDir = Files.createTempDirectory("dirl-secret").toFile()
        val wrong = createDirl(
            AppConfig(publicUrl = "https://ssh.example.com", dataDir = otherDir.absolutePath, oidc = OidcConfig(issuer = mock.issuer, clientId = "dirl", clientSecret = "not-the-secret")),
            otherDir,
        )
        application { dirlModule(wrong) }
        val (_, cookie) = login(createClient { followRedirects = false }, ada)
        assertEquals(null, cookie, "the provider must refuse the code without the right secret")
    }

    @Test
    fun `while sealed only users from the mirror reach the unlock page`(): Unit = testApplication {
        application { dirlModule(dirl) }
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor(ada.sub, ada.name))
        dirl.vault.seal(Actor(ada.sub, ada.name))
        val client = createClient { followRedirects = false }

        val (_, adaCookie) = login(client, ada)
        assertNotNull(adaCookie)
        assertTrue(client.get("/unlock") { header(HttpHeaders.Cookie, adaCookie) }.bodyAsText().contains("Unlock vault"))
        assertEquals(HttpStatusCode.Forbidden, login(client, bob).first)
    }

    @Test
    fun `restoring a backup leads to the unlock page and unlocks`(): Unit = testApplication {
        val sourceDir = Files.createTempDirectory("dirl-source").toFile()
        val source = createDirl(AppConfig(publicUrl = "https://ssh.example.com", dataDir = sourceDir.absolutePath, oidc = OidcConfig(issuer = mock.issuer, clientId = "dirl", clientSecret = mock.clientSecret)), sourceDir)
        val passphrase = "correct horse battery staple extra"
        source.vault.setup(passphrase.toCharArray(), Actor(ada.sub, ada.name))
        val backup = source.vault.exportEncrypted()!!

        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        val (_, cookie) = login(client, ada)
        assertNotNull(cookie)
        val headers: io.ktor.client.request.HttpRequestBuilder.() -> Unit = {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        val restore = client.submitFormWithBinaryData("/setup/restore", formData {
            append("backup", backup, Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"vault.json\"") })
        }, block = headers)
        assertEquals("/unlock?done=restored", restore.headers[HttpHeaders.Location])
        assertTrue(client.get("/unlock") { header(HttpHeaders.Cookie, cookie) }.bodyAsText().contains("Unlock vault"))

        val unlock = client.post("/unlock") {
            headers()
            contentType(ContentType.Application.FormUrlEncoded)
            setBody("passphrase=" + passphrase.replace(" ", "+"))
        }
        assertEquals("/", unlock.headers[HttpHeaders.Location])
        assertEquals(HttpStatusCode.OK, client.get("/") { header(HttpHeaders.Cookie, cookie) }.status)
    }

    @Test
    fun `anonymous login starts cannot block the login`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        repeat(1500) { assertEquals(HttpStatusCode.Found, client.get("/auth/start").status) }
        val (status, cookie) = login(client, ada)
        assertEquals(HttpStatusCode.OK, status)
        assertNotNull(cookie)
    }

    @Test
    fun `a tampered login cookie is rejected`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        val start = client.get("/auth/start")
        val loginCookie = start.headers.getAll(HttpHeaders.SetCookie)!!.first { it.startsWith(LOGIN_COOKIE) }.substringBefore(';')
        val provider = jdk.send(HttpRequest.newBuilder(URI(start.headers[HttpHeaders.Location]!!)).build(), HttpResponse.BodyHandlers.discarding())
        val callback = URI(provider.headers().firstValue("Location").get())
        val url = "${callback.path}?${callback.rawQuery}"
        // Flip one character of the signed payload: the signature no longer matches.
        val value = loginCookie.substringAfter('=')
        val forged = "$LOGIN_COOKIE=" + value.replaceRange(3, 4, if (value[3] == 'A') "B" else "A")
        assertEquals(HttpStatusCode.Forbidden, client.get(url) { header(HttpHeaders.Cookie, forged) }.status)
        // The genuine cookie still works, so the rejection above came from the signature.
        assertEquals(HttpStatusCode.OK, client.get(url) { header(HttpHeaders.Cookie, loginCookie) }.status)
    }

    @Test
    fun `a replayed callback is rejected`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        val start = client.get("/auth/start")
        val loginCookie = start.headers.getAll(HttpHeaders.SetCookie)!!.first { it.startsWith(LOGIN_COOKIE) }.substringBefore(';')
        val provider = jdk.send(HttpRequest.newBuilder(URI(start.headers[HttpHeaders.Location]!!)).build(), HttpResponse.BodyHandlers.discarding())
        val callback = URI(provider.headers().firstValue("Location").get())
        val url = "${callback.path}?${callback.rawQuery}"

        assertEquals(HttpStatusCode.OK, client.get(url) { header(HttpHeaders.Cookie, loginCookie) }.status)
        assertEquals(HttpStatusCode.Forbidden, client.get(url) { header(HttpHeaders.Cookie, loginCookie) }.status)
        // Without the login cookie of this browser the callback is worthless.
        assertEquals(HttpStatusCode.Forbidden, client.get(url).status)
    }
}
