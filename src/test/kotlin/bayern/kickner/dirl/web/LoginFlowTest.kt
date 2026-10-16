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
            oidc = OidcConfig(issuer = mock.issuer, clientId = "dirl"),
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
        assertIs<ResultOf2.Success<Unit>>(dirl.access.revoke(bob.sub, Actor(ada.sub, ada.name)))
        assertEquals("/login", client.get("/") { header(HttpHeaders.Cookie, bobAllowed) }.headers[HttpHeaders.Location])
        assertEquals(RevokeError.LastUser, (dirl.access.revoke(ada.sub, Actor(ada.sub, ada.name)) as ResultOf2.Failure).value)
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
