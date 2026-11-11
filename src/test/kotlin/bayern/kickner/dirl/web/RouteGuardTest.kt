package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.server.application.plugin
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.RoutingRoot
import io.ktor.server.routing.getAllRoutes
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import java.net.Socket
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Checks every route of [dirlModule] against the guards of [installGuards], read from Ktor's routing tree. A new route
 * is covered without touching this test, also one nobody thought of protecting.
 */
class RouteGuardTest {
    private val origin = "https://ssh.example.com"
    private val passphrase = "correct horse battery staple extra"
    private val actor = Actor("user-1", "Ada")
    private val dataDir = Files.createTempDirectory("dirl-routes").toFile()
    private val dirl = createDirl(
        AppConfig(publicUrl = origin, dataDir = dataDir.absolutePath, oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret")),
        dataDir,
    )

    /** Reachable without a session, the same list as in [installGuards]. */
    private val publicPaths = setOf("/login", "/auth/start", "/auth/callback", "/healthz")

    /** Reachable with a session while the vault is sealed, the same list as in [installGuards]. */
    private val sealedAllowed = setOf("/unlock", "/setup", "/setup/restore", "/logout")

    /** The headers every answer carries, see [installGuards]. */
    private val securityHeaders = listOf(
        "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", HttpHeaders.CacheControl,
        "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Permissions-Policy", "Strict-Transport-Security",
    )

    /**
     * Method and path of a route, path parameters replaced by `x` and selectors dropped: `/hosts/{id}/files/(method:POST)`
     * is `POST /hosts/x/files`, `/ws/presence/(header:Upgrade = websocket)/(method:GET)` is `GET /ws/presence`.
     */
    private data class Endpoint(val method: HttpMethod, val path: String) {
        override fun toString() = "${method.value} $path"
    }

    private fun endpointsOf(routes: List<String>): List<Endpoint> = routes.mapNotNull { route ->
        val method = methodSelector.find(route)?.groupValues?.get(1) ?: return@mapNotNull null
        val path = route.replace(selector, "").replace(pathParameter, "x").ifEmpty { "/" }
        Endpoint(HttpMethod.parse(method), path)
    }.distinct()

    @Test
    fun `every route needs a session of an allowed user, the own origin and an unlocked vault`(): Unit = testApplication {
        dirl.vault.setup(passphrase.toCharArray(), actor)
        var routes = emptyList<String>()
        application {
            dirlModule(dirl)
            routes = plugin(RoutingRoot).getAllRoutes().map { it.toString() }
        }
        startApplication()
        val endpoints = endpointsOf(routes).filter { it.path !in publicPaths && it.path.startsWith("/static/").not() }
        // Guards against a change in Ktor's route names that would silently leave nothing to check.
        assertTrue(endpoints.size >= 50, "only ${endpoints.size} routes found in $routes")
        assertTrue(Endpoint(HttpMethod.Post, "/hosts/x/files/upload") in endpoints && Endpoint(HttpMethod.Get, "/ws/terminal/x") in endpoints, endpoints.toString())

        val client = createClient { followRedirects = false }
        suspend fun send(endpoint: Endpoint, cookie: String?, withOrigin: String?): HttpResponse = client.request(endpoint.path) {
            method = endpoint.method
            cookie?.let { header(HttpHeaders.Cookie, it) }
            withOrigin?.let { header(HttpHeaders.Origin, it) }
        }
        val problems = mutableListOf<String>()
        fun expect(label: String, endpoint: Endpoint, response: HttpResponse, ok: Boolean) {
            if (ok.not()) problems += "$label $endpoint: ${response.status.value} ${response.headers[HttpHeaders.Location].orEmpty()}"
            val missing = securityHeaders.filter { response.headers[it] == null }
            if (missing.isNotEmpty()) problems += "$label $endpoint: missing $missing"
        }
        fun HttpResponse.redirectsTo(path: String) = status.value == 302 && headers[HttpHeaders.Location] == path

        val allowed = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"
        for (endpoint in endpoints) {
            val isGet = endpoint.method == HttpMethod.Get
            // Posts carry the own origin here, so only the login check can stop them.
            val ownOrigin = if (isGet) null else origin
            val anonymous = send(endpoint, null, ownOrigin)
            expect("without session", endpoint, anonymous, if (isGet) anonymous.redirectsTo("/login") else anonymous.status.value == 401)
            // A fresh session each time: the guard ends the session of a user without access on first use.
            val stranger = send(endpoint, "$SESSION_COOKIE=${dirl.sessions.create(Actor("intruder", "Ada")).token}", ownOrigin)
            expect("user without access", endpoint, stranger, if (isGet) stranger.redirectsTo("/login") else stranger.status.value == 401)
            if (isGet.not()) {
                val foreign = send(endpoint, allowed, "https://evil.example")
                expect("foreign origin", endpoint, foreign, foreign.status.value == 403)
                val noOrigin = send(endpoint, allowed, null)
                expect("no origin", endpoint, noOrigin, noOrigin.status.value == 403)
            }
        }

        dirl.vault.seal(actor)
        val sealed = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"
        for (endpoint in endpoints.filter { it.path !in sealedAllowed }) {
            val isGet = endpoint.method == HttpMethod.Get
            val response = send(endpoint, sealed, if (isGet) null else origin)
            expect("sealed vault", endpoint, response, if (isGet) response.redirectsTo("/unlock") else response.status.value == 423)
        }
        assertEquals(emptyList(), problems)
    }

    @Test
    fun `no WebSocket upgrade passes without the own origin, on the real engine`() {
        // The test client refuses to set Upgrade itself, so the handshake goes over a plain socket to CIO.
        dirl.vault.setup(passphrase.toCharArray(), actor)
        val server = embeddedServer(CIO, port = 0, host = "127.0.0.1") { dirlModule(dirl) }.start(wait = false)
        try {
            val routes = server.application.plugin(RoutingRoot).getAllRoutes().map { it.toString() }
            val gets = endpointsOf(routes).filter { it.method == HttpMethod.Get && it.path !in publicPaths && it.path.startsWith("/static/").not() }
            assertTrue(gets.size >= 20, gets.toString())
            val port = runBlocking { server.engine.resolvedConnectors().first().port }
            val token = dirl.sessions.create(actor).token
            fun statusLine(path: String, withOrigin: String?): String = Socket("127.0.0.1", port).use { socket ->
                socket.soTimeout = 5000
                val request = "GET $path HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: $SESSION_COOKIE=$token\r\nUpgrade: websocket\r\n" +
                    "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
                    withOrigin?.let { "Origin: $it\r\n" }.orEmpty() + "\r\n"
                socket.getOutputStream().write(request.toByteArray())
                socket.getInputStream().bufferedReader().readLine().orEmpty()
            }
            val problems = gets.flatMap { endpoint ->
                listOf(null, "https://evil.example").mapNotNull { withOrigin ->
                    statusLine(endpoint.path, withOrigin).takeIf { it.startsWith("HTTP/1.1 403").not() }?.let { "$endpoint origin=$withOrigin: $it" }
                }
            }
            assertEquals(emptyList(), problems)
            // The real sockets still open with the own origin, so the refusals above are not a broken handshake.
            assertTrue(statusLine("/ws/presence", origin).startsWith("HTTP/1.1 101"))
            assertTrue(statusLine("/ws/terminal/x", origin).startsWith("HTTP/1.1 101"))
        } finally {
            server.stop(100, 1000)
        }
    }
}

private val methodSelector = "\\(method:(\\w+)\\)".toRegex()
private val selector = "/?\\([^)]*\\)".toRegex()
private val pathParameter = "\\{[^}]+}".toRegex()
