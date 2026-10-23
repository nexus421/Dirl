package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.nio.file.Files
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets

/** Presence through real requests: the presence WebSocket on the production engine (CIO), its guards and watchdog. */
class PresenceWebTest {
    private var now = 1_000_000L
    private val dataDir = Files.createTempDirectory("dirl-presence").toFile()
    private val config = AppConfig(
        publicUrl = "https://ssh.example.com",
        dataDir = dataDir.absolutePath,
        oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret"),
    )
    private val actor = Actor("user-1", "Ada")
    private val dirl = createDirl(config, dataDir) { now }.also {
        it.vault.setup("correct horse battery staple extra".toCharArray(), actor)
    }

    /** Runs [block] with Dirl on a real CIO server on a free port, the URL of the presence socket as argument. */
    private fun onCio(block: (String) -> Unit) {
        val server = embeddedServer(CIO, port = 0, host = "127.0.0.1") { dirlModule(dirl) }.start(wait = false)
        try {
            val port = runBlocking { server.engine.resolvedConnectors().first().port }
            block("ws://127.0.0.1:$port/ws/presence")
        } finally {
            server.stop(100, 1000)
        }
    }

    private fun connect(url: String, cookie: String?, origin: String = "https://ssh.example.com"): CompletableFuture<WebSocket> {
        val builder = HttpClient.newHttpClient().newWebSocketBuilder().header("Origin", origin)
        if (cookie != null) builder.header("Cookie", cookie)
        return builder.buildAsync(URI(url), object : WebSocket.Listener {})
    }

    /** Lets the clock run past the grace until Dirl counts as absent, which needs the handler to have ended. */
    private fun awaitAbsent(): Boolean {
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            now += 31_000
            if (dirl.presence.present.not()) return true
            Thread.sleep(50)
        }
        return false
    }

    @Test
    fun `an open presence socket keeps Dirl present on CIO, closing it ends the presence after the grace`() = onCio { url ->
        assertTrue(dirl.presence.present.not())
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"
        val socket = connect(url, cookie).get(5, TimeUnit.SECONDS)

        // The request of the open socket counts, no matter how long it is open. This is what the whole model rests on.
        now += 3_600_000
        assertTrue(dirl.presence.present, "an open WebSocket must hold the presence")

        socket.sendClose(WebSocket.NORMAL_CLOSURE, "bye").get(5, TimeUnit.SECONDS)
        assertTrue(awaitAbsent(), "after the socket closed and the grace passed, nobody is present")
    }

    @Test
    fun `the presence socket needs a session and the own origin`() = onCio { url ->
        val noSession = runCatching { connect(url, null).get(5, TimeUnit.SECONDS) }
        assertTrue(noSession.isFailure, "without a session")
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"
        val foreign = runCatching { connect(url, cookie, origin = "https://evil.example").get(5, TimeUnit.SECONDS) }
        assertTrue(foreign.isFailure, "from a foreign origin")
        assertTrue(awaitAbsent(), "rejected requests do not count as presence")
    }

    @Test
    fun `the presence socket never extends the session and closes when the session ends`(): Unit = testApplication {
        application {
            install(ServerWebSockets)
            installGuards(dirl)
            routing { presenceRoutes(dirl, checkEvery = 100.milliseconds) }
        }
        val session = dirl.sessions.create(actor)
        val seen = session.lastSeen
        val client = createClient { install(WebSockets) }
        // The overview reloads itself every minute and every reload opens a new presence socket. If opening one
        // counted, an unattended browser would never reach the idle timeout.
        now += 60_000
        client.webSocket("/ws/presence", request = {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}")
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }) {
            assertEquals(seen, session.lastSeen, "opening the presence socket must not count as activity")
            now += 60_000
            send(Frame.Text("anything"))
            send(Frame.Binary(true, byteArrayOf(1, 2, 3)))
            Thread.sleep(300)
            assertEquals(seen, session.lastSeen, "frames on the presence socket must not count as activity")

            dirl.sessions.remove(session.token)
            // The watchdog closes the socket, the loop ends instead of waiting forever.
            withTimeout(5_000) { incoming.consumeEach { } }
        }
    }
}
