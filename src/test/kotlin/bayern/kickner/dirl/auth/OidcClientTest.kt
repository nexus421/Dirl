package bayern.kickner.dirl.auth

import bayern.kickner.dirl.config.OidcConfig
import com.sun.net.httpserver.HttpServer
import kotnexlib.ResultOf2
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Anonymous login requests must not turn into unbounded load on the provider or on Dirl's threads. */
class OidcClientTest {
    private val hits = AtomicInteger()
    private val inFlight = AtomicInteger()
    private val maxInFlight = AtomicInteger()
    private var delayMillis = 0L
    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
        executor = Executors.newCachedThreadPool()
        createContext("/.well-known/openid-configuration") { ex ->
            hits.incrementAndGet()
            maxInFlight.accumulateAndGet(inFlight.incrementAndGet(), ::maxOf)
            Thread.sleep(delayMillis)
            inFlight.decrementAndGet()
            ex.sendResponseHeaders(500, -1)
            ex.close()
        }
        start()
    }
    private var now = 1_000_000L
    private val client = OidcClient(
        OidcConfig(issuer = "http://localhost:${server.address.port}", clientId = "dirl", clientSecret = "secret"),
        "https://ssh.example.com/auth/callback",
        clock = { now },
    )

    @AfterTest
    fun stop() = server.stop(0)

    @Test
    fun `a failing provider is asked again only after a pause`() {
        repeat(20) { assertIs<ResultOf2.Failure<LoginError>>(client.startLogin()) }
        assertEquals(1, hits.get())
        now += 16_000
        client.startLogin()
        assertEquals(2, hits.get())
    }

    @Test
    fun `a slow provider holds at most a few threads`() {
        delayMillis = 2_000
        // Twelve logins at once against a provider that takes two seconds to answer.
        val shared = OidcClient(OidcConfig(issuer = "http://localhost:${server.address.port}", clientId = "dirl", clientSecret = "secret"), "https://x/cb")
        val sharedThreads = (1..12).map { thread { shared.startLogin() } }
        sharedThreads.forEach { it.join() }
        assertTrue(maxInFlight.get() <= OidcClient.MAX_CONCURRENT_PROVIDER_CALLS, "max in flight was ${maxInFlight.get()}")
    }
}
