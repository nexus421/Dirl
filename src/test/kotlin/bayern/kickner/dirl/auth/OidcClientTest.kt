package bayern.kickner.dirl.auth

import bayern.kickner.dirl.config.OidcConfig
import com.sun.net.httpserver.HttpServer
import kotnexlib.ResultOf2
import java.net.InetSocketAddress
import java.net.URI
import java.util.concurrent.CountDownLatch
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

    @Test
    fun `a replayed login cookie does not make callbacks wait for a slot`() {
        // Anybody can get a login cookie from /auth/start and replay it with made-up codes for ten minutes.
        val release = CountDownLatch(1)
        val tokenCalls = AtomicInteger()
        val provider = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val issuer = "http://localhost:${provider.address.port}"
        provider.executor = Executors.newCachedThreadPool()
        provider.createContext("/.well-known/openid-configuration") { ex ->
            val doc = """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token"}""".toByteArray()
            ex.sendResponseHeaders(200, doc.size.toLong())
            ex.responseBody.use { it.write(doc) }
        }
        provider.createContext("/token") { ex ->
            tokenCalls.incrementAndGet()
            release.await()
            ex.sendResponseHeaders(400, -1)
            ex.close()
        }
        provider.start()
        try {
            val client = OidcClient(OidcConfig(issuer = issuer, clientId = "dirl", clientSecret = "secret"), "https://x/cb")
            val start = assertIs<ResultOf2.Success<LoginStart>>(client.startLogin()).value
            val state = URI(start.redirectUrl).query.split('&').first { it.startsWith("state=") }.removePrefix("state=")
            val replay = { client.finishLogin(start.cookie, state, "made-up", null, null) }

            val holders = (1..OidcClient.MAX_CONCURRENT_PROVIDER_CALLS).map { thread { replay() } }
            while (tokenCalls.get() < OidcClient.MAX_CONCURRENT_PROVIDER_CALLS) Thread.sleep(10)

            // All slots are taken, the next callback must fail at once instead of holding its thread.
            val started = System.nanoTime()
            val result = replay()
            val waitedMillis = (System.nanoTime() - started) / 1_000_000
            val error = assertIs<LoginError.InvalidToken>(assertIs<ResultOf2.Failure<LoginError>>(result).value)
            assertTrue(error.reason.startsWith("Too many concurrent"), error.reason)
            assertTrue(waitedMillis < 500, "callback waited $waitedMillis ms for a slot")

            release.countDown()
            holders.forEach { it.join() }
        } finally {
            release.countDown()
            provider.stop(0)
        }
    }
}
