package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.ssh.ConnectionState
import bayern.kickner.dirl.ssh.DiskUsage
import bayern.kickner.dirl.ssh.RawMetrics
import bayern.kickner.dirl.ssh.RebootStatus
import bayern.kickner.dirl.ssh.generateEd25519Key
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.OverviewMetric
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.parameters
import io.ktor.http.parametersOf
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotnexlib.ResultOf2
import java.net.ServerSocket
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** The host overview: pins, order, the rows and the arrange page. */
class HostOverviewTest {
    private val actor = Actor("user-1", "Ada")
    private val dataDir = Files.createTempDirectory("dirl-overview").toFile()
    private val dirl = createDirl(
        AppConfig(
            publicUrl = "https://ssh.example.com",
            dataDir = dataDir.absolutePath,
            oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret"),
        ),
        dataDir,
    )
    private val key = generateEd25519Key("k")

    init {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), actor)
    }

    private fun host(id: String, pinned: Boolean = false, tags: List<String> = emptyList()) =
        Host(id = id, name = "host-$id", address = "10.0.0.1", username = "u", keyId = key.id, pinned = pinned, tags = tags)

    private fun hosts(vararg hosts: Host) = dirl.vault.update { it.copy(keys = listOf(key), hosts = hosts.toList()) }

    private fun names() = dirl.vault.content!!.hosts.map { it.id }

    private class Browser(val client: HttpClient, val cookie: String)

    private fun ApplicationTestBuilder.browser(): Browser {
        application { dirlModule(dirl) }
        return Browser(createClient { followRedirects = false }, "$SESSION_COOKIE=${dirl.sessions.create(actor).token}")
    }

    private suspend fun Browser.page(path: String = "/") = client.get(path) { header(HttpHeaders.Cookie, cookie) }.bodyAsText()

    private suspend fun Browser.post(path: String, form: Parameters, origin: String = "https://ssh.example.com"): HttpResponse =
        client.submitForm(path, form) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, origin)
        }

    /** Host names in each group of the overview, in page order. Each piece of the split holds one group. */
    private fun groups(page: String): List<List<String>> = page.split("<div class=\"host-list\">").drop(1).map { group ->
        Regex("class=\"host-name\">([^<]+)</a>").findAll(group.substringBefore("<footer")).map { it.groupValues[1] }.toList()
    }

    /** The row of the host named [name]. */
    private fun rowOf(page: String, name: String): String = page.split("class=\"host-row ").drop(1).first { it.contains(">$name</a>") }

    @Test
    fun `pinned hosts come first, both groups keep the order of the vault, the divider only shows with both`(): Unit = testApplication {
        hosts(host("c"), host("a", pinned = true), host("b"), host("d", pinned = true))
        val browser = browser()
        val page = browser.page()
        assertEquals(listOf(listOf("host-a", "host-d"), listOf("host-c", "host-b")), groups(page))
        assertTrue(page.contains(">Pinned</div>") && page.contains(">Other hosts</div>"))

        hosts(host("c"), host("b"))
        val plain = browser.page()
        assertEquals(listOf(listOf("host-c", "host-b")), groups(plain), "not sorted by name any more")
        assertFalse(plain.contains("Pinned") || plain.contains("Other hosts"), "no groups without a pin")

        hosts(host("a", pinned = true))
        assertFalse(browser.page().contains("Other hosts"), "no divider without other hosts")
    }

    @Test
    fun `pinning keeps the tag filter, survives editing and needs the own origin`(): Unit = testApplication {
        hosts(host("a", tags = listOf("prod")), host("b", tags = listOf("prod")))
        val browser = browser()
        val pinned = browser.post("/hosts/b/pinned", parametersOf("pinned" to listOf("true"), "tag" to listOf("prod")))
        assertEquals("/?tag=prod", pinned.headers[HttpHeaders.Location])
        assertTrue(dirl.vault.content!!.host("b")!!.pinned)
        assertEquals(listOf(listOf("host-b"), listOf("host-a")), groups(browser.page("/?tag=prod")))
        assertTrue(dirl.audit.tail().any { it.action == AuditAction.HOST_UPDATED && it.detail == "pinned" })

        // A tag that does not exist does not go into the redirect.
        val unknownTag = browser.post("/hosts/b/pinned", parametersOf("pinned" to listOf("true"), "tag" to listOf("nope\r\nX: y")))
        assertEquals("/", unknownTag.headers[HttpHeaders.Location])

        val edited = browser.post("/hosts/b", parameters {
            append("name", "renamed"); append("address", "10.0.0.2"); append("port", "22"); append("username", "u"); append("keyId", key.id)
        })
        assertEquals(HttpStatusCode.Found, edited.status)
        assertTrue(dirl.vault.content!!.host("b")!!.pinned, "editing a host must not drop its pin")

        assertEquals(HttpStatusCode.Forbidden, browser.post("/hosts/b/pinned", parametersOf("pinned" to listOf("false")), origin = "https://evil.example.com").status)
        assertTrue(dirl.vault.content!!.host("b")!!.pinned)
        browser.post("/hosts/b/pinned", parametersOf("pinned" to listOf("false")))
        assertFalse(dirl.vault.content!!.host("b")!!.pinned)
        assertEquals(HttpStatusCode.NotFound, browser.post("/hosts/nope/pinned", parametersOf("pinned" to listOf("true"))).status)
    }

    @Test
    fun `the arrange form orders by number, equal and missing numbers keep their place`() {
        val list = listOf(host("a"), host("b"), host("c"), host("d"))
        fun order(vararg fields: Pair<String, String>) =
            (parseArrangeForm(parametersOf(*fields.map { "pos-${it.first}" to listOf(it.second) }.toTypedArray()), list) as ResultOf2.Success).value
        assertEquals(listOf("d", "a", "b", "c"), order("a" to "2", "b" to "3", "c" to "4", "d" to "1"))
        assertEquals(listOf("a", "c", "b", "d"), order("a" to "1", "b" to "3", "c" to "2", "d" to "4"))
        assertEquals(listOf("b", "a", "c", "d"), order("a" to "3", "b" to "1", "c" to "3", "d" to "9"), "equal numbers keep the current order")
        assertEquals(listOf("a", "b", "d", "c"), order("d" to "2"), "hosts without a field keep the number of their place")
        assertEquals(listOf("a", "b", "c", "d"), order("a" to " 1 ", "b" to "", "c" to "3", "d" to "4"))
        assertIs<ResultOf2.Failure<String>>(parseArrangeForm(parametersOf("pos-a" to listOf("first")), list))
        assertIs<ResultOf2.Failure<String>>(parseArrangeForm(parametersOf("pos-a" to listOf("1.5")), list))

        assertEquals(listOf("c", "a", "b"), arrangeHosts(list.take(3), listOf("c", "a", "b")).map { it.id })
        assertEquals(listOf("b", "a", "c", "d"), arrangeHosts(list, listOf("b", "a")).map { it.id }, "hosts missing from the order come last, in their order")
        assertEquals(listOf("a", "b"), arrangeHosts(list.take(2), listOf("x", "a", "b")).map { it.id }, "an id of a deleted host is ignored")
    }

    @Test
    fun `saving the arrange page changes the order of the overview in one post`(): Unit = testApplication {
        hosts(host("a"), host("b", pinned = true), host("c"))
        val browser = browser()
        val page = browser.page("/hosts/arrange")
        assertEquals(listOf("1", "2", "3"), Regex("name=\"pos-[abc]\" value=\"(\\d)\"").findAll(page).map { it.groupValues[1] }.toList())
        assertEquals(6, Regex("data-move=\"(up|down)\"[^>]*hidden").findAll(page).count(), "the arrows wait for app.js")
        assertTrue(browser.page("/").contains("href=\"/hosts/arrange\""), "the hosts page links the arrange page")

        val saved = browser.post("/hosts/arrange", parametersOf("pos-a" to listOf("3"), "pos-b" to listOf("2"), "pos-c" to listOf("1")))
        assertEquals("/?done=hosts-arranged", saved.headers[HttpHeaders.Location])
        assertEquals(listOf("c", "b", "a"), names())
        assertEquals(listOf(listOf("host-b"), listOf("host-c", "host-a")), groups(browser.page()))
        assertEquals("3 hosts", dirl.audit.tail().first { it.action == AuditAction.HOSTS_ARRANGED }.detail)

        val refused = browser.post("/hosts/arrange", parametersOf("pos-a" to listOf("x")))
        assertEquals(HttpStatusCode.BadRequest, refused.status)
        assertTrue(refused.bodyAsText().contains("The position of host-a must be a whole number."))
        assertEquals(listOf("c", "b", "a"), names(), "a refused form changes nothing")
        assertEquals(HttpStatusCode.Forbidden, browser.post("/hosts/arrange", parametersOf("pos-a" to listOf("1")), origin = "https://evil.example.com").status)
        assertEquals(listOf("c", "b", "a"), names())
    }

    private val sample = RawMetrics(
        uptimeSeconds = 86400.0, load1 = 0.1, load5 = 0.1, load15 = 0.1, cpuPercent = 12.0, memTotalKiB = 4_000_000, memAvailableKiB = 3_000_000,
        swapTotalKiB = 0, swapFreeKiB = 0, disks = listOf(DiskUsage("/dev/sda1", "/", "ext4", 10_000_000, 2_000_000)),
    )

    @Test
    fun `a row shows the round trip, warnings, critical values and an offline host`(): Unit = testApplication {
        val closedPort = ServerSocket(0).use { it.localPort }
        val warnings = setOf(OverviewMetric.CPU, OverviewMetric.RAM, OverviewMetric.DISK, OverviewMetric.REBOOT)
        hosts(
            host("fast"), host("slow"), host("full").copy(overview = warnings), host("reboot").copy(overview = warnings),
            host("down").copy(address = "127.0.0.1", port = closedPort), host("jump").copy(jumpOnly = true), host("new"),
        )
        listOf("fast", "slow", "full", "reboot").forEach { dirl.metrics.record(it, sample) }
        dirl.metrics.record("full", sample.copy(disks = listOf(DiskUsage("/dev/sda1", "/", "ext4", 10_000_000, 9_300_000))))
        dirl.metrics.record("reboot", sample.copy(reboot = RebootStatus(needed = true, newerKernel = null)))
        dirl.metrics.recordLatency("fast", 0.4)
        dirl.metrics.recordLatency("slow", 140.6)
        dirl.metrics.recordLatency("full", 12.0)
        dirl.metrics.recordLatency("reboot", 12.0)
        // A real refused connection, no server listens on that port.
        runBlocking { dirl.connections.connection("down") }
        assertIs<ConnectionState.Failed>(dirl.connections.state("down"))
        val browser = browser()
        val page = browser.page()

        // Only connected hosts show their round trip, see SshIntegrationTest. These never connected.
        assertTrue(rowOf(page, "host-fast").let { it.startsWith("pending") && it.contains("<span class=\"ms\">connecting</span>") && it.contains("140").not() })
        assertTrue(rowOf(page, "host-down").let { it.startsWith("error") && it.contains(">offline<") && it.contains("Connect now") && it.contains("Next try") })
        assertTrue(rowOf(page, "host-down").contains("action=\"/hosts/down/connect\""))
        assertTrue(rowOf(page, "host-jump").let { it.contains("Jump host, nothing behind it yet") && it.contains("Terminal").not() })
        assertTrue(rowOf(page, "host-reboot").contains("<span class=\"pill warn\">Reboot needed</span>"))
        assertTrue(rowOf(page, "host-full").contains("class=\"bar critical\"") && rowOf(page, "host-full").contains("--p:93"))
        assertTrue(rowOf(page, "host-fast").contains("class=\"host-name\">host-fast</a>") && rowOf(page, "host-fast").contains("href=\"/hosts/fast\""))
        assertTrue(rowOf(page, "host-fast").contains("aria-label=\"Pin host-fast to the top\""))
        assertFalse(Regex("<script(?![^>]*src=)").containsMatchIn(page), "no inline script, the CSP forbids it")
    }

    @Test
    fun `the health of a row follows the connection, warnings and the round trip`() {
        val connected = ConnectionState.Connected
        assertEquals(Health.OK, healthOf(connected, attention = false, latency = 99.9))
        assertEquals(Health.WARN, healthOf(connected, attention = false, latency = 100.0), "from 100 ms on")
        assertEquals(Health.WARN, healthOf(connected, attention = true, latency = 1.0))
        assertEquals(Health.OK, healthOf(connected, attention = false, latency = null))
        assertEquals(Health.PENDING, healthOf(ConnectionState.Idle, attention = true, latency = null))
        assertEquals(Health.PENDING, healthOf(ConnectionState.Connecting, attention = false, latency = null))
        assertEquals(Health.WARN, healthOf(ConnectionState.HostKeyUnknown("ssh-ed25519", "SHA256:x"), attention = false, latency = null))
        assertEquals(Health.ERROR, healthOf(ConnectionState.Failed("refused", 1, 0), attention = false, latency = null))
        assertEquals(Health.ERROR, healthOf(ConnectionState.AuthFailed(1, 0), attention = false, latency = null))
        assertEquals(Health.ERROR, healthOf(ConnectionState.Stopped("stop"), attention = false, latency = null))
        assertEquals(Health.ERROR, healthOf(ConnectionState.HostKeyMismatch("a", "b"), attention = false, latency = null))
    }

    @Test
    fun `round trips and tag colors read well and stay the same`() {
        assertEquals("<1 ms", roundTripText(0.4))
        assertEquals("1 ms", roundTripText(1.0))
        assertEquals("141 ms", roundTripText(140.6))
        assertEquals(tagHue("prod"), tagHue("Prod"), "the same tag in other case has the same color")
        assertTrue((0 until 360).contains(tagHue("prod")) && (0 until 360).contains(tagHue("")))
        // Fixed, so a tag keeps its color across versions and machines.
        assertEquals(Math.floorMod("prod".hashCode(), 360), tagHue("prod"))
    }
}
