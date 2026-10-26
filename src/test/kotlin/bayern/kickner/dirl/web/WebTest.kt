package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.config.validateConfig
import bayern.kickner.dirl.createDirl
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.parameters
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class WebTest {
    private val config = AppConfig(
        publicUrl = "https://ssh.example.com",
        dataDir = Files.createTempDirectory("dirl-web").toString(),
        oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret", allowedSubjects = listOf("user-1")),
    )
    private val dirl = createDirl(config, java.io.File(config.dataDir))

    private fun ApplicationTestBuilder.noRedirects() = createClient { followRedirects = false }

    @Test
    fun `every response carries the security headers`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val response = noRedirects().get("/healthz")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(CONTENT_SECURITY_POLICY, response.headers["Content-Security-Policy"])
        assertEquals("nosniff", response.headers["X-Content-Type-Options"])
        // "no-referrer" makes browsers send "Origin: null" on form posts, which the origin check rejects.
        assertEquals("same-origin", response.headers["Referrer-Policy"])
        assertEquals("max-age=31536000", response.headers["Strict-Transport-Security"])
    }

    /** A Dirl whose update check answers [latest] instead of asking GitHub, counting the questions in [asked]. */
    private fun dirlWithRelease(latest: String?, asked: AtomicInteger = AtomicInteger()) = createDirl(
        config, Files.createTempDirectory("dirl-update-web").toFile(), latestRelease = { asked.incrementAndGet(); latest },
    ).also { it.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada")) }

    @Test
    fun `opening a page starts the update check`(): Unit = testApplication {
        val asked = AtomicInteger()
        val dirl = dirlWithRelease("99.0.0", asked)
        application { dirlModule(dirl) }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        assertEquals(0, asked.get(), "nothing is asked before a page is opened")
        noRedirects().get("/") { header(HttpHeaders.Cookie, cookie) }
        val deadline = System.currentTimeMillis() + 5000
        while (asked.get() == 0 && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertEquals(1, asked.get())
        noRedirects().get("/keys") { header(HttpHeaders.Cookie, cookie) }
        Thread.sleep(200)
        assertEquals(1, asked.get(), "the next page within the hour does not ask again")
    }

    @Test
    fun `a newer release shows in the footer of logged in pages only`(): Unit = testApplication {
        val dirl = dirlWithRelease("99.0.0")
        runBlocking { dirl.updates.checkIfDue(CoroutineScope(Dispatchers.IO))?.join() }
        application { dirlModule(dirl) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"

        val page = client.get("/") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(page.contains("99.0.0 available"), "footer must show the release")
        assertTrue(page.contains("href=\"https://github.com/nexus421/Dirl/releases/tag/v99.0.0\""), "link to the release")
        assertFalse(client.get("/login").bodyAsText().contains("available"), "not before login")
        val settings = client.get("/settings") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(settings.contains("99.0.0"), "the settings show the latest release")
    }

    @Test
    fun `the running version shows no update`(): Unit = testApplication {
        val dirl = dirlWithRelease(bayern.kickner.dirl.BuildConfig.VERSION)
        runBlocking { dirl.updates.checkIfDue(CoroutineScope(Dispatchers.IO))?.join() }
        application { dirlModule(dirl) }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        assertFalse(noRedirects().get("/") { header(HttpHeaders.Cookie, cookie) }.bodyAsText().contains("available"))
    }

    @Test
    fun `the update check can be turned off and on in the settings`(): Unit = testApplication {
        val dirl = dirlWithRelease("99.0.0")
        runBlocking { dirl.updates.checkIfDue(CoroutineScope(Dispatchers.IO))?.join() }
        application { dirlModule(dirl) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        suspend fun save(on: Boolean) = client.submitForm("/settings/updates", parameters { if (on) append("updateCheck", "on") }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }

        val off = save(on = false)
        assertEquals(HttpStatusCode.Found, off.status)
        assertEquals("/settings?done=settings-saved", off.headers[HttpHeaders.Location])
        assertFalse(dirl.vault.content!!.settings.updateCheck)
        assertFalse(client.get("/") { header(HttpHeaders.Cookie, cookie) }.bodyAsText().contains("available"), "hidden when off")
        val audited = dirl.audit.tail().first()
        assertEquals(AuditAction.SETTINGS_CHANGED, audited.action)
        assertEquals("updateCheck=off", audited.detail)

        save(on = true)
        assertTrue(dirl.vault.content!!.settings.updateCheck)
        assertTrue(client.get("/") { header(HttpHeaders.Cookie, cookie) }.bodyAsText().contains("99.0.0 available"))
    }

    /** A sample like a Debian 13 host sends, with a hostile unit name. */
    private val sample = bayern.kickner.dirl.ssh.RawMetrics(
        uptimeSeconds = 3 * 86400.0 + 7200, load1 = 0.54, load5 = 0.50, load15 = 0.37, cpuPercent = 12.0, cores = 4,
        memTotalKiB = 4_000_000, memAvailableKiB = 1_000_000, swapTotalKiB = 1_000_000, swapFreeKiB = 750_000,
        disks = listOf(
            bayern.kickner.dirl.ssh.DiskUsage("/dev/sda1", "/", "ext4", 10_000_000, 2_500_000),
            bayern.kickner.dirl.ssh.DiskUsage("/dev/sdb1", "/srv/data", "xfs", 20_000_000, 18_000_000),
        ),
        reboot = bayern.kickner.dirl.ssh.RebootStatus(needed = true, newerKernel = "6.12.41+deb13-amd64"),
        failedUnits = listOf("backup.service", "<script>alert(1)</script>.service"),
        osName = "Debian GNU/Linux 13 (trixie)", kernel = "6.12.38+deb13-amd64", loggedInUsers = 2,
        zram = bayern.kickner.dirl.ssh.ZramUsage(origBytes = 1_288_490_188, comprBytes = 429_496_729, memUsedBytes = 440_000_000),
    )

    /** A number as Dirl prints it, in the JVM's locale like the pages (`0,54` with a German one). */
    private fun num(pattern: String, value: Double) = pattern.format(value)

    /** The overview card of the host named [name] in [page]. */
    private fun cardOf(page: String, name: String): String =
        page.split("class=\"card host-card\"").drop(1).first { it.contains(">$name</a>") }

    @Test
    fun `the overview shows exactly the metrics chosen per host`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        val key = bayern.kickner.dirl.ssh.generateEd25519Key("k")
        val plain = bayern.kickner.dirl.vault.Host(id = "a", name = "plain", address = "10.0.0.1", username = "u", keyId = key.id)
        val all = plain.copy(id = "b", name = "everything", overview = bayern.kickner.dirl.vault.OverviewMetric.entries.toSet())
        val none = plain.copy(id = "c", name = "nothing", overview = emptySet())
        dirl.vault.update { it.copy(keys = listOf(key), hosts = listOf(plain, all, none)) }
        listOf(plain, all, none).forEach { dirl.metrics.record(it.id, sample) }
        application { dirlModule(dirl) }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        val page = noRedirects().get("/") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()

        val default = cardOf(page, "plain")
        listOf(">CPU<", ">RAM<", ">Disk<").forEach { assertTrue(default.contains(it), "default shows $it") }
        listOf("Load", "Swap", "Up ", "failed", "Reboot", "zram", "Debian", "logged in", "/srv/data").forEach { assertFalse(default.contains(it), "default hides $it") }

        val everything = cardOf(page, "everything")
        assertTrue(everything.contains("title=\"/srv/data\""), "a long mount point stays readable as tooltip")
        listOf(
            ">CPU<", ">RAM<", ">Swap<", ">Disk<", ">/srv/data<",
            "Load ${num("%.2f", 0.54)} ${num("%.2f", 0.50)} ${num("%.2f", 0.37)}", "4 cores", "Up 3 d 2 h", "Reboot needed",
            "2 failed services", "zram ${num("%.1f", 1.2)} GiB in 420 MiB RAM (${num("%.1f", 2.9)}x)", "Debian GNU/Linux 13 (trixie)", "6.12.38+deb13-amd64",
            "2 logged in",
        ).forEach { assertTrue(everything.contains(it), "all metrics show $it") }

        val nothing = cardOf(page, "nothing")
        assertFalse(nothing.contains("class=\"meters\"") || nothing.contains("class=\"facts\""), "nothing chosen shows no metrics")
        assertTrue(nothing.contains("class=\"pill"), "the connection state stays")
    }

    @Test
    fun `zram shows how much RAM it really saves and says when it is nearly empty`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        val key = bayern.kickner.dirl.ssh.generateEd25519Key("k")
        val zramOnly = setOf(bayern.kickner.dirl.vault.OverviewMetric.ZRAM)
        val busy = bayern.kickner.dirl.vault.Host(id = "a", name = "busy", address = "10.0.0.1", username = "u", keyId = key.id, overview = zramOnly)
        val idle = busy.copy(id = "b", name = "idle")
        val zeros = busy.copy(id = "c", name = "zeros")
        dirl.vault.update { it.copy(keys = listOf(key), hosts = listOf(busy, idle, zeros)) }
        val mib = 1024L * 1024
        // Like the first host in the field: 186 MiB stored, 33 MiB compressed, 35 MiB RAM taken.
        dirl.metrics.record("a", sample.copy(zram = bayern.kickner.dirl.ssh.ZramUsage(186 * mib, 33 * mib, 35 * mib)))
        // Like the second: a few pages swapped out, mostly zero filled ones that zram stores without compressing.
        dirl.metrics.record("b", sample.copy(zram = bayern.kickner.dirl.ssh.ZramUsage(70 * 4096, 4130, 0)))
        // Many zero filled pages cost no RAM at all, the factor must not divide by zero.
        dirl.metrics.record("c", sample.copy(zram = bayern.kickner.dirl.ssh.ZramUsage(64 * mib, 0, 0)))
        application { dirlModule(dirl) }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        val client = noRedirects()
        val page = client.get("/") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()

        assertTrue(cardOf(page, "busy").contains("zram 186 MiB in 35 MiB RAM (${num("%.1f", 5.3)}x)"), cardOf(page, "busy"))
        val idleCard = cardOf(page, "idle")
        assertTrue(idleCard.contains("zram on, nearly empty"), idleCard)
        assertFalse(Regex("""\d+x\)""").containsMatchIn(idleCard), "no factor from a few zero filled pages")
        val zerosCard = cardOf(page, "zeros")
        assertTrue(zerosCard.contains("zram 64 MiB in 0 KiB RAM"), zerosCard)
        assertFalse(zerosCard.contains("Infinity") || zerosCard.contains("NaN") || Regex("""\d+x\)""").containsMatchIn(zerosCard), "no factor without RAM")

        val details = client.get("/hosts/a") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(details.contains("186 MiB stored, 33 MiB compressed, 35 MiB RAM used (${num("%.1f", 5.3)}x)"), "all three values on the host page")
        val idleDetails = client.get("/hosts/b") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(idleDetails.contains("on, nearly empty (280 KiB stored)"), "the host page says how little")
    }

    @Test
    fun `the host page shows every metric and escapes text from the server`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        val key = bayern.kickner.dirl.ssh.generateEd25519Key("k")
        val host = bayern.kickner.dirl.vault.Host(id = "a", name = "web", address = "10.0.0.1", username = "u", keyId = key.id, overview = emptySet())
        dirl.vault.update { it.copy(keys = listOf(key), hosts = listOf(host)) }
        dirl.metrics.record(host.id, sample)
        application { dirlModule(dirl) }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        val page = noRedirects().get("/hosts/a") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        listOf(
            "${num("%.2f", 0.54)} / ${num("%.2f", 0.50)} / ${num("%.2f", 0.37)}", "4 cores", "3 d 2 h", "yes, 6.12.38+deb13-amd64 runs, 6.12.41+deb13-amd64 is installed",
            "backup.service", "Debian GNU/Linux 13 (trixie)", "Logged in users", "/srv/data",
        ).forEach { assertTrue(page.contains(it), "host page shows $it") }
        assertFalse(page.contains("<script>alert(1)"), "a unit name from the server must not become markup")
        assertTrue(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;.service"))
    }

    @Test
    fun `the host form offers the overview choice with the default ticked`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        val key = bayern.kickner.dirl.ssh.generateEd25519Key("k")
        dirl.vault.update { it.copy(keys = listOf(key)) }
        application { dirlModule(dirl) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        val form = client.get("/hosts/new") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        bayern.kickner.dirl.vault.OverviewMetric.entries.forEach { metric ->
            val checked = Regex("""<input[^>]*name="overview"[^>]*value="${metric.name}"[^>]*>""").find(form)?.value
            assertTrue(checked != null, "${metric.name} is offered")
            assertEquals(metric in bayern.kickner.dirl.vault.DEFAULT_OVERVIEW, checked.contains("checked"), metric.name)
        }

        val saved = client.submitForm("/hosts", parameters {
            append("name", "web"); append("address", "10.0.0.5"); append("port", "22"); append("username", "root"); append("keyId", key.id)
            append("overviewShown", "1"); append("overview", "UPTIME"); append("overview", "FAILED_SERVICES")
        }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        assertEquals(HttpStatusCode.Found, saved.status)
        assertEquals(
            setOf(bayern.kickner.dirl.vault.OverviewMetric.UPTIME, bayern.kickner.dirl.vault.OverviewMetric.FAILED_SERVICES),
            dirl.vault.content!!.hosts.single().overview,
        )
    }

    @Test
    fun `an unknown host is a plain 404 on every host page`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        application { dirlModule(dirl) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        for (path in listOf("/hosts/nope", "/hosts/nope/edit", "/hosts/nope/files", "/hosts/nope/terminal")) {
            val response = client.get(path) { header(HttpHeaders.Cookie, cookie) }
            assertEquals(HttpStatusCode.NotFound, response.status, path)
            assertTrue(response.bodyAsText().contains("This address does not exist in Dirl."), path)
        }
        val deleted = client.post("/hosts/nope/delete") {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        assertEquals(HttpStatusCode.NotFound, deleted.status)
    }

    @Test
    fun `pages require a login`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val response = noRedirects().get("/")
        assertEquals(HttpStatusCode.Found, response.status)
        assertEquals("/login", response.headers[HttpHeaders.Location])
    }

    @Test
    fun `a logged in user is sent to the vault setup first`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val session = dirl.sessions.create(Actor("user-1", "Ada"))
        val response = noRedirects().get("/") { header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}") }
        assertEquals("/unlock", response.headers[HttpHeaders.Location])
    }

    @Test
    fun `posts and websockets from a foreign origin are rejected`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val session = dirl.sessions.create(Actor("user-1", "Ada"))
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${session.token}"

        assertEquals(HttpStatusCode.Forbidden, client.post("/logout") { header(HttpHeaders.Cookie, cookie) }.status)
        assertEquals(HttpStatusCode.Forbidden, client.post("/logout") { header(HttpHeaders.Cookie, cookie); header(HttpHeaders.Origin, "https://evil.example") }.status)
        assertEquals(HttpStatusCode.Found, client.post("/logout") { header(HttpHeaders.Cookie, cookie); header(HttpHeaders.Origin, "https://ssh.example.com") }.status)

        // The handshake with the right origin succeeds (the server then closes for the unknown host), with a foreign one it fails.
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        val wsSession = dirl.sessions.create(Actor("user-1", "Ada"))
        val wsClient = createClient { install(WebSockets) }
        suspend fun handshake(origin: String) = runCatching {
            wsClient.webSocket("/ws/terminal/x", request = {
                header(HttpHeaders.Cookie, "$SESSION_COOKIE=${wsSession.token}")
                header(HttpHeaders.Origin, origin)
            }) {}
        }
        assertTrue(handshake("https://ssh.example.com").isSuccess)
        assertTrue(handshake("https://evil.example").isFailure)
    }

    @Test
    fun `path tricks neither bypass the login nor end as server errors`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val client = noRedirects()
        assertEquals(HttpStatusCode.BadRequest, client.get("/static/..%2Fsettings").status)
        assertEquals(HttpStatusCode.NotFound, client.get("/login/..%2Fsettings").status)
    }

    @Test
    fun `automatic reloads do not keep an idle session alive`(): Unit = testApplication {
        var now = 1_000_000L
        val dataDir = Files.createTempDirectory("dirl-idle").toFile()
        val clocked = createDirl(config.copy(dataDir = dataDir.absolutePath), dataDir) { now }
        clocked.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        application { dirlModule(clocked) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${clocked.sessions.create(Actor("user-1", "Ada")).token}"

        // Every minute, ten minutes past the idle timeout, the overview reloads itself, nobody touches the browser.
        val idle = config.session.idleTimeoutMinutes
        repeat(idle + 10) {
            now += 60_000
            val reload = client.get("/?$AUTO_REFRESH_PARAM=1") { header(HttpHeaders.Cookie, cookie) }
            if (it < idle - 1) assertEquals(HttpStatusCode.OK, reload.status, "minute ${it + 1}")
        }
        assertEquals("/login", client.get("/") { header(HttpHeaders.Cookie, cookie) }.headers[HttpHeaders.Location])
    }

    @Test
    fun `real requests keep the session alive`(): Unit = testApplication {
        var now = 1_000_000L
        val dataDir = Files.createTempDirectory("dirl-active").toFile()
        val clocked = createDirl(config.copy(dataDir = dataDir.absolutePath), dataDir) { now }
        clocked.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        application { dirlModule(clocked) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${clocked.sessions.create(Actor("user-1", "Ada")).token}"
        repeat(config.session.idleTimeoutMinutes + 10) {
            now += 60_000
            assertEquals(HttpStatusCode.OK, client.get("/") { header(HttpHeaders.Cookie, cookie) }.status)
        }
    }

    @Test
    fun `ending your own session clears the cookie like a logout`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        application { dirlModule(dirl) }
        val client = noRedirects()
        val own = dirl.sessions.create(Actor("user-1", "Ada"))
        val other = dirl.sessions.create(Actor("user-1", "Ada"))
        suspend fun end(id: String) = client.submitForm("/settings/sessions/revoke", parameters { append("id", id) }) {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=${own.token}")
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }

        val endedOther = end(other.id)
        assertEquals("/settings?done=session-revoked", endedOther.headers[HttpHeaders.Location])
        assertTrue(endedOther.headers.getAll(HttpHeaders.SetCookie).orEmpty().none { it.startsWith("$SESSION_COOKIE=") })

        val endedOwn = end(own.id)
        assertEquals("/login", endedOwn.headers[HttpHeaders.Location])
        val cleared = endedOwn.headers.getAll(HttpHeaders.SetCookie).orEmpty().firstOrNull { it.startsWith("$SESSION_COOKIE=") }
        assertTrue(cleared != null && cleared.startsWith("$SESSION_COOKIE=;") && cleared.contains("Max-Age=0"), "was: $cleared")
    }

    @Test
    fun `too long snippets are refused with the input kept instead of cut silently`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        application { dirlModule(dirl) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        suspend fun post(url: String, name: String, command: String) = client.submitForm(url, parameters { append("name", name); append("command", command) }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        val long = "echo " + "x".repeat(4100) + " end"

        val added = post("/snippets", "long one", long)
        assertEquals(HttpStatusCode.BadRequest, added.status)
        val page = added.bodyAsText()
        assertTrue(page.contains("Command is longer than 4000 characters"), "the reason must be shown")
        assertTrue(page.contains("x".repeat(4100) + " end") && page.contains("value=\"long one\""), "the input must stay in the form")
        assertEquals(emptyList(), dirl.vault.content!!.snippets, "nothing may be stored")

        assertTrue(post("/snippets", "n".repeat(65), "ls").bodyAsText().contains("Name is longer than 64 characters"))

        // Editing keeps the edit form, so a second try saves the same snippet instead of adding a new one.
        assertEquals(HttpStatusCode.Found, post("/snippets", "disk", "df -h").status)
        val id = dirl.vault.content!!.snippets.single().id
        val edited = post("/snippets/$id", "disk", long)
        assertEquals(HttpStatusCode.BadRequest, edited.status)
        assertTrue(edited.bodyAsText().contains("action=\"/snippets/$id\""), "the error must show the edit form")
        assertEquals("df -h", dirl.vault.content!!.snippets.single().command)
    }

    @Test
    fun `removing a subject that is not in the list keeps its sessions`(): Unit = testApplication {
        // user-1 is break-glass from the config, the vault list only holds user-2.
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-2", "Bob"))
        application { dirlModule(dirl) }
        val client = noRedirects()
        val breakGlass = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        val other = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-2", "Bob")).token}"

        val revoked = client.submitForm("/settings/users/revoke", parameters { append("sub", "user-1") }) {
            header(HttpHeaders.Cookie, other)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        assertEquals(HttpStatusCode.Found, revoked.status)
        assertEquals(HttpStatusCode.OK, client.get("/settings") { header(HttpHeaders.Cookie, breakGlass) }.status, "the session must stay")
    }

    @Test
    fun `a restore without a multipart body is a bad request, not a server error`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        val response = noRedirects().submitForm("/setup/restore", parameters { append("file", "x") }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `the overview reloads fast only while hosts are on their way to a status, and not forever`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        val key = bayern.kickner.dirl.ssh.generateEd25519Key("k")
        // Port 1 on loopback refuses at once, so the host fails without waiting for a timeout.
        val host = bayern.kickner.dirl.vault.Host(id = "w", name = "waiting", address = "127.0.0.1", port = 1, username = "u", keyId = key.id)
        dirl.vault.update { it.copy(keys = listOf(key), hosts = listOf(host)) }
        application { dirlModule(dirl) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        suspend fun refresh(url: String): String {
            val page = client.get(url) { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
            return Regex("http-equiv=\"refresh\" content=\"([^\"]+)\"").find(page)!!.groupValues[1].replace("&amp;", "&")
        }

        assertEquals("3; url=/?autorefresh=1&wait=1", refresh("/"), "a host not tried yet is on its way")
        assertEquals("3; url=/?autorefresh=1&wait=10", refresh("/?autorefresh=1&wait=9"))
        assertEquals("60; url=/?autorefresh=1", refresh("/?autorefresh=1&wait=10"), "after ten fast reloads back to once a minute")

        dirl.connections.connection(host.id)
        assertIs<bayern.kickner.dirl.ssh.ConnectionState.Failed>(dirl.connections.state(host.id))
        assertEquals("60; url=/?autorefresh=1", refresh("/"), "a failed host waits for nobody")
    }

    @Test
    fun `the keys page puts generate on top and folds every key, opening only the new one`(): Unit = testApplication {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), Actor("user-1", "Ada"))
        val used = bayern.kickner.dirl.ssh.generateEd25519Key("used", now = 1000)
        val spare = bayern.kickner.dirl.ssh.generateEd25519Key("spare", now = 2000)
        val host = bayern.kickner.dirl.vault.Host(id = "h", name = "web", address = "10.0.0.5", username = "root", keyId = used.id)
        dirl.vault.update { it.copy(keys = listOf(used, spare), hosts = listOf(host)) }
        application { dirlModule(dirl) }
        val client = noRedirects()
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(Actor("user-1", "Ada")).token}"
        val rowPattern = Regex("""<details class="key-row"( open="open")?>(.*?)</details>""", RegexOption.DOT_MATCHES_ALL)
        suspend fun page(url: String) = client.get(url) { header(HttpHeaders.Cookie, cookie) }.bodyAsText()

        val plain = page("/keys")
        assertTrue(plain.indexOf("action=\"/keys/generate\"") < plain.indexOf("class=\"key-row\""), "generate comes before the keys")
        assertTrue(Regex("""<details class="import">.*?action="/keys/import"""", RegexOption.DOT_MATCHES_ALL).containsMatchIn(plain), "import is folded")
        val rows = rowPattern.findAll(plain).toList()
        assertEquals(2, rows.size)
        assertTrue(rows.none { it.groupValues[1].isNotEmpty() }, "a normal visit opens no key")
        val (spareRow, usedRow) = rows.map { it.groupValues[2] }
        assertTrue(spareRow.contains("unused") && spareRow.contains("/keys/${spare.id}/delete"), "an unused key is marked and can be deleted")
        assertTrue(usedRow.contains("1 host") && usedRow.contains("web") && usedRow.contains("/keys/${used.id}/delete").not())
        assertTrue(usedRow.contains("/keys/${used.id}/rename") && usedRow.contains("/keys/${used.id}/export"))
        assertTrue(usedRow.contains("${used.publicKey} dirl"), "the authorized_keys line is in the row")

        val generated = client.submitForm("/keys/generate", parameters { append("name", "fresh") }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        assertEquals("/keys?done=key-generated", generated.headers[HttpHeaders.Location])
        val opened = rowPattern.findAll(page("/keys?done=key-generated")).filter { it.groupValues[1].isNotEmpty() }.toList()
        assertEquals(1, opened.size, "only the new key is open")
        assertTrue(opened.single().groupValues[2].contains("fresh"))

        val failed = client.submitForm("/keys/import", parameters { append("name", "bad"); append("privateKey", "garbage") }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        assertEquals(HttpStatusCode.BadRequest, failed.status)
        assertTrue(failed.bodyAsText().contains("<details class=\"import\" open=\"open\">"), "a failed import keeps the form open")
    }

    @Test
    fun `the example config from the quick start is valid`() {
        val loaded = bayern.kickner.dirl.config.loadConfig(java.io.File("config.example.json"))
        assertIs<kotnexlib.ResultOf2.Success<AppConfig>>(loaded, "config.example.json: $loaded")
    }

    @Test
    fun `config validation reports every problem`() {
        val broken = config.copy(port = 0, publicUrl = "http://ssh.example.com/", oidc = config.oidc.copy(issuer = "ftp://x", clientSecret = " ", scopes = listOf("profile")))
        val issues = validateConfig(broken)
        assertEquals(6, issues.size, issues.joinToString("\n"))
        assertTrue(validateConfig(config.copy(publicUrl = "http://localhost:8080")).isEmpty())
    }

    @Test
    fun `publicUrl must have the form browsers send as Origin`() {
        // A path, query, fragment or user info never matches the Origin header and breaks the absolute links.
        listOf(
            "https://ssh.example.com:443", "http://localhost:80", "https://SSH.example.com",
            "https://ssh.example.com/dirl", "https://ssh.example.com?x=1", "https://ssh.example.com#top", "https://user@ssh.example.com",
        ).forEach { url ->
            assertEquals(1, validateConfig(config.copy(publicUrl = url)).size, url)
        }
        assertTrue(validateConfig(config.copy(publicUrl = "https://ssh.example.com:8443")).isEmpty())
        assertEquals("https://ssh.example.com:8443", originOf("https://ssh.example.com:8443"))
    }

    @Test
    fun `uploaded names cannot leave the directory`() {
        assertEquals("a.txt", safeFileName("../../a.txt"))
        assertEquals("b.txt", safeFileName("C:\\x\\b.txt"))
        assertEquals(null, safeFileName(".."))
        assertEquals("a__b_c_.txt", headerSafeFileName("a\r\nb\"c\\.txt"))
        assertEquals("parent", parentOf("/parent/child").removePrefix("/"))
    }
}
