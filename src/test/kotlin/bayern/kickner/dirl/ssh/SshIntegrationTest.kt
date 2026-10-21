package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.PinnedHostKey
import bayern.kickner.dirl.web.Dirl
import bayern.kickner.dirl.web.SESSION_COOKIE
import bayern.kickner.dirl.web.dirlModule
import bayern.kickner.dirl.web.deleteEntry
import bayern.kickner.dirl.web.listDirectory
import bayern.kickner.dirl.web.listEntries
import bayern.kickner.dirl.web.writeAtomically
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.forms.formData
import io.ktor.client.request.forms.submitFormWithBinaryData
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Headers
import io.ktor.http.HttpStatusCode
import io.ktor.http.HttpHeaders
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import io.ktor.websocket.readBytes
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotnexlib.ResultOf2
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.sftp.FileMode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Connects Dirl to real OpenSSH servers (see [LocalSshd]) with the restricted `authorized_keys` lines Dirl shows in
 * the UI. Skipped when no `sshd` is available.
 */
class SshIntegrationTest {
    private val root = LocalSshd.findRoot()
    private val servers = mutableListOf<LocalSshd>()
    private val actor = Actor("user-1", "Ada")
    private val user = System.getProperty("user.name")
    private var now = System.currentTimeMillis()
    private lateinit var dirl: Dirl

    @BeforeEach
    fun setUp() {
        assumeTrue(root != null, "No sshd found, set DIRL_SSHD_ROOT or install openssh-server")
        val dataDir = Files.createTempDirectory("dirl-it").toFile()
        val config = AppConfig(
            publicUrl = "https://ssh.example.com",
            dataDir = dataDir.absolutePath,
            oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret"),
        )
        dirl = createDirl(config, dataDir, clock = { now })
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), actor)
    }

    @AfterEach
    fun tearDown() {
        if (::dirl.isInitialized) dirl.connections.disconnectAll()
        servers.forEach { it.close() }
    }

    private fun sshd() = LocalSshd.start(root!!).also { servers += it }

    private fun addHost(name: String, port: Int, keyId: String, jumpHostId: String? = null, pin: PinnedHostKey? = null, jumpOnly: Boolean = false): Host {
        val host = Host(id = name, name = name, address = "127.0.0.1", port = port, username = user, keyId = keyId, jumpHostId = jumpHostId, pinnedHostKey = pin, jumpOnly = jumpOnly)
        dirl.vault.update { it.copy(hosts = it.hosts.filterNot { h -> h.id == name } + host) }
        return host
    }

    private fun newKey() = generateEd25519Key("dirl").also { key -> dirl.vault.update { it.copy(keys = it.keys + key) } }

    private fun exec(client: SSHClient, command: String): String = client.startSession().use { session ->
        val cmd = session.exec(command)
        val out = cmd.inputStream.readBytes().decodeToString()
        cmd.join(10, TimeUnit.SECONDS)
        out
    }

    @Test
    fun `first contact asks for the host key, after pinning commands and metrics work`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty,from=\"127.0.0.1\" ${key.publicKey} dirl")
        val host = addHost("web", server.port, key.id)

        val first = dirl.connections.connection(host.id)
        val unknown = assertIs<ConnectionState.HostKeyUnknown>((first as ResultOf2.Failure).value)
        assertEquals(server.hostKeyFingerprint, unknown.fingerprint)

        assertTrue(dirl.connections.pinHostKey(host.id, unknown.fingerprint, actor))
        val client = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        assertTrue(exec(client, "echo dirl-ok").contains("dirl-ok"))
        val metrics = assertIs<ResultOf2.Success<RawMetrics>>(parseMetrics(exec(client, METRICS_COMMAND)), "metrics output did not parse")
        assertTrue(metrics.value.cpuPercent != null, "one poll must yield the CPU usage on its own")
    }

    @Test
    fun `a changed host key blocks the connection and is audited`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("${key.publicKey} dirl")
        val host = addHost("db", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", "SHA256:not-the-real-key", now))

        val result = dirl.connections.connection(host.id)
        val mismatch = assertIs<ConnectionState.HostKeyMismatch>((result as ResultOf2.Failure).value)
        assertEquals(server.hostKeyFingerprint, mismatch.actual)
        assertTrue(dirl.audit.tail().any { it.action == AuditAction.HOST_KEY_MISMATCH })
        // Blocked: no new attempt, even after a long time.
        now += 3_600_000
        assertIs<ConnectionState.HostKeyMismatch>((dirl.connections.connection(host.id) as ResultOf2.Failure).value)
    }

    @Test
    fun `three rejected logins stop the host until it is reset`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        val host = addHost("app", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))

        repeat(2) { attempt ->
            assertIs<ConnectionState.AuthFailed>((dirl.connections.connection(host.id) as ResultOf2.Failure).value)
            // Within the backoff no network attempt happens.
            assertIs<ConnectionState.AuthFailed>((dirl.connections.connection(host.id) as ResultOf2.Failure).value)
            now += backoffDelayMillis(attempt + 1) + 1
        }
        assertIs<ConnectionState.Stopped>((dirl.connections.connection(host.id) as ResultOf2.Failure).value)
        now += 24 * 3_600_000L
        assertIs<ConnectionState.Stopped>((dirl.connections.connection(host.id) as ResultOf2.Failure).value)

        server.authorize("${key.publicKey} dirl")
        dirl.connections.reset(host.id)
        val afterReset = dirl.connections.connection(host.id)
        assertIs<ResultOf2.Success<SSHClient>>(afterReset, "state: $afterReset\nsshd log:\n${server.log().lines().takeLast(15).joinToString("\n")}")
    }

    @Test
    fun `closing for absence keeps a stopped host stopped and the next access connects again`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("${key.publicKey} dirl")
        val pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now)
        val good = addHost("good", server.port, key.id, pin = pin)
        val bad = addHost("bad", server.port, newKey().id, pin = pin)

        val first = (dirl.connections.connection(good.id) as ResultOf2.Success).value
        repeat(MAX_AUTH_FAILURES) { attempt ->
            dirl.connections.connection(bad.id)
            now += backoffDelayMillis(attempt + 1) + 1
        }
        assertIs<ConnectionState.Stopped>(dirl.connections.state(bad.id))

        dirl.connections.closeAll()
        assertEquals(ConnectionState.Idle, dirl.connections.state(good.id))
        assertTrue(first.isConnected.not(), "the connection must be closed")
        assertIs<ConnectionState.Stopped>(dirl.connections.state(bad.id), "a stop survives, otherwise every arrival brings new failed logins")
        assertIs<ConnectionState.Stopped>((dirl.connections.connection(bad.id) as ResultOf2.Failure).value)

        val second = (dirl.connections.connection(good.id) as ResultOf2.Success).value
        assertTrue(second !== first && second.isConnected)
    }

    @Test
    fun `the status poll runs only while somebody is present and never twice at once for a host`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("${key.publicKey} dirl")
        GatedProxy(server.port).use { proxy ->
            // The rounds run on IO: the test thread blocks on the proxy, the polls must not wait for it.
            val host = addHost("polled", proxy.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
            withContext(Dispatchers.IO) { assertEquals(0, dirl.metrics.round(this), "nobody is present, nothing is polled") }
            assertEquals(ConnectionState.Idle, dirl.connections.state(host.id))

            val leave = CompletableDeferred<Unit>()
            val arrived = CompletableDeferred<Unit>()
            val visitor = launch(Dispatchers.IO) { dirl.presence.hold { arrived.complete(Unit); leave.await() } }
            arrived.await()
            withContext(Dispatchers.IO) {
                assertEquals(1, dirl.metrics.round(this))
                assertTrue(proxy.awaitAccepted(), "the poll connects")
                assertEquals(0, dirl.metrics.round(this), "the first poll still hangs, a second one must not pile up")
                proxy.open()
            }
            assertIs<ConnectionState.Connected>(dirl.connections.state(host.id))
            assertTrue(dirl.metrics.polled(host.id))
            assertTrue(dirl.metrics.latest(host.id)?.cpuPercent != null, "the first sample already has the CPU usage")

            leave.complete(Unit)
            visitor.join()
            now += 31_000
            withContext(Dispatchers.IO) { dirl.metrics.round(this) }
            assertEquals(ConnectionState.Idle, dirl.connections.state(host.id))
            assertTrue(dirl.metrics.latest(host.id) == null && dirl.metrics.polled(host.id).not(), "stale values are forgotten")
            assertTrue(proxy.awaitIdle(), "nobody is present, the connection must be closed")
        }
    }

    @Test
    fun `closing all connections during a connect does not leave the new connection open`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("${key.publicKey} dirl")
        GatedProxy(server.port).use { proxy ->
            val host = addHost("slow", proxy.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))

            val attempt = async(Dispatchers.IO) { dirl.connections.connection(host.id) }
            assertTrue(proxy.awaitAccepted(), "the connect attempt never reached the proxy")
            // What sealing the vault does, while the handshake is held back.
            dirl.connections.disconnectAll()
            proxy.open()

            assertIs<ResultOf2.Failure<ConnectionState>>(attempt.await(), "a connect that outlived disconnectAll must not be handed out")
            assertTrue(proxy.awaitIdle(), "the connection outlived disconnectAll")
            assertIs<ResultOf2.Success<SSHClient>>(dirl.connections.connection(host.id), "the next attempt must connect normally")
        }
    }

    @Test
    fun `targets behind a restricted jump host are reachable, the jump host itself runs no commands`(): Unit = runBlocking {
        val jumpServer = sshd()
        val targetServer = sshd()
        val key = newKey()
        val jump = addHost("jump", jumpServer.port, key.id, pin = PinnedHostKey("ssh-ed25519", jumpServer.hostKeyFingerprint, now), jumpOnly = true)
        val target = addHost("target", targetServer.port, key.id, jumpHostId = jump.id, pin = PinnedHostKey("ssh-ed25519", targetServer.hostKeyFingerprint, now))

        val content = dirl.vault.content!!
        jumpServer.authorize(authorizedKeysLine(jump, key, content.hosts, "127.0.0.1"))
        targetServer.authorize(authorizedKeysLine(target, key, content.hosts, "127.0.0.1"))
        assertTrue(authorizedKeysLine(jump, key, content.hosts, "127.0.0.1").contains("command=\"/bin/false\""))

        val targetClient = (dirl.connections.connection(target.id) as ResultOf2.Success).value
        assertTrue(exec(targetClient, "echo via-jump").contains("via-jump"))

        val jumpClient = (dirl.connections.connection(jump.id) as ResultOf2.Success).value
        assertEquals("", exec(jumpClient, "echo should-not-run").trim())
        assertTrue(runCatching { jumpClient.newDirectConnection("127.0.0.1", jumpServer.port).use { it.inputStream.read() } }.isFailure, "forwarding to other destinations must be refused")
    }

    @Test
    fun `an IPv6 target behind a restricted jump host is reachable with the generated lines`(): Unit = runBlocking {
        val v6 = runCatching { java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("::1")).close() }.isSuccess
        assumeTrue(v6, "No IPv6 loopback")
        val jumpServer = sshd()
        val targetServer = LocalSshd.start(root!!, listen = "::1").also { servers += it }
        val key = newKey()
        val jump = addHost("jump6", jumpServer.port, key.id, pin = PinnedHostKey("ssh-ed25519", jumpServer.hostKeyFingerprint, now), jumpOnly = true)
        val target = Host(id = "target6", name = "target6", address = "::1", port = targetServer.port, username = user, keyId = key.id, jumpHostId = jump.id, pinnedHostKey = PinnedHostKey("ssh-ed25519", targetServer.hostKeyFingerprint, now))
        dirl.vault.update { it.copy(hosts = it.hosts + target) }
        val content = dirl.vault.content!!
        jumpServer.authorize(authorizedKeysLine(jump, key, content.hosts, "127.0.0.1"))
        targetServer.authorize(authorizedKeysLine(target, key, content.hosts, "::1"))

        val result = dirl.connections.connection(target.id)
        assertIs<ResultOf2.Success<SSHClient>>(result, "state: $result\njump sshd log:\n${jumpServer.log().lines().takeLast(10).joinToString("\n")}")
        assertTrue(exec(result.value, "echo via-v6").contains("via-v6"))
    }

    @Test
    fun `confirming the host key of a jump host lets the hosts behind it connect at once`(): Unit = runBlocking {
        val jumpServer = sshd()
        val targetServer = sshd()
        val key = newKey()
        val jump = addHost("jumpfirst", jumpServer.port, key.id)
        val target = addHost("behind", targetServer.port, key.id, jumpHostId = jump.id, pin = PinnedHostKey("ssh-ed25519", targetServer.hostKeyFingerprint, now))
        val content = dirl.vault.content!!
        jumpServer.authorize(authorizedKeysLine(jump, key, content.hosts, "127.0.0.1"))
        targetServer.authorize(authorizedKeysLine(target, key, content.hosts, "127.0.0.1"))

        // First setup: the jump host key is not confirmed yet, so the target fails and backs off.
        assertIs<ConnectionState.Failed>((dirl.connections.connection(target.id) as ResultOf2.Failure).value)
        val offered = assertIs<ConnectionState.HostKeyUnknown>(dirl.connections.state(jump.id))
        assertTrue(dirl.connections.pinHostKey(jump.id, offered.fingerprint, actor))

        // Without waiting for the backoff.
        assertIs<ResultOf2.Success<SSHClient>>(dirl.connections.connection(target.id), "the target must not wait for its backoff")
    }

    @Test
    fun `a jump host that is also a terminal target runs commands and forwards only to its targets`(): Unit = runBlocking {
        val jumpServer = sshd()
        val targetServer = sshd()
        val key = newKey()
        val jump = addHost("jump", jumpServer.port, key.id, pin = PinnedHostKey("ssh-ed25519", jumpServer.hostKeyFingerprint, now))
        val target = addHost("target", targetServer.port, key.id, jumpHostId = jump.id, pin = PinnedHostKey("ssh-ed25519", targetServer.hostKeyFingerprint, now))
        val content = dirl.vault.content!!
        jumpServer.authorize(authorizedKeysLine(jump, key, content.hosts, "127.0.0.1"))
        targetServer.authorize(authorizedKeysLine(target, key, content.hosts, "127.0.0.1"))

        val jumpClient = (dirl.connections.connection(jump.id) as ResultOf2.Success).value
        assertTrue(exec(jumpClient, "echo jump-shell").contains("jump-shell"))
        val targetClient = (dirl.connections.connection(target.id) as ResultOf2.Success).value
        assertTrue(exec(targetClient, "echo behind-jump").contains("behind-jump"))
        assertTrue(runCatching { jumpClient.newDirectConnection("127.0.0.1", jumpServer.port).use { it.inputStream.read() } }.isFailure, "forwarding to other destinations must be refused")
    }

    @Test
    fun `uploads do not overwrite existing files unless asked to`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty ${key.publicKey} dirl")
        val host = addHost("up", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-upload").toFile()
        File(dir, "a.txt").writeText("old")
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }

        suspend fun upload(overwrite: Boolean) = client.submitFormWithBinaryData(
            url = "/hosts/${host.id}/files/upload?path=${dir.absolutePath}",
            formData = formData {
                if (overwrite) append("overwrite", "on")
                append("file", "new".toByteArray(), Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"a.txt\"") })
            },
        ) {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}")
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }

        val refused = upload(overwrite = false)
        assertTrue(refused.bodyAsText().contains("not overwritten"))
        assertEquals("old", File(dir, "a.txt").readText())
        assertEquals(HttpStatusCode.Found, upload(overwrite = true).status)
        assertEquals("new", File(dir, "a.txt").readText())
        dir.deleteRecursively()
    }

    @Test
    fun `sftp writes atomically and overwrites existing files`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty ${key.publicKey} dirl")
        val host = addHost("files", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-sftp").toFile()
        val target = File(dir, "config.txt").apply { writeText("old") }

        val client = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        client.newSFTPClient().use { sftp -> writeAtomically(sftp, target.absolutePath, "new äöü\r\n".byteInputStream()) }

        assertEquals("new äöü\r\n", target.readText())
        assertEquals(listOf("config.txt"), dir.list()!!.toList(), "no temporary file may be left behind")

        // A transfer that breaks off, e.g. a closed browser tab during an upload, leaves neither a changed target nor
        // the partial temporary file behind.
        val broken = object : java.io.InputStream() {
            private var sent = 0
            override fun read(): Int = if (sent++ < 100_000) 'x'.code else throw java.io.IOException("connection reset")
        }
        val failure = client.newSFTPClient().use { sftp -> runCatching { writeAtomically(sftp, target.absolutePath, broken) }.exceptionOrNull() }
        assertTrue(failure?.message.orEmpty().contains("connection reset"), "the original error must reach the caller, was: $failure")
        assertEquals("new äöü\r\n", target.readText())
        assertEquals(listOf("config.txt"), dir.list()!!.toList(), "the partial temporary file must be removed")

        // Listings stop at the limit with a message for the user instead of growing without bound.
        repeat(9) { File(dir, "f$it").writeText("x") }
        client.newSFTPClient().use { sftp ->
            assertEquals(10, listDirectory(sftp, dir.absolutePath, max = 10).size)
            val tooMany = runCatching { listDirectory(sftp, dir.absolutePath, max = 5) }.exceptionOrNull()
            assertTrue(tooMany?.message.orEmpty().contains("more than 5 entries"), "was: $tooMany")
        }
        dir.deleteRecursively()
    }

    @Test
    fun `symlinks list, delete and save like their targets without touching them`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict ${key.publicKey} dirl")
        val host = addHost("links", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-links").toFile()
        val sub = File(dir, "sub").apply { mkdir(); File(this, "inside.txt").writeText("keep") }
        val real = File(dir, "real.txt").apply { writeText("old") }
        Files.createSymbolicLink(File(dir, "linkdir").toPath(), sub.toPath())
        Files.createSymbolicLink(File(dir, "link.txt").toPath(), real.toPath())
        Files.createSymbolicLink(File(dir, "broken").toPath(), File(dir, "missing").toPath())

        val client = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        client.newSFTPClient().use { sftp ->
            val entries = listEntries(sftp, dir.absolutePath).associateBy { it.name }
            assertTrue(entries.getValue("linkdir").isDirectory, "a link to a directory must be navigable")
            assertTrue(entries.getValue("linkdir").isLink)
            assertEquals(FileMode.Type.REGULAR, entries.getValue("link.txt").type, "a link to a text file must be editable")
            assertEquals(3, entries.getValue("link.txt").size, "size of the target, not of the link")
            assertTrue(entries.getValue("broken").isDirectory.not() && entries.getValue("broken").isLink)
            assertTrue(entries.getValue("real.txt").isLink.not())

            // Saving through the link writes the target and keeps the link.
            writeAtomically(sftp, File(dir, "link.txt").absolutePath, "new".byteInputStream())
            assertTrue(Files.isSymbolicLink(File(dir, "link.txt").toPath()), "the link must survive a save")
            assertEquals("new", real.readText())

            // Deleting a link removes the link, never the target.
            deleteEntry(sftp, File(dir, "linkdir").absolutePath)
            deleteEntry(sftp, File(dir, "broken").absolutePath)
            deleteEntry(sftp, File(dir, "link.txt").absolutePath)
        }
        assertEquals(listOf("real.txt", "sub"), dir.list()!!.sorted())
        assertEquals("keep", File(sub, "inside.txt").readText())
        assertEquals("new", real.readText())
        dir.deleteRecursively()
    }

    @Test
    fun `the file list opens links to directories and marks links`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict ${key.publicKey} dirl")
        val host = addHost("linkpage", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-linkpage").toFile()
        val sub = File(dir, "sub").apply { mkdir() }
        Files.createSymbolicLink(File(dir, "linkdir").toPath(), sub.toPath())
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }

        val page = client.get("/hosts/${host.id}/files?path=${java.net.URLEncoder.encode(dir.absolutePath, Charsets.UTF_8)}") {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}")
        }.bodyAsText()
        val linkHref = "/hosts/${host.id}/files?path=" + java.net.URLEncoder.encode(File(dir, "linkdir").absolutePath, Charsets.UTF_8)
        assertTrue(page.contains("href=\"$linkHref\""), "the link to a directory must open the listing")
        assertTrue(page.contains("linkdir/</a><span class=\"muted\" title=\"Symbolic link\"> →</span>"), "the link must be marked")
        assertTrue(page.contains("sub/</a><span").not(), "plain directories carry no mark")
        dir.deleteRecursively()
    }

    @Test
    fun `the terminal websocket runs a real shell`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty,from=\"127.0.0.1\" ${key.publicKey} dirl")
        val host = addHost("term", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }

        val client = createClient { install(WebSockets) }
        var output = ""
        client.webSocket("/ws/terminal/${host.id}?cols=100&rows=30", request = {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}")
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }) {
            send(Frame.Text("""{"type":"resize","cols":120,"rows":40}"""))
            // The marker only appears in the output, not in the echoed input, because printf assembles it.
            send(Frame.Binary(true, "printf 'DIRL%sMARK\\n' -ws-; stty size\r".toByteArray()))
            withTimeout(15_000) {
                for (frame in incoming) {
                    if (frame is Frame.Binary) output += frame.readBytes().decodeToString()
                    if (output.contains("DIRL-ws-MARK") && output.contains("40 120")) break
                }
            }
        }
        assertTrue(output.contains("DIRL-ws-MARK"), "shell output missing: $output")
        assertTrue(output.contains("40 120"), "resize did not reach the PTY: $output")
        assertTrue(dirl.audit.tail().any { it.action == AuditAction.TERMINAL_OPENED && it.host == host.name })
    }
}
