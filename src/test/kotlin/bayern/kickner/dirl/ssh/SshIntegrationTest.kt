package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.dev.DelayProxy
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.PinnedHostKey
import bayern.kickner.dirl.vault.SshKey
import bayern.kickner.dirl.web.Dirl
import bayern.kickner.dirl.web.SESSION_COOKIE
import bayern.kickner.dirl.web.commitWrite
import bayern.kickner.dirl.web.dirlModule
import bayern.kickner.dirl.web.deleteEntry
import bayern.kickner.dirl.web.listDirectory
import bayern.kickner.dirl.web.listEntries
import bayern.kickner.dirl.web.roundTripText
import bayern.kickner.dirl.web.writeAtomically
import bayern.kickner.dirl.web.writeTemporary
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.forms.formData
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.forms.submitFormWithBinaryData
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Headers
import io.ktor.http.HttpStatusCode
import io.ktor.http.HttpHeaders
import io.ktor.http.parameters
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
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
import net.schmizz.sshj.connection.channel.forwarded.RemotePortForwarder
import net.schmizz.sshj.connection.channel.forwarded.SocketForwardingConnectListener
import net.schmizz.sshj.sftp.FileMode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.URLEncoder
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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

    /** A host on loopback. Hosts behind it see it coming from [forTargets], `127.0.0.1` for targets on IPv4 loopback. */
    private fun addHost(name: String, port: Int, keyId: String, jumpHostId: String? = null, pin: PinnedHostKey? = null, jumpOnly: Boolean = false, forTargets: String? = "127.0.0.1"): Host {
        val host = Host(id = name, name = name, address = "127.0.0.1", port = port, username = user, keyId = keyId, jumpHostId = jumpHostId, pinnedHostKey = pin, jumpOnly = jumpOnly, sourceAddressForTargets = forTargets)
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

    /** Whether [client] may open a listening port on its server, what `ssh -R` does. */
    private fun remoteForwardAllowed(client: SSHClient): Boolean {
        val port = ServerSocket(0).use { it.localPort }
        val forward = RemotePortForwarder.Forward("127.0.0.1", port)
        return runCatching { client.remotePortForwarder.bind(forward, SocketForwardingConnectListener(InetSocketAddress("127.0.0.1", 9))) }.isSuccess
    }

    /** A host for file transfers on its own sshd, host key pinned. */
    private fun fileHost(name: String): Host {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty ${key.publicKey} dirl")
        return addHost(name, server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
    }

    /** Dirl on the production engine (CIO) on a free port, [block] gets the port. The test engine cannot cut a request off. */
    private fun onCio(block: (Int) -> Unit) {
        val server = embeddedServer(CIO, port = 0, host = "127.0.0.1") { dirlModule(dirl) }.start(wait = false)
        try {
            block(runBlocking { server.engine.resolvedConnectors().first().port })
        } finally {
            server.stop(100, 1000)
        }
    }

    /**
     * Sends an upload into [dir] over a plain socket: the head announces [declaredLength] bytes, then [body] and whatever
     * [more] writes follow, then the request ends with a clean FIN like a closed browser tab. Returns Dirl's answer,
     * which comes once the upload route is done.
     */
    private fun rawUpload(port: Int, host: Host, dir: File, declaredLength: Int, body: ByteArray, more: (OutputStream) -> Unit = {}): String {
        val token = dirl.sessions.create(actor).token
        val head = "POST /hosts/${host.id}/files/upload?path=${URLEncoder.encode(dir.absolutePath, Charsets.UTF_8)} HTTP/1.1\r\n" +
            "Host: 127.0.0.1\r\nOrigin: https://ssh.example.com\r\nCookie: $SESSION_COOKIE=$token\r\nConnection: close\r\n" +
            "Content-Type: multipart/form-data; boundary=BOUNDARY\r\nContent-Length: $declaredLength\r\n\r\n"
        return Socket("127.0.0.1", port).use { socket ->
            socket.soTimeout = 30_000
            val out = socket.getOutputStream()
            out.write(head.toByteArray())
            out.write(body)
            more(out)
            out.flush()
            socket.shutdownOutput()
            val answer = ByteArrayOutputStream()
            runCatching { socket.getInputStream().copyTo(answer) }.onFailure { if (it !is SocketException) throw it }
            answer.toString(Charsets.UTF_8)
        }
    }

    private fun formPart(name: String, value: String) = "--BOUNDARY\r\nContent-Disposition: form-data; name=\"$name\"\r\n\r\n$value\r\n"

    private fun fileHeader(fileName: String) =
        "--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"$fileName\"\r\nContent-Type: application/octet-stream\r\n\r\n"

    private fun uploadsAudited(dir: File) = dirl.audit.tail(100).filter { it.action == AuditAction.SFTP_UPLOAD && it.detail.orEmpty().startsWith(dir.absolutePath) }.map { it.detail }.toSet()

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
        // The optional parts against the real system the test runs on.
        val raw = metrics.value
        assertEquals(Runtime.getRuntime().availableProcessors(), raw.cores, "nproc")
        assertEquals(ProcessBuilder("uname", "-r").start().inputStream.readBytes().decodeToString().trim(), raw.kernel)
        if (File("/etc/os-release").exists()) assertTrue(raw.osName != null, "PRETTY_NAME from /etc/os-release")
        assertTrue(raw.loggedInUsers != null, "who")
        if (File("/run/systemd/system").isDirectory) assertTrue(raw.failedUnits != null, "systemd runs, its list counts")
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
    fun `every poll measures the round trip, of a pure jump host too, and the overview row shows it`(): Unit = testApplication {
        val near = sshd()
        val far = sshd()
        val key = newKey()
        // 60 ms each way, so the round trip is at least 120 ms and the row turns yellow.
        DelayProxy(far.port, delayMillis = 60).use { slow ->
            val jump = addHost("near", near.port, key.id, pin = PinnedHostKey("ssh-ed25519", near.hostKeyFingerprint, now), jumpOnly = true)
            val remote = addHost("far", slow.port, key.id, pin = PinnedHostKey("ssh-ed25519", far.hostKeyFingerprint, now))
            near.authorize(authorizedKeysLine(jump, key, dirl.vault.content!!.hosts, "127.0.0.1"))
            far.authorize("restrict,pty,from=\"127.0.0.1\" ${key.publicKey} dirl")
            application { dirlModule(dirl) }
            val cookie = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"
            val client = createClient { followRedirects = false }

            val page = dirl.presence.hold {
                withContext(Dispatchers.IO) { dirl.metrics.round(this) }
                client.get("/") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
            }
            val local = assertNotNull(dirl.metrics.latencyMillis(jump.id), "a pure jump host is measured as well")
            assertTrue(local < 50, "loopback: $local ms")
            val delayed = assertNotNull(dirl.metrics.latencyMillis(remote.id))
            assertTrue(delayed >= 120 && delayed < 2_000, "through the delay: $delayed ms")

            fun row(name: String) = page.split("class=\"host-row ").drop(1).first { it.contains(">$name</a>") }
            assertTrue(row("far").startsWith("warn") && row("far").contains("<div class=\"host-ping warn\"") && row("far").contains(">${roundTripText(delayed)}<"), row("far"))
            assertTrue(row("near").startsWith("ok") && row("near").contains("<div class=\"host-ping ok\""), row("near"))
            assertTrue(row("far").contains(">CPU<"), "the slow host still has its metrics")

            // A closed connection answers nothing.
            val connection = (dirl.connections.connection(remote.id) as ResultOf2.Success).value
            connection.disconnect()
            assertNull(roundTripMillis(connection))

            // Nobody is there any more: the round trips are forgotten like the samples.
            now += 31_000
            withContext(Dispatchers.IO) { dirl.metrics.round(this) }
            assertNull(dirl.metrics.latencyMillis(jump.id))
            assertNull(dirl.metrics.latencyMillis(remote.id))
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
        assertTrue(remoteForwardAllowed(jumpClient).not(), "remote forwarding must be refused")
    }

    @Test
    fun `a target behind a jump host accepts the line with the jump host's address, not Dirl's`(): Unit = runBlocking {
        // Dirl reaches the jump host on a non-loopback address, the jump host reaches the target on loopback. So the
        // target sees 127.0.0.1 while Dirl's own source address is the non-loopback one.
        val dirlAddress = java.net.NetworkInterface.networkInterfaces().toList().filter { it.isUp && it.isLoopback.not() }
            .flatMap { it.inetAddresses().toList() }.firstOrNull { it is java.net.Inet4Address }?.hostAddress
        assumeTrue(dirlAddress != null, "No non-loopback IPv4 address")
        val jumpServer = LocalSshd.start(root!!, listen = dirlAddress!!).also { servers += it }
        val targetServer = sshd()
        val key = newKey()
        val jump = addHost("jumpwan", jumpServer.port, key.id, pin = PinnedHostKey("ssh-ed25519", jumpServer.hostKeyFingerprint, now), jumpOnly = true)
            .copy(address = dirlAddress).also { j -> dirl.vault.update { it.copy(hosts = it.hosts.map { h -> if (h.id == j.id) j else h }) } }
        val target = addHost("lan", targetServer.port, key.id, jumpHostId = jump.id, pin = PinnedHostKey("ssh-ed25519", targetServer.hostKeyFingerprint, now))
        val hosts = dirl.vault.content!!.hosts
        jumpServer.authorize(authorizedKeysLine(jump, key, hosts, dirlAddress))
        val targetLine = authorizedKeysLine(target, key, hosts, dirlAddress)
        assertTrue(targetLine.startsWith("restrict,pty,from=\"127.0.0.1\" "), targetLine)
        targetServer.authorize(targetLine)

        val result = dirl.connections.connection(target.id)
        assertIs<ResultOf2.Success<SSHClient>>(result, "state: $result\ntarget sshd log:\n${targetServer.log().lines().takeLast(5).joinToString("\n")}")
        assertTrue(exec(result.value, "echo via-wan-jump").contains("via-wan-jump"))
    }

    @Test
    fun `an IPv6 target behind a restricted jump host is reachable with the generated lines`(): Unit = runBlocking {
        val v6 = runCatching { java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("::1")).close() }.isSuccess
        assumeTrue(v6, "No IPv6 loopback")
        val jumpServer = sshd()
        val targetServer = LocalSshd.start(root!!, listen = "::1").also { servers += it }
        val key = newKey()
        val jump = addHost("jump6", jumpServer.port, key.id, pin = PinnedHostKey("ssh-ed25519", jumpServer.hostKeyFingerprint, now), jumpOnly = true, forTargets = "::1")
        val target = Host(id = "target6", name = "target6", address = "::1", port = targetServer.port, username = user, keyId = key.id, jumpHostId = jump.id, pinnedHostKey = PinnedHostKey("ssh-ed25519", targetServer.hostKeyFingerprint, now))
        dirl.vault.update { it.copy(hosts = it.hosts + target) }
        val content = dirl.vault.content!!
        jumpServer.authorize(authorizedKeysLine(jump, key, content.hosts, "127.0.0.1"))
        targetServer.authorize(authorizedKeysLine(target, key, content.hosts, "127.0.0.1"))

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
        assertTrue(remoteForwardAllowed(jumpClient).not(), "remote forwarding must be refused")
    }

    @Test
    fun `downloads arrive byte for byte around the read-ahead block size`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty ${key.publicKey} dirl")
        val host = addHost("down", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-download").toFile()
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }
        val random = java.util.Random(1)
        // Empty, one byte, around the 32 KiB blocks and past the 16 reads in flight (512 KiB).
        for (size in listOf(0, 1, 32 * 1024 - 1, 32 * 1024, 32 * 1024 + 1, 17 * 32 * 1024 + 7)) {
            val file = File(dir, "f$size").apply { writeBytes(ByteArray(size).also(random::nextBytes)) }
            val response = client.get("/hosts/${host.id}/files/download?path=${file.absolutePath}") { header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}") }
            assertEquals(HttpStatusCode.OK, response.status)
            assertTrue(response.bodyAsBytes().contentEquals(file.readBytes()), "size $size")
        }
        dir.deleteRecursively()
    }

    @Test
    fun `an upload that breaks off while it is written leaves the file it would replace unchanged`() {
        val host = fileHost("cut")
        val dir = Files.createTempDirectory("dirl-cut").toFile()
        val target = File(dir, "backup.tar").apply { writeBytes(ByteArray(8 * 1024 * 1024) { 'O'.code.toByte() }) }
        onCio { port ->
            val head = (formPart("overwrite", "on") + fileHeader("backup.tar")).toByteArray()
            // 10 MiB announced, 3 MiB arrive while Dirl writes, then the connection ends. Ktor reports that end as the
            // normal end of the part, only the missing boundary afterwards shows that the file is incomplete.
            rawUpload(port, host, dir, head.size + 10 * 1024 * 1024, head) { out ->
                out.write(ByteArray(3 * 1024 * 1024) { 'N'.code.toByte() })
                out.flush()
                Thread.sleep(1500)
            }
        }
        val content = target.readBytes()
        assertEquals(8 * 1024 * 1024, content.size, "the existing file keeps its size")
        assertTrue(content.all { it == 'O'.code.toByte() }, "the existing file keeps its content")
        assertEquals(listOf("backup.tar"), dir.list()!!.toList(), "no temporary file may be left behind")
        assertEquals(emptySet(), uploadsAudited(dir), "nothing changed, so nothing is audited")

        // The same for a new file: no truncated file that looks complete.
        val fresh = Files.createTempDirectory("dirl-cut-new").toFile()
        onCio { port ->
            val head = fileHeader("new.tar").toByteArray()
            rawUpload(port, host, fresh, head.size + 10 * 1024 * 1024, head) { out ->
                out.write(ByteArray(3 * 1024 * 1024) { 'N'.code.toByte() })
                out.flush()
                Thread.sleep(1500)
            }
        }
        assertEquals(emptyList(), fresh.list()!!.toList(), "neither the file nor its temporary file may exist")
        dir.deleteRecursively()
        fresh.deleteRecursively()
    }

    @Test
    fun `files that arrived before an upload broke off are kept and audited`() {
        val host = fileHost("partial")

        // Control: a complete request with two files.
        val complete = Files.createTempDirectory("dirl-complete").toFile()
        onCio { port ->
            val body = (fileHeader("a.txt") + "A\r\n" + fileHeader("b.txt") + "B\r\n" + "--BOUNDARY--\r\n").toByteArray()
            val answer = rawUpload(port, host, complete, body.size, body)
            assertTrue(answer.startsWith("HTTP/1.1 302"), answer.lineSequence().first())
        }
        assertEquals("A", File(complete, "a.txt").readText())
        assertEquals("B", File(complete, "b.txt").readText())
        assertEquals(setOf("${complete.absolutePath}/a.txt", "${complete.absolutePath}/b.txt"), uploadsAudited(complete))

        // Two complete files, the third breaks off while it is written.
        val dir = Files.createTempDirectory("dirl-partial").toFile()
        onCio { port ->
            val body = (fileHeader("first.txt") + "FIRST\r\n" + fileHeader("second.txt") + "SECOND\r\n" + fileHeader("third.bin")).toByteArray()
            rawUpload(port, host, dir, body.size + 10 * 1024 * 1024, body) { out ->
                out.write(ByteArray(3 * 1024 * 1024) { 'N'.code.toByte() })
                out.flush()
                Thread.sleep(1500)
            }
        }
        assertEquals("FIRST", File(dir, "first.txt").readText())
        assertEquals("SECOND", File(dir, "second.txt").readText())
        assertEquals(setOf("first.txt", "second.txt"), dir.list()!!.toSet(), "the broken file and its temporary file are gone")
        assertEquals(setOf("${dir.absolutePath}/first.txt", "${dir.absolutePath}/second.txt"), uploadsAudited(dir))

        // The body ends inside the headers of the next part. Ktor hands out a part only with complete headers, so the
        // file before it is not proven complete and is discarded as well. Nothing changes, nothing is audited.
        val headers = Files.createTempDirectory("dirl-partial-headers").toFile()
        onCio { port ->
            val body = (fileHeader("first.txt") + "FIRST\r\n" + "--BOUNDARY\r\nContent-Disposition: form-da").toByteArray()
            rawUpload(port, host, headers, body.size + 30_000, body)
        }
        assertEquals(emptyList(), headers.list()!!.toList(), "neither the file nor its temporary file may exist")
        assertEquals(emptySet(), uploadsAudited(headers))
        listOf(complete, dir, headers).forEach { it.deleteRecursively() }
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

        // A failed upload names the reason from the server, not only the file.
        dir.setWritable(false)
        val failed = upload(overwrite = true).bodyAsText()
        dir.setWritable(true)
        assertTrue(failed.contains("Failed: a.txt (Permission denied)."), failed.substringAfter("notice").take(200))
        dir.deleteRecursively()
    }

    @Test
    fun `renaming onto an existing entry says so and changes nothing`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty ${key.publicKey} dirl")
        val host = addHost("ren", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-rename").toFile()
        File(dir, "a.txt").writeText("a")
        File(dir, "b.txt").writeText("b")
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }

        suspend fun rename(target: String) = client.submitForm("/hosts/${host.id}/files/rename", parameters {
            append("path", File(dir, "a.txt").absolutePath)
            append("target", File(dir, target).absolutePath)
        }) {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}")
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }

        val refused = rename("b.txt")
        assertTrue(refused.bodyAsText().contains("already exists"), "the reason must be shown")
        assertEquals("a", File(dir, "a.txt").readText())
        assertEquals("b", File(dir, "b.txt").readText())
        assertEquals(HttpStatusCode.Found, rename("c.txt").status)
        assertEquals("a", File(dir, "c.txt").readText())

        // A dangling symlink is an existing entry too. OpenSSH would refuse a file with a bare "Failure" and silently
        // replace the link with a directory.
        val link = File(dir, "gone.lnk").toPath()
        Files.createSymbolicLink(link, File(dir, "missing").toPath())
        File(dir, "a.txt").also { File(dir, "c.txt").renameTo(it) }
        assertTrue(rename("gone.lnk").bodyAsText().contains("already exists"), "a dangling link must count as existing")
        File(dir, "a.txt").delete()
        File(dir, "a.txt").mkdir()
        assertTrue(rename("gone.lnk").bodyAsText().contains("already exists"), "a directory must not replace the link")
        assertTrue(Files.isSymbolicLink(link), "the link must stay")
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
        client.openSftp().use { sftp -> writeAtomically(sftp, target.absolutePath, "new äöü\r\n".byteInputStream()) }

        assertEquals("new äöü\r\n", target.readText())
        assertEquals(listOf("config.txt"), dir.list()!!.toList(), "no temporary file may be left behind")

        // A transfer that breaks off, e.g. a closed browser tab during an upload, leaves neither a changed target nor
        // the partial temporary file behind.
        val broken = object : java.io.InputStream() {
            private var sent = 0
            override fun read(): Int = if (sent++ < 100_000) 'x'.code else throw java.io.IOException("connection reset")
        }
        val failure = client.openSftp().use { sftp -> runCatching { writeAtomically(sftp, target.absolutePath, broken) }.exceptionOrNull() }
        assertTrue(failure?.message.orEmpty().contains("connection reset"), "the original error must reach the caller, was: $failure")
        assertEquals("new äöü\r\n", target.readText())
        assertEquals(listOf("config.txt"), dir.list()!!.toList(), "the partial temporary file must be removed")

        // Listings stop at the limit with a message for the user instead of growing without bound.
        repeat(9) { File(dir, "f$it").writeText("x") }
        client.openSftp().use { sftp ->
            assertEquals(10, listDirectory(sftp, dir.absolutePath, max = 10).size)
            val tooMany = runCatching { listDirectory(sftp, dir.absolutePath, max = 5) }.exceptionOrNull()
            assertTrue(tooMany?.message.orEmpty().contains("more than 5 entries"), "was: $tooMany")
        }
        dir.deleteRecursively()
    }

    @Test
    fun `sftp writes keep the permissions and the group of the file they replace`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty ${key.publicKey} dirl")
        val host = addHost("files", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-modes").toFile()
        val client = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        fun mode(f: File) = (Files.getAttribute(f.toPath(), "unix:mode") as Int).and("7777".toInt(8)).toString(8)

        // A private key must not become readable by others, a script must stay executable.
        for ((name, mode) in listOf("id_ed25519" to "600", "backup.sh" to "755", "app.conf" to "640", "tool" to "4750")) {
            val file = File(dir, name).apply { writeText("old") }
            Files.setAttribute(file.toPath(), "unix:mode", mode.toInt(8))
            client.openSftp().use { sftp -> writeAtomically(sftp, file.absolutePath, "new".byteInputStream()) }
            assertEquals("new", file.readText())
            assertEquals(mode, mode(file), name)
        }

        // A file shared through a group keeps that group, the new file would otherwise get the login's primary group.
        val primary = Files.getAttribute(dir.toPath(), "unix:gid") as Int
        val other = ProcessBuilder("id", "-G").start().inputStream.readBytes().decodeToString().trim().split(' ').map { it.toInt() }.firstOrNull { it != primary }
        if (other != null) {
            val shared = File(dir, "shared.conf").apply { writeText("old") }
            Files.setAttribute(shared.toPath(), "unix:gid", other)
            client.openSftp().use { sftp -> writeAtomically(sftp, shared.absolutePath, "new".byteInputStream()) }
            assertEquals("new", shared.readText())
            assertEquals(other, Files.getAttribute(shared.toPath(), "unix:gid"))
        }
        assertTrue(dir.list()!!.none { it.contains(".dirl-tmp") }, "no temporary file may be left behind")
        dir.deleteRecursively()
    }

    @Test
    fun `symlinks list, delete and overwrite like their targets without touching them`(): Unit = runBlocking {
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
        client.openSftp().use { sftp ->
            val entries = listEntries(sftp, dir.absolutePath).associateBy { it.name }
            assertTrue(entries.getValue("linkdir").isDirectory, "a link to a directory must be navigable")
            assertTrue(entries.getValue("linkdir").isLink)
            assertEquals(FileMode.Type.REGULAR, entries.getValue("link.txt").type, "a link to a file must be listed as a file")
            assertEquals(3, entries.getValue("link.txt").size, "size of the target, not of the link")
            assertTrue(entries.getValue("broken").isDirectory.not() && entries.getValue("broken").isLink)
            assertTrue(entries.getValue("real.txt").isLink.not())

            // Overwriting through the link, as an upload does, writes the target and keeps the link.
            writeAtomically(sftp, File(dir, "link.txt").absolutePath, "new".byteInputStream())
            assertTrue(Files.isSymbolicLink(File(dir, "link.txt").toPath()), "the link must survive an overwrite")
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

    /** Opens a terminal WebSocket, returns its first message (error text or shell output) and keeps it open until [hold]. */
    private suspend fun io.ktor.client.HttpClient.firstTerminalMessage(hostId: String, token: String, hold: CompletableDeferred<Unit>?, first: CompletableDeferred<String>) =
        webSocket("/ws/terminal/$hostId?cols=80&rows=24", request = {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=$token")
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }) {
            val frame = withTimeout(15_000) { incoming.receiveCatching().getOrNull() }
            first.complete(if (frame is Frame.Text) frame.readBytes().decodeToString() else "shell")
            hold?.await()
        }

    @Test
    fun `a refused terminal closes its session, so the host stays usable`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        // Without pty every terminal is refused. OpenSSH allows 10 sessions per connection, leftovers would use them up.
        server.authorize("restrict,from=\"127.0.0.1\" ${key.publicKey} dirl")
        val host = addHost("nopty", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }
        val client = createClient { install(WebSockets) }
        repeat(11) {
            val first = CompletableDeferred<String>()
            client.firstTerminalMessage(host.id, session.token, null, first)
            assertTrue(first.await().contains("needs pty"), first.await())
        }
        val ssh = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        assertEquals("ok", exec(ssh, "echo ok").trim())
    }

    @Test
    fun `beyond the session limit of the server terminals and files explain why`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty,from=\"127.0.0.1\" ${key.publicKey} dirl")
        val host = addHost("full", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }
        val client = createClient { install(WebSockets) }
        val plain = createClient { followRedirects = false }
        val hold = CompletableDeferred<Unit>()
        kotlinx.coroutines.coroutineScope {
            // The OpenSSH default MaxSessions is 10, all of them taken by terminals.
            val terminals = (1..10).map {
                val first = CompletableDeferred<String>()
                launch { client.firstTerminalMessage(host.id, session.token, hold, first) }.also { assertEquals("shell", first.await()) }
            }
            val eleventh = CompletableDeferred<String>()
            client.firstTerminalMessage(host.id, session.token, null, eleventh)
            assertTrue(eleventh.await().contains("MaxSessions"), eleventh.await())

            val files = plain.get("/hosts/${host.id}/files") { header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}") }
            assertTrue(files.bodyAsText().contains("MaxSessions"))
            val upload = plain.submitFormWithBinaryData(url = "/hosts/${host.id}/files/upload?path=/tmp", formData = formData {
                append("file", "x".toByteArray(), Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"dirl-full.txt\"") })
            }) {
                header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}")
                header(HttpHeaders.Origin, "https://ssh.example.com")
            }
            assertEquals(HttpStatusCode.BadGateway, upload.status)
            assertTrue(upload.bodyAsText().contains("MaxSessions"))
            hold.complete(Unit)
            terminals.forEach { it.join() }
        }
    }

    @Test
    fun `an SFTP server announcing a huge packet is refused before the buffer exists`(): Unit = runBlocking {
        // A compromised server answers the SFTP start with a header of almost 1 GiB and nothing else. sshj alone
        // would allocate that much at once, with -Xmx256m Dirl would end with an OutOfMemoryError. cat keeps the
        // channel open until Dirl closes it.
        val script = File(Files.createTempDirectory("dirl-evil").toFile(), "evil-sftp.sh").apply {
            writeText("#!/bin/sh\nprintf '\\077\\377\\377\\377'\nexec cat > /dev/null\n")
            setExecutable(true)
        }
        val server = LocalSshd.start(root!!, sftpSubsystem = script).also { servers += it }
        val key = newKey()
        server.authorize("restrict ${key.publicKey} dirl")
        val host = addHost("evil", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val client = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        // More attempts than OpenSSH's 10 sessions per connection: every refused start must close its channel.
        repeat(11) {
            val error = runCatching { client.openSftp() }.exceptionOrNull()
            assertTrue(error?.message.orEmpty().contains("more than the $MAX_SFTP_PACKET Dirl accepts"), "was: $error")
        }
        assertEquals("ok", exec(client, "echo ok").trim())
        script.parentFile.deleteRecursively()
    }

    @Test
    fun `the terminal websocket runs a real shell`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        // A fixed shell instead of the login shell of whoever runs the tests: fish 4 asks the terminal for its features at
        // startup, waits two seconds for an answer this test never gives and can swallow the command sent meanwhile.
        server.authorize("restrict,pty,command=\"/bin/sh -i\",from=\"127.0.0.1\" ${key.publicKey} dirl")
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

    /** Whether [key] logs in on [server] with [line] as its only `authorized_keys` line, straight through sshj. */
    private fun logsIn(server: LocalSshd, key: SshKey, line: String): Boolean {
        server.authorize(line)
        return runCatching {
            SSHClient().use { client ->
                client.addHostKeyVerifier(server.hostKeyFingerprint)
                client.connect("127.0.0.1", server.port)
                client.authPublickey(user, client.loadKeys(key.privateKeyPem, null, null))
                exec(client, "echo ok").trim() == "ok"
            }
        }.getOrDefault(false)
    }

    @Test
    fun `the command from the host page installs a line OpenSSH accepts and retires an older one`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        val host = addHost("installed", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val line = authorizedKeysLine(host, key, dirl.vault.content!!.hosts, "127.0.0.1")
        val command = assertNotNull(authorizedKeysCommand(line, key.publicKey))

        // An outdated line of the same key comes first and allows another address only, as after a changed source.
        val home = Files.createTempDirectory("dirl-home").toFile()
        val file = File(home, ".ssh/authorized_keys").apply { parentFile.mkdirs() }
        file.writeText("restrict,pty,from=\"192.0.2.9\" ${key.publicKey} dirl\nssh-ed25519 AAAAOTHER other@laptop\n")
        fun logsIn(): Boolean {
            server.authorize(*file.readLines().toTypedArray())
            return runCatching {
                SSHClient().use { client ->
                    client.addHostKeyVerifier(server.hostKeyFingerprint)
                    client.connect("127.0.0.1", server.port)
                    client.authPublickey(user, client.loadKeys(key.privateKeyPem, null, null))
                    exec(client, "echo ok").trim() == "ok"
                }
            }.getOrDefault(false)
        }
        assertFalse(logsIn(), "the outdated line keeps Dirl out")

        val shell = ProcessBuilder("sh", "-c", command).apply { environment()["HOME"] = home.absolutePath; redirectErrorStream(true) }.start()
        val output = shell.inputStream.readBytes().decodeToString()
        assertEquals(0, shell.waitFor(), output)
        assertEquals(listOf("ssh-ed25519 AAAAOTHER other@laptop", line), file.readLines())
        assertTrue(logsIn(), server.log())
        home.deleteRecursively()
    }

    @Test
    fun `OpenSSH refuses the whole line for source entries Dirl normalizes or rejects`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        fun line(from: String) = "restrict,pty,from=\"$from\" ${key.publicKey} dirl"
        assertTrue(logsIn(server, key, line("127.0.0.1")), server.log())
        assertTrue(logsIn(server, key, line("192.0.2.9,127.0.0.1")), "Dirl's address second in a list")
        assertTrue(logsIn(server, key, line("127.0.0.1,192.0.2.9")), "Dirl's address first in a list")
        assertFalse(logsIn(server, key, line("192.0.2.9,198.51.100.7")), "no entry matches")

        for (raw in listOf("192.0.2.9, 127.0.0.1", "127.0.0.1,", "127.0.0.1,,192.0.2.9")) {
            assertFalse(logsIn(server, key, line(raw)), "OpenSSH accepted \"$raw\", the normalization may no longer be needed")
            val normalized = assertIs<ResultOf2.Success<String?>>(normalizeSourceAddress(raw)).value!!
            assertTrue(logsIn(server, key, line(normalized)), "\"$raw\" normalized to \"$normalized\"")
        }
        for (raw in listOf("127.0.0.1/8", "127.0.0.1,192.0.2.0/33")) {
            assertFalse(logsIn(server, key, line(raw)), "OpenSSH accepted \"$raw\"")
            assertIs<ResultOf2.Failure<String>>(normalizeSourceAddress(raw), raw)
        }
        for (accepted in listOf("127.0.0.0/8", "192.0.2.0/24,127.0.0.1", "127.0.0.*", "!192.0.2.9,127.0.0.1")) {
            assertTrue(logsIn(server, key, line(accepted)), accepted)
            assertEquals(accepted, assertIs<ResultOf2.Success<String?>>(normalizeSourceAddress(accepted)).value)
        }
        // Host names only match with UseDNS yes, which is off by default.
        assertFalse(logsIn(server, key, line("localhost")))
    }

    @Test
    fun `the line the host page shows for several source addresses lets Dirl in`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        val host = addHost("multi", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"
        suspend fun save(address: String, unrestricted: Boolean = false) = client.submitForm(
            "/settings/ssh",
            parameters { append("sshSourceAddress", address); if (unrestricted) append("sshSourceUnrestricted", "on") },
        ) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        suspend fun pageLine(): String {
            val page = client.get("/hosts/${host.id}") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
            return Regex("restrict,[^<]* dirl").find(page)!!.value.replace("&quot;", "\"").replace("&#34;", "\"")
        }
        suspend fun connects(): Boolean {
            dirl.connections.disconnectAll()
            // Past any backoff from an earlier refused attempt.
            now += 3_600_000
            return dirl.connections.connection(host.id) is ResultOf2.Success
        }

        // A LAN address and a public one, typed with a space after the comma, Dirl's address is the second.
        assertEquals("/settings?done=settings-saved", save("192.0.2.9, 127.0.0.1").headers[HttpHeaders.Location])
        val line = pageLine()
        assertEquals("restrict,pty,from=\"192.0.2.9,127.0.0.1\" ${key.publicKey} dirl", line)
        server.authorize(line)
        assertTrue(connects(), server.log())
        assertEquals("ok", exec((dirl.connections.connection(host.id) as ResultOf2.Success).value, "echo ok").trim())

        save("127.0.0.1 192.0.2.9")
        server.authorize(pageLine())
        assertTrue(connects(), "Dirl's address first, separated by a space")

        save("192.0.2.9, 198.51.100.7")
        server.authorize(pageLine())
        assertFalse(connects(), "neither address is Dirl's")

        // A rejected input changes nothing.
        val rejected = save("127.0.0.1/8")
        assertEquals(HttpStatusCode.BadRequest, rejected.status)
        val rejectedPage = rejected.bodyAsText()
        assertTrue(rejectedPage.contains("Did you mean 127.0.0.0/8?"))
        assertTrue(rejectedPage.contains("value=\"127.0.0.1/8\""), "the field keeps what was typed")
        assertEquals("192.0.2.9,198.51.100.7", dirl.vault.content!!.settings.sshSourceAddress)

        // Without the restriction the line has no from= and the address is kept for later.
        save("192.0.2.9", unrestricted = true)
        val unrestricted = pageLine()
        assertEquals("restrict,pty ${key.publicKey} dirl", unrestricted)
        server.authorize(unrestricted)
        assertTrue(connects())
        assertEquals("192.0.2.9", dirl.vault.content!!.settings.sshSourceAddress)
        assertEquals("sshSourceAddress=192.0.2.9 sshSourceUnrestricted=on", dirl.audit.tail().first { it.action == AuditAction.SETTINGS_CHANGED }.detail)
    }

    @Test
    fun `entries planted under the temporary name are never followed or written`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict ${key.publicKey} dirl")
        val host = addHost("planted", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-planted").toFile()
        val client = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        fun mode(f: File) = (Files.getAttribute(f.toPath(), "unix:mode") as Int).and("7777".toInt(8)).toString(8)
        fun setMode(f: File, m: String) = Files.setAttribute(f.toPath(), "unix:mode", m.toInt(8))

        // Another user who can write to the directory plants links under the names Dirl used to use, towards a file
        // of the login, and a file of their own they keep open to read along.
        val victim = File(dir, "victim").apply { writeText("victim") }.also { setMode(it, "644") }
        val conf = File(dir, "app.conf").apply { writeText("old") }.also { setMode(it, "600") }
        val secret = File(dir, "id_ed25519").apply { writeText("old") }.also { setMode(it, "600") }
        val planted = listOf(".new.txt.dirl-tmp", ".app.conf.dirl-tmp").map { File(dir, it) }
        planted.forEach { Files.createSymbolicLink(it.toPath(), victim.toPath()) }
        val spyFile = File(dir, ".id_ed25519.dirl-tmp").apply { writeText("") }.also { setMode(it, "666") }

        java.io.FileInputStream(spyFile).use { spy ->
            client.openSftp().use { sftp ->
                writeAtomically(sftp, File(dir, "new.txt").absolutePath, "upload".byteInputStream())
                writeAtomically(sftp, conf.absolutePath, "new conf".byteInputStream())
                writeAtomically(sftp, secret.absolutePath, "PRIVATE KEY".byteInputStream())
            }
            assertEquals("", spy.readAllBytes().decodeToString(), "a planted file must not see the upload")
        }
        assertEquals("victim", victim.readText(), "a planted link must not redirect the write")
        assertEquals("644", mode(victim), "a planted link must not redirect the permissions")
        assertEquals("upload", File(dir, "new.txt").readText())
        assertTrue(Files.isSymbolicLink(File(dir, "new.txt").toPath()).not())
        assertEquals("new conf", conf.readText())
        assertTrue(Files.isSymbolicLink(conf.toPath()).not())
        assertEquals("600", mode(conf))
        assertEquals("PRIVATE KEY", secret.readText())
        assertEquals("600", mode(secret))
        assertTrue(planted.all { Files.isSymbolicLink(it.toPath()) } && spyFile.readText().isEmpty(), "planted entries stay untouched")
        assertEquals(listOf("app.conf", "id_ed25519", "new.txt", "victim"), dir.list()!!.filterNot { File(dir, it) in planted + spyFile }.sorted())
        dir.deleteRecursively()
    }

    @Test
    fun `a failed commit never costs the target, without overwrite a file created meanwhile stays`(): Unit = runBlocking {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict ${key.publicKey} dirl")
        val host = addHost("commit", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-commit").toFile()
        val target = File(dir, "data.txt").apply { writeText("precious") }
        val client = (dirl.connections.connection(host.id) as ResultOf2.Success).value
        client.openSftp().use { sftp ->
            // The temporary file vanishes before the commit, e.g. removed by somebody else. The rename fails, the
            // target must not have been removed for it.
            val vanished = writeTemporary(sftp, target.absolutePath, "new".byteInputStream())
            File(vanished.tmp).delete()
            assertTrue(runCatching { commitWrite(sftp, vanished, overwrite = true) }.isFailure)
            assertEquals("precious", target.readText())

            // Without overwrite a file that appeared after the upload checked for it is kept, the temporary file goes.
            val fresh = File(dir, "fresh.txt")
            val write = writeTemporary(sftp, fresh.absolutePath, "mine".byteInputStream())
            fresh.writeText("theirs")
            val error = runCatching { commitWrite(sftp, write, overwrite = false) }.exceptionOrNull()
            assertTrue(error?.message.orEmpty().contains("created by somebody else during the upload"), "was: $error")
            assertEquals("theirs", fresh.readText())
        }
        assertEquals(listOf("data.txt", "fresh.txt"), dir.list()!!.sorted(), "no temporary file may be left behind")
        dir.deleteRecursively()
    }

    @Test
    fun `normal uploads through the page write new files, overwrite keeping the mode and leave nothing behind`(): Unit = testApplication {
        val server = sshd()
        val key = newKey()
        server.authorize("restrict,pty ${key.publicKey} dirl")
        val host = addHost("normal", server.port, key.id, pin = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now))
        val dir = Files.createTempDirectory("dirl-normal").toFile()
        fun mode(f: File) = (Files.getAttribute(f.toPath(), "unix:mode") as Int).and("7777".toInt(8)).toString(8)
        val existing = File(dir, "id_ed25519").apply { writeText("old") }
        Files.setAttribute(existing.toPath(), "unix:mode", "600".toInt(8))
        val real = File(dir, "real.conf").apply { writeText("old") }
        Files.createSymbolicLink(File(dir, "link.conf").toPath(), real.toPath())
        val session = dirl.sessions.create(actor)
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        val big = ByteArray(5 * 1024 * 1024 + 123).also { java.util.Random(7).nextBytes(it) }

        val response = client.submitFormWithBinaryData(
            url = "/hosts/${host.id}/files/upload?path=${dir.absolutePath}",
            formData = formData {
                append("overwrite", "on")
                append("file", big, Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"big.bin\"") })
                append("file", "new key".toByteArray(), Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"id_ed25519\"") })
                append("file", "through the link".toByteArray(), Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"link.conf\"") })
                append("file", "äöü\r\n".toByteArray(), Headers.build { append(HttpHeaders.ContentDisposition, "filename=\"notes.txt\"") })
            },
        ) {
            header(HttpHeaders.Cookie, "$SESSION_COOKIE=${session.token}")
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        assertEquals(HttpStatusCode.Found, response.status, response.bodyAsText().substringAfter("notice").take(200))
        assertTrue(response.headers[HttpHeaders.Location].orEmpty().endsWith("&done=uploaded"))
        assertTrue(File(dir, "big.bin").readBytes().contentEquals(big), "a large binary file arrives byte for byte")
        assertEquals("new key", existing.readText())
        assertEquals("600", mode(existing), "an overwritten private key stays private")
        assertEquals("through the link", real.readText())
        assertTrue(Files.isSymbolicLink(File(dir, "link.conf").toPath()), "the link stays a link")
        assertEquals("äöü\r\n", File(dir, "notes.txt").readText())
        assertEquals(listOf("big.bin", "id_ed25519", "link.conf", "notes.txt", "real.conf"), dir.list()!!.sorted(), "no temporary file may be left behind")
        assertEquals(
            setOf("big.bin", "id_ed25519", "link.conf", "notes.txt").map { "${dir.absolutePath}/$it" }.toSet(),
            uploadsAudited(dir),
        )
        dir.deleteRecursively()
    }

    @Test
    fun `an upload that outlasts the session writes nothing after it ended`() {
        val host = fileHost("outlast")
        val dir = Files.createTempDirectory("dirl-outlast").toFile()
        val first = (fileHeader("first.txt") + "FIRST\r\n").toByteArray()
        val rest = (fileHeader("second.txt") + "SECOND\r\n--BOUNDARY--\r\n").toByteArray()
        lateinit var answer: String
        onCio { port ->
            // The first file is on its way when the user logs out or is removed, the second one follows afterwards.
            answer = rawUpload(port, host, dir, first.size + rest.size, first) { out ->
                out.flush()
                Thread.sleep(500)
                dirl.sessions.removeAllFor(actor.sub)
                out.write(rest)
            }
        }
        assertTrue(answer.startsWith("HTTP/1.1 401"), answer.lineSequence().first())
        assertEquals(emptyList(), dir.list()!!.toList(), "nothing is written once the session ended, no temporary file stays")
        assertEquals(emptySet(), uploadsAudited(dir))
        dir.deleteRecursively()
    }
}
