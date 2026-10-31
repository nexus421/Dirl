package bayern.kickner.dirl

import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.dev.MockOidcProvider
import bayern.kickner.dirl.dev.MockUser
import bayern.kickner.dirl.ssh.LocalSshd
import bayern.kickner.dirl.web.LOGIN_COOKIE
import bayern.kickner.dirl.web.SESSION_COOKIE
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import java.io.File
import java.net.ServerSocket
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.WebSocket
import java.nio.ByteBuffer
import java.nio.file.Files
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Runs the Docker image the way docs/deployment.md "Docker" tells users to: restricted like deploy/docker-compose.yml,
 * config mounted read-only, config and data directory owned by UID 10001. Then it goes through a whole first run
 * against the container: login through the mock provider, vault setup, key, host, host key, a command in the
 * terminal, a restart and the unlock afterwards.
 *
 * Runs through `./gradlew dockerImageTest` with `DIRL_DOCKER_IMAGE` (the image to test) and an sshd, otherwise it is
 * skipped. The container shares the network of the test (`--network host`), so the mock provider and the sshd on
 * loopback are reachable and `http://localhost` is allowed as issuer. The port mapping of the compose file is
 * therefore not covered.
 */
class DockerImageTest {
    private val image = System.getenv("DIRL_DOCKER_IMAGE")?.takeIf { it.isNotBlank() }
    private val root = LocalSshd.findRoot()
    private val passphrase = "docker image test ${randomToken(12)}"
    private val container = "dirl-image-test-${ProcessHandle.current().pid()}"
    private val port = ServerSocket(0).use { it.localPort }
    private val publicUrl = "http://localhost:$port"
    private val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).build()
    private lateinit var dir: File
    private lateinit var mock: MockOidcProvider
    private lateinit var sshd: LocalSshd

    @BeforeEach
    fun start() {
        assumeTrue(image != null, "DIRL_DOCKER_IMAGE not set, run ./gradlew dockerImageTest")
        assumeTrue(root != null, "No sshd found, set DIRL_SSHD_ROOT or install openssh-server")
        mock = MockOidcProvider(autoLogin = MockUser("docker-ada", "Ada Lovelace"))
        sshd = LocalSshd.start(root!!)
        dir = Files.createTempDirectory("dirl-docker").toFile()
        File(dir, "data").mkdir()
        val config = AppConfig(
            host = "0.0.0.0",
            port = port,
            publicUrl = publicUrl,
            oidc = OidcConfig(issuer = mock.issuer, clientId = "dirl", clientSecret = mock.clientSecret),
        )
        File(dir, "config.json").writeText(Json.encodeToString(AppConfig.serializer(), config))
        // The owner and modes docs/deployment.md asks for. The test user cannot chown, a throwaway container can.
        asRoot("chown 10001:10001 /work/data /work/config.json && chmod 0700 /work/data && chmod 0400 /work/config.json")
        docker(
            "run", "-d", "--name", container, "--network", "host",
            "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--ulimit", "core=0", "--memory", "512m", "--memory-swap", "512m",
            "-v", "$dir/config.json:/etc/dirl/config.json:ro", "-v", "$dir/data:/var/lib/dirl",
            image!!,
        )
    }

    @AfterEach
    fun stop() {
        if (image == null) return
        runCatching { docker("rm", "-f", container) }
        if (::dir.isInitialized) {
            val owner = "${Files.getAttribute(dir.toPath(), "unix:uid")}:${Files.getAttribute(dir.toPath(), "unix:gid")}"
            runCatching { asRoot("chown -R $owner /work") }
            dir.deleteRecursively()
        }
        if (::sshd.isInitialized) sshd.close()
        if (::mock.isInitialized) mock.close()
    }

    @Test
    fun `the image runs a first start and keeps its vault over a restart`(): Unit {
        awaitHealthy()
        var session = login()
        assertEquals("/unlock", location(get("/", session)))
        assertEquals("/", location(post("/setup", session, "passphrase" to passphrase, "confirm" to passphrase)), "vault setup")

        // In the host network the container reaches the sshd from loopback, so that is the from= of the key line.
        assertEquals("/settings?done=settings-saved", location(post("/settings/ssh", session, "sshSourceAddress" to "127.0.0.1")))
        assertEquals(302, post("/keys/generate", session, "name" to "docker").statusCode())
        val keys = get("/keys", session).body()
        val keyId = Regex("/keys/([^/\"]+)/rename").find(keys)?.groupValues?.get(1) ?: fail("No key on /keys")
        val keyLine = Regex("restrict,pty,from=[^<]+").find(keys)?.value?.replace("&quot;", "\"") ?: fail("No authorized_keys line on /keys")
        sshd.authorize(keyLine)

        val added = post(
            "/hosts", session,
            "name" to "docker-sshd", "address" to "127.0.0.1", "port" to "${sshd.port}",
            "username" to System.getProperty("user.name"), "keyId" to keyId,
        )
        val hostId = Regex("^/hosts/([^/?]+)\\?done=host-added$").find(location(added).orEmpty())?.groupValues?.get(1)
            ?: fail("Host not added, HTTP ${added.statusCode()}")
        // The first connection stops at the unknown host key, then the fingerprint the test knows pins it.
        post("/hosts/$hostId/connect", session)
        assertEquals("/hosts/$hostId?done=pinned", location(post("/hosts/$hostId/pin", session, "fingerprint" to sshd.hostKeyFingerprint)))
        // The shell computes the number, so the echo of the typed line cannot match. Works in sh, bash and fish.
        assertEquals("dirl-docker-42", terminal(session, hostId, "expr 6 \\* 7 | sed 's/^/dirl-docker-/'\n", Regex("dirl-docker-\\d+")))

        docker("restart", container)
        awaitHealthy()
        session = login()
        assertEquals("/unlock", location(get("/", session)), "the vault must be sealed after the restart")
        assertEquals("/", location(post("/unlock", session, "passphrase" to passphrase)), "unlock")
        assertTrue(get("/hosts/$hostId", session).body().contains("docker-sshd"), "the host must survive the restart")

        val files = docker("exec", container, "ls", "/var/lib/dirl")
        assertTrue("vault.json" in files, files)
        val log = docker("exec", container, "cat", "/var/lib/dirl/logs/app.log")
        assertTrue(log.contains("Loaded OIDC discovery document"), log)
        assertTrue(log.contains(passphrase).not() && docker("logs", container).contains(passphrase).not(), "The passphrase must never be logged")
    }

    /** Runs `docker` with [args] and returns its output, fails unless it exits with 0. */
    private fun docker(vararg args: String): String {
        val process = ProcessBuilder("docker", *args).redirectErrorStream(true).start()
        val output = process.inputStream.readBytes().decodeToString()
        check(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0) { "docker ${args.first()} failed: $output" }
        return output
    }

    /** Runs [script] as root in a throwaway container of the image, with the test directory at `/work`. */
    private fun asRoot(script: String) {
        docker("run", "--rm", "--user", "0:0", "--network", "none", "--entrypoint", "/bin/sh", "-v", "$dir:/work", image!!, "-c", script)
    }

    /** Waits until `/healthz` answers, fails with the container log if the container stops or never gets there. */
    private fun awaitHealthy() {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
        while (System.nanoTime() < deadline) {
            val status = runCatching { http.send(request("/healthz").build(), HttpResponse.BodyHandlers.discarding()).statusCode() }.getOrNull()
            if (status == 200) return
            check(docker("inspect", "-f", "{{.State.Running}}", container).trim() == "true") { "Container stopped: ${docker("logs", container)}" }
            Thread.sleep(250)
        }
        fail("No /healthz within 60 s: ${docker("logs", container)}")
    }

    /**
     * The browser's part of the login: start, the mock provider (logs in right away), callback. The cookies are sent
     * by hand, the JDK's cookie handling never sends `Secure` cookies over `http`.
     *
     * @return the session cookie as `name=value`.
     */
    private fun login(): String {
        val start = http.send(request("/auth/start").build(), HttpResponse.BodyHandlers.discarding())
        val loginCookie = start.headers().allValues("Set-Cookie").first { it.startsWith("$LOGIN_COOKIE=") }.substringBefore(';')
        val provider = http.send(HttpRequest.newBuilder(URI(location(start)!!)).build(), HttpResponse.BodyHandlers.discarding())
        val callback = http.send(
            HttpRequest.newBuilder(URI(location(provider)!!)).header("Cookie", loginCookie).build(),
            HttpResponse.BodyHandlers.discarding(),
        )
        return callback.headers().allValues("Set-Cookie")
            .firstOrNull { it.startsWith("$SESSION_COOKIE=") && it.startsWith("$SESSION_COOKIE=;").not() }
            ?.substringBefore(';')
            ?: fail("Login created no session, HTTP ${callback.statusCode()}")
    }

    /**
     * Opens the terminal of [hostId], types [input] and returns the first output that matches [expected]. [input] is
     * typed up to four times, a shell may drop what arrives while it starts. An error message from Dirl (a text
     * frame) or a closed socket fails right away.
     */
    private fun terminal(cookie: String, hostId: String, input: String, expected: Regex): String {
        val found = CompletableFuture<String>()
        val output = StringBuilder()
        val lastOutput = AtomicLong(System.nanoTime())
        val listener = object : WebSocket.Listener {
            override fun onBinary(webSocket: WebSocket, data: ByteBuffer, last: Boolean): CompletionStage<*>? {
                val text = ByteArray(data.remaining()).also(data::get).decodeToString()
                lastOutput.set(System.nanoTime())
                synchronized(output) {
                    output.append(text)
                    expected.find(output)?.let { found.complete(it.value) }
                }
                webSocket.request(1)
                return null
            }

            override fun onText(webSocket: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
                found.completeExceptionally(AssertionError("Terminal reported: $data"))
                webSocket.request(1)
                return null
            }

            override fun onClose(webSocket: WebSocket, statusCode: Int, reason: String): CompletionStage<*>? {
                found.completeExceptionally(AssertionError("Terminal closed: $statusCode $reason"))
                return null
            }
        }
        val socket = http.newWebSocketBuilder().header("Cookie", cookie).header("Origin", publicUrl)
            .buildAsync(URI("ws://localhost:$port/ws/terminal/$hostId"), listener)
            .get(30, TimeUnit.SECONDS)
        val match = (1..4).firstNotNullOfOrNull {
            // Typed once the shell is quiet, i.e. shows its prompt. fish, for one, waits two seconds for answers to
            // terminal queries at the start and drops what arrives meanwhile.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
            while (System.nanoTime() - lastOutput.get() < TimeUnit.MILLISECONDS.toNanos(2500) && System.nanoTime() < deadline) Thread.sleep(100)
            socket.sendBinary(ByteBuffer.wrap(input.encodeToByteArray()), true).get(10, TimeUnit.SECONDS)
            runCatching { found.get(5, TimeUnit.SECONDS) }
                .onFailure { e -> if (e !is TimeoutException) fail("Terminal failed: ${synchronized(output) { output.toString() }}", e) }
                .getOrNull()
        } ?: fail("No match for $expected in the terminal output: ${synchronized(output) { output.toString() }}")
        socket.sendClose(WebSocket.NORMAL_CLOSURE, "")
        return match
    }

    private fun request(path: String, cookie: String? = null): HttpRequest.Builder =
        HttpRequest.newBuilder(URI(publicUrl + path)).timeout(Duration.ofSeconds(30)).apply { if (cookie != null) header("Cookie", cookie) }

    private fun get(path: String, cookie: String): HttpResponse<String> =
        http.send(request(path, cookie).build(), HttpResponse.BodyHandlers.ofString())

    /** Posts [fields] as a form, with the `Origin` header every non-GET request needs. */
    private fun post(path: String, cookie: String, vararg fields: Pair<String, String>): HttpResponse<String> {
        val body = fields.joinToString("&") { (name, value) -> "${encode(name)}=${encode(value)}" }
        val request = request(path, cookie)
            .header("Origin", publicUrl)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        return http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    private fun encode(value: String): String = URLEncoder.encode(value, Charsets.UTF_8)

    private fun location(response: HttpResponse<*>): String? = response.headers().firstValue("Location").orElse(null)
}
