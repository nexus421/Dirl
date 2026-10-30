package bayern.kickner.dirl.dev

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.config.UnlockMode
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.restrictToOwner
import bayern.kickner.dirl.secureRandom
import bayern.kickner.dirl.ssh.LocalSshd
import bayern.kickner.dirl.ssh.authorizedKeysLine
import bayern.kickner.dirl.ssh.generateEd25519Key
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.OverviewMetric
import bayern.kickner.dirl.vault.PinnedHostKey
import bayern.kickner.dirl.vault.Snippet
import bayern.kickner.dirl.web.tmuxSnippets
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.system.exitProcess

/** Port of the demo instance. */
const val DEMO_PORT = 18090

/** Port of the mock OIDC provider of the demo, it logs in Ada right away. */
const val DEMO_OIDC_PORT = 18091

/**
 * Starts Dirl with demo data to look at the UI: `./gradlew demoRun` with an sshd (system, `DIRL_SSHD_ROOT` or
 * `build/sshd-root`), then open
 * `http://localhost:18090`. Every start begins from scratch in `build/demo`.
 *
 * The hosts are real OpenSSH servers on loopback (see [LocalSshd]): a pinned host, a pure jump host with a host behind
 * it, a slow host behind a [DelayProxy], two hosts whose metrics are partly replaced (full disk, reboot needed, a
 * failed service, more load), a host that is offline and one whose host key is not confirmed yet. The vault unlocks
 * with a key file and the mock provider logs in Ada without asking, so the overview opens after one "Sign in".
 */
fun main() {
    // An unpacked openssh-server in build/sshd-root works as well, so the demo needs no environment variable.
    val root = LocalSshd.findRoot() ?: File("build/sshd-root").absoluteFile.takeIf { File(it, "usr/sbin/sshd").canExecute() } ?: run {
        System.err.println("No sshd found. Set DIRL_SSHD_ROOT or unpack openssh-server into build/sshd-root, see docs/development.md.")
        exitProcess(1)
    }
    val dir = File("build/demo").apply { deleteRecursively(); mkdirs() }
    val dataDir = File(dir, "data").apply { mkdirs() }
    val keyFile = File(dir, "kek").apply { writeBytes(ByteArray(32).also(secureRandom::nextBytes)) }
    restrictToOwner(keyFile)
    val ada = MockUser("dev-ada", "Ada Lovelace")
    val oidc = MockOidcProvider(DEMO_OIDC_PORT, autoLogin = ada)
    val config = AppConfig(
        port = DEMO_PORT,
        publicUrl = "http://localhost:$DEMO_PORT",
        dataDir = dataDir.absolutePath,
        unlockMode = UnlockMode.KEYFILE,
        keyFile = keyFile.absolutePath,
        oidc = OidcConfig(issuer = oidc.issuer, clientId = "dirl-demo", clientSecret = oidc.clientSecret, forceReauth = false),
    )

    val servers = mutableListOf<LocalSshd>()
    fun sshd() = LocalSshd.start(root).also { servers += it }
    val shell = demoShell(dir, root)
    val key = generateEd25519Key("dirl-demo")
    val user = System.getProperty("user.name")
    val now = System.currentTimeMillis()
    fun pin(server: LocalSshd) = PinnedHostKey("ssh-ed25519", server.hostKeyFingerprint, now)

    val web = sshd()
    val bastion = sshd()
    val app = sshd()
    val db = sshd()
    val staging = sshd()
    val fresh = sshd()
    // About 70 ms each way, so db-02 shows a slow round trip.
    val slow = DelayProxy(db.port, delayMillis = 70)
    val offlinePort = ServerSocket(0).use { it.localPort }
    val extra = setOf(OverviewMetric.LOAD, OverviewMetric.UPTIME, OverviewMetric.SYSTEM)

    val hosts = listOf(
        Host("web", "web-01", "127.0.0.1", web.port, user, key.id, tags = listOf("prod", "web"), pinnedHostKey = pin(web), pinned = true,
            overview = setOf(OverviewMetric.CPU, OverviewMetric.RAM, OverviewMetric.DISK) + extra),
        Host("bastion", "bastion", "127.0.0.1", bastion.port, user, key.id, tags = listOf("infra"), jumpOnly = true, pinnedHostKey = pin(bastion),
            sourceAddressForTargets = "127.0.0.1", pinned = true),
        Host("app", "app-01", "127.0.0.1", app.port, user, key.id, jumpHostId = "bastion", tags = listOf("prod", "app"), pinnedHostKey = pin(app)),
        Host("db", "db-02", "127.0.0.1", slow.port, user, key.id, tags = listOf("prod", "database"), pinnedHostKey = pin(db),
            overview = setOf(OverviewMetric.CPU, OverviewMetric.RAM, OverviewMetric.DISK, OverviewMetric.REBOOT, OverviewMetric.FAILED_SERVICES, OverviewMetric.ZRAM, OverviewMetric.UPTIME)),
        Host("staging", "staging", "127.0.0.1", staging.port, user, key.id, tags = listOf("staging"), pinnedHostKey = pin(staging),
            overview = setOf(OverviewMetric.CPU, OverviewMetric.RAM, OverviewMetric.DISK) + extra),
        Host("backup", "backup", "127.0.0.1", offlinePort, user, key.id, tags = listOf("home")),
        Host("fresh", "new-box", "127.0.0.1", fresh.port, user, key.id, tags = listOf("home")),
    )
    // Every host but the jump host gets the demo shell, so its terminal shows its own name in a plain bash.
    fun line(host: Host, profile: String? = null): String {
        val base = authorizedKeysLine(host, key, hosts, "127.0.0.1")
        val profilePath = profile?.let { File(dir, it).absolutePath } ?: "-"
        return "command=\"${shell.absolutePath} $profilePath ${host.name}\"," + base
    }
    web.authorize(line(hosts[0]))
    bastion.authorize(authorizedKeysLine(hosts[1], key, hosts, "127.0.0.1"))
    app.authorize(line(hosts[2]))
    db.authorize(line(hosts[3], "db.profile"))
    staging.authorize(line(hosts[4], "staging.profile"))
    fresh.authorize(line(hosts[6]))
    writeProfiles(dir)

    val dirl = createDirl(config, dataDir)
    val actor = Actor(ada.sub, ada.name)
    dirl.vault.setup("demo passphrase, never use it for anything".toCharArray(), actor)
    dirl.vault.update {
        it.copy(
            keys = listOf(key),
            hosts = hosts,
            snippets = demoSnippets(),
            // No request to GitHub from a demo.
            settings = it.settings.copy(sshSourceAddress = "127.0.0.1", updateCheck = false),
        )
    }
    dirl.vault.seal(actor)

    Runtime.getRuntime().addShutdownHook(thread(start = false) { servers.forEach { it.close() }; slow.close() })
    println("Demo: http://localhost:$DEMO_PORT (Sign in logs in ${ada.name} right away)")
    val configFile = File(dir, "config.json")
    configFile.writeText(
        """
        {
          "port": ${config.port},
          "publicUrl": "${config.publicUrl}",
          "dataDir": "${config.dataDir}",
          "unlockMode": "keyfile",
          "keyFile": "${config.keyFile}",
          "oidc": { "issuer": "${oidc.issuer}", "clientId": "dirl-demo", "clientSecret": "${oidc.clientSecret}", "forceReauth": false }
        }
        """.trimIndent()
    )
    bayern.kickner.dirl.main(arrayOf("config=${configFile.absolutePath}"))
}

/**
 * The forced command of the demo hosts, called with a profile (or `-`) and the host name: the metrics command gets
 * some of its parts replaced by the profile, a terminal gets a plain bash with the host name in its prompt and no
 * history file, SFTP the real `sftp-server`. A profile is a file of `@@name` blocks like the metrics output itself.
 */
private fun demoShell(dir: File, root: File): File {
    val sftp = listOf("usr/lib/openssh/sftp-server", "usr/libexec/openssh/sftp-server", "usr/libexec/sftp-server")
        .map { File(root, it) }.firstOrNull { it.canExecute() }?.absolutePath ?: "false"
    val script = File(dir, "demo-shell.sh")
    script.writeText(
        """
        #!/bin/sh
        profile="${'$'}1"
        name="${'$'}2"
        case "${'$'}SSH_ORIGINAL_COMMAND" in
          *@@uptime*) if [ "${'$'}profile" = "-" ]; then exec sh -c "${'$'}SSH_ORIGINAL_COMMAND"; fi
            sh -c "${'$'}SSH_ORIGINAL_COMMAND" | awk -v profile="${'$'}profile" '
              BEGIN { while ((getline line < profile) > 0) { if (line ~ /^@@/) { name = line; seen[name] = 1 } else over[name] = over[name] line "\n" } }
              /^@@/ { skip = ($0 in seen); printf "%s\n", $0; if (skip) printf "%s", over[$0]; next }
              !skip { print }' ;;
          sftp|internal-sftp|*sftp-server*) exec $sftp ;;
          "") cd "${'$'}HOME"; exec env HISTFILE= PS1="\\u@${'$'}name:\\w\\$ " bash --norc --noprofile -i ;;
          *) exec sh -c "${'$'}SSH_ORIGINAL_COMMAND" ;;
        esac
        """.trimIndent() + "\n"
    )
    script.setExecutable(true)
    return script
}

/** Metrics parts the demo replaces: db-02 is full and needs attention, staging is busy. */
private fun writeProfiles(dir: File) {
    File(dir, "db.profile").writeText(
        """
        @@cpu
        cpu  10000 0 0 90000 0 0 0 0 0 0
        cpu  10220 0 0 90780 0 0 0 0 0 0
        @@mem
        MemTotal:        8000000 kB
        MemAvailable:    1760000 kB
        SwapTotal:       4000000 kB
        SwapFree:        3100000 kB
        @@df
        Filesystem Type 1024-blocks Used Available Capacity Mounted on
        /dev/vda1 ext4 50000000 46500000 3500000 93% /
        @@uptime
        3542400.00 7000000.00
        @@rebootflag
        yes
        @@failed
        nightly-backup.service loaded failed failed Nightly backup
        @@failedrc
        0
        @@zram
        1932735283 552000000 545259520 0 600000000 0 0 0
        """.trimIndent() + "\n"
    )
    File(dir, "staging.profile").writeText(
        """
        @@cpu
        cpu  10000 0 0 90000 0 0 0 0 0 0
        cpu  10470 0 0 90530 0 0 0 0 0 0
        @@load
        1.12 0.97 0.80 2/310 4242
        @@cores
        2
        @@mem
        MemTotal:        4000000 kB
        MemAvailable:    1360000 kB
        SwapTotal:       0 kB
        SwapFree:        0 kB
        @@df
        Filesystem Type 1024-blocks Used Available Capacity Mounted on
        /dev/sda1 ext4 30000000 8700000 21300000 29% /
        @@uptime
        259200.00 500000.00
        @@os
        PRETTY_NAME="Ubuntu 24.04.3 LTS"
        """.trimIndent() + "\n"
    )
}

/** A few snippets in folders, to look at the folded snippets page, and the ready-made tmux snippets. */
private fun demoSnippets(): List<Snippet> = listOf(
    Snippet("s1", "Update", "sudo apt update && sudo apt upgrade -y\n"),
    Snippet("s2", "Edit Caddyfile", "sudo nano /etc/caddy/Caddyfile\n", "Caddy"),
    Snippet("s3", "Reload Caddy", "sudo systemctl reload caddy\n", "Caddy"),
    Snippet("s4", "Containers", "docker ps\n", "Docker"),
    Snippet("s5", "Disk usage", "docker system df\n", "Docker"),
    Snippet("s6", "Update stack", "docker compose pull && docker compose up -d\n", "Docker"),
    Snippet("s7", "Follow journal", "journalctl -f -n 50", "System"),
    // Placeholders: asked for before sending. The Go template of docker ps is no placeholder and goes out as it is.
    Snippet("s8", "Logs of a container", "docker logs --tail {{Lines:100}} -f {{Container}}", "Docker"),
    Snippet("s9", "Container names", "docker ps --format '{{.Names}}'\n", "Docker"),
    Snippet("s10", "Say hello", "echo \"Hello {{Name:World}}, nice to see you {{Name}}\"\n"),
    // Lower case names and braces of the shell in a default.
    Snippet("s11", "Tail a file", "tail -n {{lines:5}} \"{{file:\${HOME}/.profile}}\"\n", "System"),
    // Asks first without variables: the command with Send and Cancel.
    Snippet("s12", "Free memory", "free -h", "System"),
) + tmuxSnippets.mapIndexed { i, entry -> entry.toSnippet("tmux$i") }

/**
 * A TCP proxy on a free loopback port that forwards to [targetPort] and holds every chunk back for [delayMillis] in
 * both directions, in order. It makes a local host look far away.
 */
class DelayProxy(private val targetPort: Int, private val delayMillis: Long) : AutoCloseable {
    private val server = ServerSocket(0)

    /** The port to connect to instead of [targetPort]. */
    val port: Int get() = server.localPort

    init {
        thread(isDaemon = true, name = "delay-proxy") {
            while (server.isClosed.not()) {
                val client = runCatching { server.accept() }.getOrNull() ?: break
                val target = runCatching { Socket("127.0.0.1", targetPort) }.getOrNull()
                if (target == null) {
                    client.close()
                    continue
                }
                pump(client.getInputStream(), target.getOutputStream()) { client.close(); target.close() }
                pump(target.getInputStream(), client.getOutputStream()) { client.close(); target.close() }
            }
        }
    }

    private fun pump(from: InputStream, to: OutputStream, done: () -> Unit) {
        val delayed = Executors.newSingleThreadScheduledExecutor()
        thread(isDaemon = true) {
            val buffer = ByteArray(16 * 1024)
            runCatching {
                while (true) {
                    val n = from.read(buffer)
                    if (n < 0) break
                    val chunk = buffer.copyOf(n)
                    delayed.schedule({ runCatching { to.write(chunk); to.flush() } }, delayMillis, TimeUnit.MILLISECONDS)
                }
            }
            delayed.schedule({ done(); delayed.shutdown() }, delayMillis, TimeUnit.MILLISECONDS)
        }
    }

    override fun close() {
        server.close()
    }
}
