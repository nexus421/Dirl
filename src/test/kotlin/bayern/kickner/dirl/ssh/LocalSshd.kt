package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.restrictToOwner
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files

/**
 * A real OpenSSH server for integration tests, started as the current user on a free loopback port. No root needed:
 * PAM and privilege separation are off, the host key is generated with Dirl's own key generator.
 *
 * The binaries come from `$DIRL_SSHD_ROOT/usr/sbin/sshd` (an unpacked `openssh-server` package) or from the system
 * (`/usr/sbin/sshd`, as installed in CI by `apt-get install openssh-server`).
 *
 * @property port The port it listens on.
 * @property hostKeyFingerprint `SHA256:` fingerprint of its host key.
 */
class LocalSshd private constructor(
    val port: Int,
    private val dir: File,
    private val process: Process,
    val hostKeyFingerprint: String,
) : AutoCloseable {

    /** Replaces `authorized_keys` with [lines]. sshd rereads it on every login. */
    fun authorize(vararg lines: String) {
        File(dir, "authorized_keys").writeText(lines.joinToString("\n", postfix = "\n"))
    }

    /** The server log, for assertion messages. */
    fun log(): String = File(dir, "sshd.log").takeIf { it.isFile }?.readText().orEmpty()

    override fun close() {
        process.destroy()
        process.waitFor()
        dir.deleteRecursively()
    }

    companion object {
        /** Root of the OpenSSH installation, or `null` if there is none and the tests must be skipped. */
        fun findRoot(): File? {
            val fromEnv = System.getenv("DIRL_SSHD_ROOT")?.let(::File)?.takeIf { File(it, "usr/sbin/sshd").canExecute() }
            return fromEnv ?: File("/").takeIf { File("/usr/sbin/sshd").canExecute() }
        }

        /**
         * Starts a server and waits until it accepts connections.
         *
         * @param penalties OpenSSH 9.8 and later block a source address for a while after failed logins
         *   (`PerSourcePenalties`). Off by default so tests can check Dirl's own logic in isolation.
         * @param listen Loopback address to listen on, `::1` for IPv6 tests.
         */
        fun start(root: File, penalties: Boolean = false, listen: String = "127.0.0.1"): LocalSshd {
            val dir = Files.createTempDirectory("dirl-sshd").toFile()
            val port = ServerSocket(0).use { it.localPort }
            val hostKey = generateEd25519Key("host")
            val keyFile = File(dir, "hostkey").apply { writeText(hostKey.privateKeyPem) }
            restrictToOwner(keyFile)
            File(dir, "authorized_keys").writeText("")

            val openssh = listOf("usr/lib/openssh", "usr/libexec/openssh", "usr/libexec").map { File(root, it) }
            val sftp = openssh.map { File(it, "sftp-server") }.firstOrNull { it.canExecute() }
            val session = openssh.map { File(it, "sshd-session") }.firstOrNull { it.canExecute() }
            val auth = openssh.map { File(it, "sshd-auth") }.firstOrNull { it.canExecute() }
            val sshd = File(root, "usr/sbin/sshd").absolutePath
            val version = runCatching {
                val out = ProcessBuilder(sshd, "-V").redirectErrorStream(true).start().inputStream.readBytes().decodeToString()
                Regex("OpenSSH_(\\d+)\\.(\\d+)").find(out)!!.destructured.let { (major, minor) -> major.toInt() * 100 + minor.toInt() }
            }.getOrDefault(0)
            val config = File(dir, "sshd_config")
            config.writeText(
                buildString {
                    appendLine("Port $port")
                    appendLine("ListenAddress $listen")
                    appendLine("HostKey ${keyFile.absolutePath}")
                    appendLine("PidFile ${File(dir, "sshd.pid").absolutePath}")
                    appendLine("AuthorizedKeysFile ${File(dir, "authorized_keys").absolutePath}")
                    appendLine("PasswordAuthentication no")
                    appendLine("KbdInteractiveAuthentication no")
                    appendLine("UsePAM no")
                    appendLine("StrictModes no")
                    appendLine("LogLevel VERBOSE")
                    if (sftp != null) appendLine("Subsystem sftp ${sftp.absolutePath}")
                    if (session != null) appendLine("SshdSessionPath ${session.absolutePath}")
                    if (auth != null) appendLine("SshdAuthPath ${auth.absolutePath}")
                    if (version >= 908 && penalties.not()) appendLine("PerSourcePenalties no")
                }
            )

            val process = ProcessBuilder(sshd, "-D", "-e", "-f", config.absolutePath)
                .redirectErrorStream(true)
                .redirectOutput(File(dir, "sshd.log"))
                .start()
            val deadline = System.currentTimeMillis() + 10_000
            while (System.currentTimeMillis() < deadline) {
                val up = runCatching { Socket().use { it.connect(InetSocketAddress(listen, port), 200) } }.isSuccess
                if (up) return LocalSshd(port, dir, process, fingerprintOfLine(hostKey.publicKey))
                check(process.isAlive) { "sshd exited: ${File(dir, "sshd.log").readText()}" }
                Thread.sleep(50)
            }
            process.destroy()
            error("sshd did not start: ${File(dir, "sshd.log").readText()}")
        }
    }
}
