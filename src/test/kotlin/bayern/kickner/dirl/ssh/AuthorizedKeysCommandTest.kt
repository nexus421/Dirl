package bayern.kickner.dirl.ssh

import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [authorizedKeysCommand] run for real in every shell installed here, against a throwaway home directory. */
class AuthorizedKeysCommandTest {
    private val key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBhnY4uhyCLKu3jFCjbj8EFig5z4Bbmzhxbrx+/9q= dirl"
    private val blob = key.split(' ')[1]
    private val line = """restrict,pty,from="192.168.1.5,fd00::1" $key"""
    private val oldLine = """restrict,pty,from="10.0.0.1" $key"""
    private val otherKeys = listOf("ssh-ed25519 AAAAOTHER other@laptop", "ssh-rsa AAAANOEOL last-without-newline")

    /** sh and bash are everywhere Dirl is built, zsh and fish only where installed. */
    private val shells = listOf("sh", "bash", "zsh", "fish").filter { shell ->
        runCatching { ProcessBuilder("which", shell).start().waitFor() == 0 }.getOrDefault(false)
    }

    private fun mode(file: File) = (Files.getAttribute(file.toPath(), "unix:mode") as Int).and("777".toInt(8)).toString(8)

    /** Runs [command] in [shell] with [home] as home directory and returns the exit code. */
    private fun run(shell: String, home: File, command: String): Int {
        val process = ProcessBuilder(shell, "-c", command).apply {
            environment()["HOME"] = home.absolutePath
            redirectErrorStream(true)
        }.start()
        process.inputStream.readBytes()
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "$shell did not finish")
        return process.exitValue()
    }

    @Test
    fun `sh and bash are there, the test does not pass by skipping`() {
        assertTrue("sh" in shells && "bash" in shells, "found $shells")
    }

    @Test
    fun `a fresh home gets the directory, the file and the line with the modes sshd wants`() {
        val command = assertNotNull(authorizedKeysCommand(line, key))
        for (shell in shells) {
            val home = Files.createTempDirectory("dirl-home").toFile()
            assertEquals(0, run(shell, home, command), shell)
            val ssh = File(home, ".ssh")
            assertEquals(listOf(line), File(ssh, "authorized_keys").readLines(), shell)
            assertEquals("700", mode(ssh), shell)
            assertEquals("600", mode(File(ssh, "authorized_keys")), shell)
            assertEquals(listOf("authorized_keys"), ssh.list()!!.toList(), "$shell left a temporary file")
            home.deleteRecursively()
        }
    }

    @Test
    fun `other keys stay, an older line of this key is replaced and running it twice changes nothing`() {
        val command = assertNotNull(authorizedKeysCommand(line, key))
        for (shell in shells) {
            val home = Files.createTempDirectory("dirl-home").toFile()
            val ssh = File(home, ".ssh").apply { mkdir() }
            Files.setAttribute(ssh.toPath(), "unix:mode", "755".toInt(8))
            // The old line sits first, sshd would take it. The last line has no line break.
            File(ssh, "authorized_keys").writeText(listOf(otherKeys[0], oldLine, otherKeys[1]).joinToString("\n"))

            assertEquals(0, run(shell, home, command), shell)
            assertEquals(0, run(shell, home, command), shell)
            assertEquals(otherKeys + line, File(ssh, "authorized_keys").readLines(), shell)
            assertEquals(1, File(ssh, "authorized_keys").readLines().count { blob in it }, shell)
            assertEquals("700", mode(ssh), shell)
            assertEquals("600", mode(File(ssh, "authorized_keys")), shell)
            home.deleteRecursively()
        }
    }

    @Test
    fun `no command for a line with a placeholder or characters the quoting does not cover`() {
        assertNull(authorizedKeysCommand("""restrict,pty,from="<DIRL-IP>" $key""", key), "sshd would reject the line")
        assertNull(authorizedKeysCommand("""restrict,pty,from="<JUMP-HOST-IP>" $key""", key))
        assertNull(authorizedKeysCommand("restrict,pty $key it's", key))
        assertNull(authorizedKeysCommand("restrict,pty $key a\\b", key))
        assertNull(authorizedKeysCommand("restrict,pty $key\nssh-ed25519 AAAAEVIL x", key))
        assertNull(authorizedKeysCommand("restrict,pty $key", ""))
        assertNotNull(authorizedKeysCommand("restrict,pty $key", key), "without from= as well")
    }
}
