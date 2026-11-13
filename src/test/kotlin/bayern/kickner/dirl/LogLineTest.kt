package bayern.kickner.dirl

import bayern.kickner.dirl.ssh.parseMetrics
import bayern.kickner.klogger.KLogger
import kotnexlib.ResultOf2
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The line format of the console and `app.log`, see [logLine]. */
class LogLineTest {
    @Test
    fun `escape sequences and control characters become visible`() {
        // OSC 52 writes the clipboard of the terminal that shows it, ESC [2J clears the screen, U+202E reorders text.
        assertEquals("a\\x1b]52;c;SGk=\\x07\\x1b[2J\\x0d\\x00b\\u202e\\u2028c\\x9b", logSafe("a\u001b]52;c;SGk=\u0007\u001b[2J\r\u0000b‮ c\u009b"))
        assertEquals("tab\tumlauts äöü emoji 😀", logSafe("tab\tumlauts äöü emoji 😀"), "ordinary text stays as it is")
    }

    @Test
    fun `further lines of a message are indented, so they cannot pass for a log line`() {
        val line = logLine(KLogger.Level.INFO, "Test", "first\n13.11.2026 12:00:00 ERROR/Vault: forged")
        val lines = line.lines()
        assertEquals(2, lines.size)
        assertTrue(lines[0].endsWith("INFO/Test: first"), lines[0])
        assertEquals("    13.11.2026 12:00:00 ERROR/Vault: forged", lines[1])

        // A stack trace stays readable, one frame per line.
        val trace = runCatching { error("boom") }.exceptionOrNull()!!.stackTraceToString().trimEnd()
        assertTrue(logSafe(trace).lines().drop(1).all { it.startsWith("    \tat ") || it.startsWith("    ") })
    }

    @Test
    fun `a metrics parse error does not reach the log with the server's escape sequences`() {
        // The message quotes the server's text raw, the line format is what keeps it out of the reader's terminal.
        val failure = parseMetrics("@@uptime\n\u001b]52;c;SGFja2Vk\u0007\u001b[2J 1.0\n") as ResultOf2.Failure
        assertTrue(failure.value.contains('\u001b'))
        val line = logLine(KLogger.Level.DEBUG, "Metrics", "No metrics for host h1: ${failure.value}")
        assertTrue(line.none { it.code < 0x20 || it.code == 0x7f }, line)
        assertTrue(line.endsWith("For input string: \"\\x1b]52;c;SGFja2Vk\\x07\\x1b[2J\""), line)
    }
}
