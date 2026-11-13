package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.web.MAX_LIST_ENTRIES
import bayern.kickner.dirl.web.listEntries
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Directory listings against a scripted SFTP server, see [fakeSftpClient]. No sshd needed. */
class SftpListingTest {
    /** Counts the bytes the client took from the server, below the limit like a real channel. */
    private class Counting(input: InputStream) : FilterInputStream(input) {
        var bytes = 0L
        override fun read(b: ByteArray, off: Int, len: Int) = super.read(b, off, len).also { if (it > 0) bytes += it }
    }

    /** Lists `/fake` through the same limits as `GET /hosts/{id}/files` and returns the result and the bytes read. */
    private fun list(batches: Sequence<List<FakeEntry>>): Pair<Result<Int>, Long> {
        lateinit var counting: Counting
        val sftp = fakeSftpClient(batches) { raw -> SftpPacketLimit(Counting(raw).also { counting = it }, MAX_SFTP_PACKET, MAX_LIST_BYTES) }
        val result = runCatching { listEntries(sftp, "/fake").size }
        runCatching { sftp.close() }
        return result to counting.bytes
    }

    /** The listing failed with the warning, read at most one packet past the limit and did not wait for a timeout. */
    private fun assertRefused(batches: Sequence<List<FakeEntry>>) {
        val started = System.nanoTime()
        val (result, read) = list(batches)
        val seconds = (System.nanoTime() - started) / 1_000_000_000
        val error = result.exceptionOrNull()
        assertTrue(error is IOException && error.message.orEmpty().startsWith("Careful: the server sent more than 16 MiB"), "was: $error")
        assertTrue(read <= MAX_LIST_BYTES + MAX_SFTP_PACKET, "read $read bytes")
        assertTrue(seconds < 10, "took $seconds s, sshj's 30 second timeout must not be waited for")
    }

    @Test
    fun `a full directory with long real names is listed`() {
        // NAME_MAX is 255 bytes, OpenSSH sends a long name like ls -l for each entry as well.
        val name = "x".repeat(240)
        val (result, read) = list((0 until MAX_LIST_ENTRIES).chunked(100).asSequence().map { chunk -> chunk.map { FakeEntry("%05d$name".format(it)) } })
        assertEquals(MAX_LIST_ENTRIES, result.getOrThrow())
        assertTrue(read < MAX_LIST_BYTES / 2, "a real listing must stay far below the limit, read $read bytes")
    }

    @Test
    fun `huge names stop the listing at the byte limit`() {
        // 9999 names of 32 KiB, sshj's longest string, would keep about 640 MiB on the heap.
        assertRefused((0 until 9999).chunked(15).asSequence().map { chunk -> chunk.map { FakeEntry("%05d".format(it) + "a".repeat(32763)) } })
    }

    @Test
    fun `huge extended attributes stop the listing at the byte limit`() {
        // 400 entries with about 0.94 MiB of extended attributes each, every packet below the packet limit.
        assertRefused((0 until 400).asSequence().map { i -> listOf(FakeEntry("f$i", (0 until 30).associate { "k$it" to "v".repeat(32000) })) })
    }

    @Test
    fun `the byte limit counts across packets and lets exactly the limit through`() {
        fun packet(size: Int) = java.nio.ByteBuffer.allocate(4 + size).putInt(size).put(ByteArray(size)).array()
        val stream = packet(96) + packet(96) + packet(96)
        assertEquals(300, SftpPacketLimit(stream.inputStream(), 100, maxTotal = 300).readAllBytes().size)
        val error = runCatching { SftpPacketLimit(stream.inputStream(), 100, maxTotal = 299).readAllBytes() }.exceptionOrNull()
        assertTrue(error is IOException && error.message.orEmpty().contains("No real directory needs that much"), "was: $error")
    }
}
