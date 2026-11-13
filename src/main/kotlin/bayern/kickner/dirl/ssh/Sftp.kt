package bayern.kickner.dirl.ssh

import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.connection.channel.direct.SessionFactory
import net.schmizz.sshj.sftp.SFTPClient
import net.schmizz.sshj.sftp.SFTPEngine
import java.io.IOException
import java.io.InputStream

/**
 * Largest SFTP packet Dirl accepts from a server. OpenSSH sends at most 256 KiB. sshj alone accepts up to 1 GiB and
 * allocates the buffer as soon as a server announces the length, before any data arrives, so one forged header
 * would end Dirl with an OutOfMemoryError and restart it sealed.
 */
const val MAX_SFTP_PACKET = 1024 * 1024

/**
 * Most bytes Dirl reads from the server on the SFTP channel of one directory listing. sshj keeps every entry until the
 * listing ends, and a hostile server can fill each one with a 32 KiB name and extended attributes, so the entry limit
 * alone does not bound the heap. A real listing of 10000 entries with long names stays far below it.
 */
const val MAX_LIST_BYTES = 16L * 1024 * 1024

/**
 * Opens an SFTP channel like [SSHClient.newSFTPClient], but refuses packets larger than [MAX_SFTP_PACKET] before sshj
 * allocates a buffer for them, and anything beyond [maxTotalBytes] read on the channel. A failed start closes the
 * channel again, a leftover one would count towards the server's session limit.
 */
fun SSHClient.openSftp(maxTotalBytes: Long = Long.MAX_VALUE): SFTPClient {
    val engine = SFTPEngine(LimitedSessions(this, maxTotalBytes))
    return runCatching { SFTPClient(engine.init()) }.onFailure { runCatching { engine.close() } }.getOrThrow()
}

/** Hands out sessions whose `sftp` subsystem reads through [SftpPacketLimit]. */
private class LimitedSessions(private val client: SSHClient, private val maxTotal: Long) : SessionFactory by client {
    override fun startSession(): Session = LimitedSession(client.startSession(), maxTotal)
}

private class LimitedSession(private val session: Session, private val maxTotal: Long) : Session by session {
    override fun startSubsystem(name: String): Session.Subsystem = LimitedSubsystem(session.startSubsystem(name), maxTotal)
}

private class LimitedSubsystem(private val subsystem: Session.Subsystem, private val maxTotal: Long) : Session.Subsystem by subsystem {
    private val limited by lazy { SftpPacketLimit(subsystem.inputStream, MAX_SFTP_PACKET, maxTotal) }

    override fun getInputStream(): InputStream = limited
}

/**
 * Passes an SFTP byte stream through unchanged and checks the 4 byte length that starts every packet.
 *
 * @throws IOException on the first packet announced larger than [max] bytes, before its content is read, and once
 *   the stream carried more than [maxTotal] bytes in all.
 */
class SftpPacketLimit(private val input: InputStream, private val max: Int, private val maxTotal: Long = Long.MAX_VALUE) : InputStream() {
    private val header = ByteArray(4)
    private var headerRead = 0
    private var packetLeft = 0L
    private var total = 0L

    override fun read(): Int {
        val one = ByteArray(1)
        return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (packetLeft > 0) {
            val n = counted(input.read(buffer, offset, minOf(length.toLong(), packetLeft).toInt()))
            if (n > 0) packetLeft -= n
            return n
        }
        // At a packet boundary: hand out the length bytes one by one and check them once all four are there.
        val n = counted(input.read(buffer, offset, minOf(length, header.size - headerRead)))
        if (n <= 0) return n
        buffer.copyInto(header, headerRead, offset, offset + n)
        headerRead += n
        if (headerRead == header.size) {
            val announced = header.fold(0L) { acc, byte -> acc shl 8 or (byte.toLong() and 0xff) }
            if (announced > max) throw IOException("The server sent an SFTP packet of $announced bytes, more than the $max Dirl accepts")
            headerRead = 0
            packetLeft = announced
        }
        return n
    }

    /** Adds [n] read bytes to the total and refuses the read that passes [maxTotal]. */
    private fun counted(n: Int): Int {
        if (n <= 0) return n
        total += n
        if (total > maxTotal) throw IOException(
            "Careful: the server sent more than ${maxTotal / (1024 * 1024)} MiB for this directory listing. No real directory needs that much, " +
                "the server may be compromised or misbehaving. Dirl stopped reading. Check this host before you trust what it shows or runs."
        )
        return n
    }

    override fun available(): Int = input.available()

    override fun close() = input.close()
}
