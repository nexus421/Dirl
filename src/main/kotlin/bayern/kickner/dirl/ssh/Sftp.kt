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
 * Opens an SFTP channel like [SSHClient.newSFTPClient], but refuses packets larger than [MAX_SFTP_PACKET] before sshj
 * allocates a buffer for them. A failed start closes the channel again, a leftover one would count towards the
 * server's session limit.
 */
fun SSHClient.openSftp(): SFTPClient {
    val engine = SFTPEngine(LimitedSessions(this))
    return runCatching { SFTPClient(engine.init()) }.onFailure { runCatching { engine.close() } }.getOrThrow()
}

/** Hands out sessions whose `sftp` subsystem reads through [SftpPacketLimit]. */
private class LimitedSessions(private val client: SSHClient) : SessionFactory by client {
    override fun startSession(): Session = LimitedSession(client.startSession())
}

private class LimitedSession(private val session: Session) : Session by session {
    override fun startSubsystem(name: String): Session.Subsystem = LimitedSubsystem(session.startSubsystem(name))
}

private class LimitedSubsystem(private val subsystem: Session.Subsystem) : Session.Subsystem by subsystem {
    private val limited by lazy { SftpPacketLimit(subsystem.inputStream, MAX_SFTP_PACKET) }

    override fun getInputStream(): InputStream = limited
}

/**
 * Passes an SFTP byte stream through unchanged and checks the 4 byte length that starts every packet.
 *
 * @throws IOException on the first packet announced larger than [max] bytes, before its content is read.
 */
class SftpPacketLimit(private val input: InputStream, private val max: Int) : InputStream() {
    private val header = ByteArray(4)
    private var headerRead = 0
    private var packetLeft = 0L

    override fun read(): Int {
        val one = ByteArray(1)
        return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (packetLeft > 0) {
            val n = input.read(buffer, offset, minOf(length.toLong(), packetLeft).toInt())
            if (n > 0) packetLeft -= n
            return n
        }
        // At a packet boundary: hand out the length bytes one by one and check them once all four are there.
        val n = input.read(buffer, offset, minOf(length, header.size - headerRead))
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

    override fun available(): Int = input.available()

    override fun close() = input.close()
}
