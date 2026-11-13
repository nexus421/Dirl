package bayern.kickner.dirl.ssh

import net.schmizz.sshj.common.LoggerFactory
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.connection.channel.direct.SessionFactory
import net.schmizz.sshj.sftp.SFTPClient
import net.schmizz.sshj.sftp.SFTPEngine
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.lang.reflect.Proxy
import kotlin.concurrent.thread

/**
 * One directory entry a [fakeSftpClient] server sends.
 *
 * @property name File name.
 * @property extended Extended attributes, sent with the `SSH_FILEXFER_ATTR_EXTENDED` flag if not empty.
 */
class FakeEntry(val name: String, val extended: Map<String, String> = emptyMap())

/**
 * An [SFTPClient] talking to a scripted SFTP version 3 server in this process, no sshd needed. The server answers
 * `OPENDIR`, `READDIR` (one NAME packet per entry of [batches], then EOF), `CLOSE`, `REALPATH` and `STAT`/`LSTAT`.
 * Its replies pass through [wrap] like the replies of a real server pass through [SftpPacketLimit] in [openSftp].
 */
fun fakeSftpClient(batches: Sequence<List<FakeEntry>>, wrap: (InputStream) -> InputStream): SFTPClient {
    val toClient = PipedInputStream(1 shl 16)
    val serverOut = DataOutputStream(PipedOutputStream(toClient))
    val toServer = PipedInputStream(1 shl 16)
    val clientOut = PipedOutputStream(toServer)
    val pending = batches.iterator()

    fun reply(type: Int, id: Int?, body: DataOutputStream.() -> Unit) {
        val bytes = java.io.ByteArrayOutputStream()
        DataOutputStream(bytes).apply { writeByte(type); id?.let { writeInt(it) }; body() }
        serverOut.writeInt(bytes.size())
        bytes.writeTo(serverOut)
        serverOut.flush()
    }
    fun DataOutputStream.string(s: String) = s.toByteArray().let { writeInt(it.size); write(it) }
    fun DataOutputStream.attrs(extended: Map<String, String> = emptyMap()) {
        if (extended.isEmpty()) writeInt(0)
        else {
            writeInt(0x80000000.toInt())
            writeInt(extended.size)
            extended.forEach { (key, value) -> string(key); string(value) }
        }
    }

    thread(isDaemon = true, name = "fake-sftp") {
        val input = DataInputStream(toServer)
        runCatching {
            while (true) {
                val length = input.readInt()
                val packet = DataInputStream(input.readNBytes(length).inputStream())
                val type = packet.readUnsignedByte()
                if (type == 1) {
                    reply(2, null) { writeInt(3) }
                    continue
                }
                val id = packet.readInt()
                when (type) {
                    11 -> reply(102, id) { string("handle") }
                    12 -> if (pending.hasNext()) {
                        val batch = pending.next()
                        reply(104, id) {
                            writeInt(batch.size)
                            batch.forEach { string(it.name); string(it.name); attrs(it.extended) }
                        }
                    } else reply(101, id) { writeInt(1); string("EOF"); string("") }
                    16 -> reply(104, id) { writeInt(1); string("/fake"); string("/fake"); attrs() }
                    7, 17 -> reply(105, id) { attrs() }
                    else -> reply(101, id) { writeInt(0); string("OK"); string("") }
                }
            }
        }
    }

    val subsystem = Proxy.newProxyInstance(Session.Subsystem::class.java.classLoader, arrayOf(Session.Subsystem::class.java)) { _, method, _ ->
        when (method.name) {
            "getInputStream" -> wrap(toClient)
            "getOutputStream" -> clientOut
            "getRemoteCharset" -> Charsets.UTF_8
            "getLoggerFactory" -> LoggerFactory.DEFAULT
            "isOpen" -> true
            else -> if (method.returnType == Boolean::class.javaPrimitiveType) false else null
        }
    } as Session.Subsystem
    val session = Proxy.newProxyInstance(Session::class.java.classLoader, arrayOf(Session::class.java)) { _, method, _ ->
        when (method.name) {
            "startSubsystem" -> subsystem
            "getLoggerFactory" -> LoggerFactory.DEFAULT
            "isOpen" -> true
            else -> if (method.returnType == Boolean::class.javaPrimitiveType) false else null
        }
    } as Session
    val factory = Proxy.newProxyInstance(SessionFactory::class.java.classLoader, arrayOf(SessionFactory::class.java)) { _, method, _ -> if (method.name == "startSession") session else null } as SessionFactory
    return SFTPClient(SFTPEngine(factory).init())
}
