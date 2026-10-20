package bayern.kickner.dirl.ssh

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * A TCP proxy on a free loopback port that accepts connections at once but forwards them to [targetPort] only after
 * [open]. Holds a connect attempt in the middle of the SSH handshake, so tests can act while it runs.
 *
 * @property targetPort Port on 127.0.0.1 to forward to.
 */
class GatedProxy(private val targetPort: Int) : AutoCloseable {
    private val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    private val gate = CountDownLatch(1)
    private val accepted = CountDownLatch(1)
    private val sockets = mutableListOf<Socket>()

    /** Proxied connections whose client side has not been closed yet. */
    val active = AtomicInteger()

    /** The port to connect to. */
    val port: Int = server.localPort

    init {
        thread(isDaemon = true, name = "gated-proxy") {
            while (server.isClosed.not()) {
                val client = runCatching { server.accept() }.getOrNull() ?: break
                synchronized(sockets) { sockets += client }
                active.incrementAndGet()
                accepted.countDown()
                thread(isDaemon = true) { forward(client) }
            }
        }
    }

    /** Waits until the first connection was accepted. */
    fun awaitAccepted(seconds: Long = 10): Boolean = accepted.await(seconds, TimeUnit.SECONDS)

    /** Lets held and future connections through. */
    fun open() = gate.countDown()

    /** Waits until no proxied connection is open any more. */
    fun awaitIdle(seconds: Long = 10): Boolean {
        val deadline = System.currentTimeMillis() + seconds * 1000
        while (active.get() > 0 && System.currentTimeMillis() < deadline) Thread.sleep(50)
        return active.get() == 0
    }

    override fun close() {
        gate.countDown()
        runCatching { server.close() }
        synchronized(sockets) { sockets.forEach { runCatching { it.close() } } }
    }

    private fun forward(client: Socket) {
        gate.await()
        val target = runCatching { Socket(InetAddress.getLoopbackAddress(), targetPort) }.getOrElse {
            closeBoth(client, null)
            return
        }
        synchronized(sockets) { sockets += target }
        thread(isDaemon = true) { pipe(target.getInputStream(), client.getOutputStream()); closeBoth(client, target) }
        pipe(client.getInputStream(), target.getOutputStream())
        closeBoth(client, target)
    }

    private fun closeBoth(client: Socket, target: Socket?) {
        val wasOpen = synchronized(client) { client.isClosed.not().also { runCatching { client.close() } } }
        if (wasOpen) active.decrementAndGet()
        runCatching { target?.close() }
    }

    private fun pipe(from: InputStream, to: OutputStream) {
        // Socket streams are unbuffered, every chunk goes out right away.
        runCatching { from.copyTo(to) }
    }
}
