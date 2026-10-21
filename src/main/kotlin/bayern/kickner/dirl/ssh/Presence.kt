package bayern.kickner.dirl.ssh

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Whether anybody uses Dirl right now. SSH connections and status polls only exist while somebody does.
 *
 * Every request of a logged-in user runs inside [hold], see `web/Security.kt`. Ktor keeps a request in its pipeline
 * until it is done: a download until the last byte is written, a WebSocket (terminal, presence) until it is closed.
 * Every open Dirl page keeps a presence WebSocket open, so "somebody uses Dirl" means "a Dirl tab is open".
 *
 * After the last request ended, Dirl still counts as used for [grace]. That covers the moment between two pages,
 * when the browser has closed the WebSocket of the old page and not yet opened the one of the new page.
 *
 * Presence is global, not per user: connections are shared by all users anyway.
 *
 * @property clock Unix milliseconds.
 * @property grace How long Dirl counts as used after the last request ended.
 */
class Presence(
    private val clock: () -> Long = System::currentTimeMillis,
    private val grace: Duration = 30.seconds,
) {
    private val running = AtomicInteger()

    /** Unix milliseconds when the last request ended, `null` before the first one. */
    @Volatile
    private var lastEnd: Long? = null

    /** Called when somebody arrives after an absence, so the status poll does not wait for its next round. */
    val arrivals: MutableList<() -> Unit> = CopyOnWriteArrayList()

    /** True while a request runs or the last one ended less than [grace] ago. */
    val present: Boolean
        get() {
            if (running.get() > 0) return true
            val end = lastEnd ?: return false
            return clock() - end < grace.inWholeMilliseconds
        }

    /** Counts as presence while [block] runs, and for [grace] after it. */
    suspend fun <T> hold(block: suspend () -> T): T {
        val arrived = present.not()
        running.incrementAndGet()
        if (arrived) arrivals.forEach { listener -> runCatching { listener() } }
        try {
            return block()
        } finally {
            // The end time is written before the count goes down, so whoever sees the count at zero sees the new time.
            lastEnd = clock()
            running.decrementAndGet()
        }
    }
}
