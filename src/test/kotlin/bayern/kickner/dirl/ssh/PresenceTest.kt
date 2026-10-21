package bayern.kickner.dirl.ssh

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PresenceTest {
    private var now = 1_000_000L
    private val presence = Presence(clock = { now })

    @Test
    fun `nobody is present before the first request`() {
        assertTrue(presence.present.not())
    }

    @Test
    fun `a running request holds presence however long it takes, the grace starts at its end`(): Unit = runBlocking {
        val release = CompletableDeferred<Unit>()
        val started = CompletableDeferred<Unit>()
        val request = async { presence.hold { started.complete(Unit); release.await() } }
        started.await()
        now += 24 * 3_600_000L
        assertTrue(presence.present, "an open WebSocket can run for hours")

        release.complete(Unit)
        request.await()
        now += 29_000
        assertTrue(presence.present, "within the grace")
        now += 2_000
        assertTrue(presence.present.not(), "after the grace")
    }

    @Test
    fun `a failing request does not keep Dirl present`(): Unit = runBlocking {
        runCatching { presence.hold { error("boom") } }
        now += 31_000
        assertTrue(presence.present.not())
    }

    @Test
    fun `arrivals are reported once per absence, not on every request`(): Unit = runBlocking {
        var arrivals = 0
        presence.arrivals += { arrivals++ }
        presence.hold { }
        presence.hold { }
        now += 10_000
        presence.hold { }
        assertEquals(1, arrivals)
        now += 31_000
        presence.hold { }
        assertEquals(2, arrivals)
    }
}
