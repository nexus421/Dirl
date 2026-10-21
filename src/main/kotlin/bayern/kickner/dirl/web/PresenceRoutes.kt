package bayern.kickner.dirl.web

import io.ktor.server.routing.Route
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * `WS /ws/presence`: every Dirl page opens it through `app.js` and keeps it open while the page is open. No data
 * goes over it. Like every request it counts as presence for as long as it runs (see `installGuards`), so the SSH
 * connections stay open while a Dirl tab is open, also on quiet pages such as the editor.
 *
 * It never extends the session: incoming frames are ignored and the session is only peeked at. A watchdog closes it
 * every [checkEvery] once the session expired, was ended or the user lost access. A forgotten tab would otherwise
 * keep the connections to every host open without anybody being able to use them.
 */
fun Route.presenceRoutes(dirl: Dirl, checkEvery: Duration = 30.seconds) {
    webSocket("/ws/presence") {
        val token = call.session.token
        val sub = call.session.actor.sub
        val watchdog = launch {
            while (isActive) {
                delay(checkEvery)
                val valid = dirl.sessions.peek(token) != null && dirl.access.isAllowed(sub)
                if (valid.not()) close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "Session ended"))
            }
        }
        // Nothing is expected from the browser, whatever arrives is dropped until the socket closes.
        runCatching { incoming.consumeEach { } }
        watchdog.cancel()
    }
}
