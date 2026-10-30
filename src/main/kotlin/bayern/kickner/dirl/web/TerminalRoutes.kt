package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.ssh.ConnectionState
import bayern.kickner.dirl.ssh.describe
import bayern.kickner.dirl.ssh.describeChannelError
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.Snippet
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readBytes
import io.ktor.websocket.readText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.html.ButtonType
import kotlinx.html.FlowContent
import kotlinx.html.a
import kotlinx.html.button
import kotlinx.html.details
import kotlinx.html.div
import kotlinx.html.id
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.summary
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotnexlib.ResultOf2
import net.schmizz.sshj.connection.channel.direct.PTYMode
import kotlin.time.Duration.Companion.seconds

private const val TAG = "Terminal"

/** Bytes read from the remote shell per WebSocket frame at most. */
private const val READ_CHUNK = 16 * 1024

/**
 * Control message from the browser, sent as WebSocket text frame. Binary frames carry terminal input.
 *
 * @property type Only `resize` so far.
 * @property cols Terminal width in characters.
 * @property rows Terminal height in characters.
 */
@Serializable
data class TerminalControl(val type: String, val cols: Int = 80, val rows: Int = 24)

/** Mobile key bar: label and the bytes it sends. Ctrl is handled in JavaScript as a sticky modifier. */
private val keyBar = listOf(
    "Esc" to "\u001b", "Tab" to "\t", "←" to "\u001b[D", "↑" to "\u001b[A", "↓" to "\u001b[B", "→" to "\u001b[C",
    "|" to "|", "~" to "~", "/" to "/",
)

/**
 * Terminal page and its WebSocket.
 *
 * - `GET /hosts/{id}/terminal` renders the page: xterm.js, a menu per snippet folder, the other snippet buttons and,
 *   on touch devices, a key bar with Ctrl, Esc, Tab and arrows. For the Actions mode (`terminal.js`) it also renders
 *   the mode toggle, an action bar with Enter and Cancel and a panel with every snippet, hidden in the classic mode.
 * - `WS /ws/terminal/{id}` bridges the browser to a PTY shell on the host. Binary frames are terminal bytes in both
 *   directions, text frames are JSON control messages ([TerminalControl]).
 *
 * The WebSocket outlives the HTTP request that opened it, so it checks the session itself: typing counts as
 * activity, and every 30 seconds a watchdog closes the terminal when the session expired, was ended under Settings,
 * or the user lost access.
 *
 * Output from the server is treated as untrusted: it goes into xterm.js as bytes, never into the DOM as HTML, and
 * the xterm links addon is not loaded.
 */
fun Route.terminalRoutes(dirl: Dirl) {
    get("/hosts/{id}/terminal") {
        val (content, host) = hostOr404(dirl) ?: return@get
        if (host.jumpOnly) return@get call.jumpOnlyPage(host)
        val state = dirl.connections.state(host.id)
        val groups = groupSnippets(content.snippets)
        call.page(
            "${host.name} terminal", call.session, Nav.HOSTS, frame = PageFrame.WIDE,
            assets = listOf("/static/vendor/xterm/xterm.css", "/static/vendor/xterm/xterm.js", "/static/vendor/xterm/addon-fit.js", "/static/terminal.js"),
        ) {
            div("term-page") {
                div("term-bar") {
                    span("name") { +host.name }
                    if (state is ConnectionState.HostKeyUnknown || state is ConnectionState.HostKeyMismatch) {
                        a(href = "/hosts/${host.id}", classes = "pill warn") { +"confirm host key first" }
                    }
                    // The folder menus sit outside the scrolling row: overflow-x would clip a menu opening inside it.
                    groups.folders.forEach { (folder, inFolder) ->
                        details("menu") {
                            summary("btn sm") { +"$folder ▾" }
                            div("menu-items") { inFolder.forEach { snippetButton(it) } }
                        }
                    }
                    div("snippets") { groups.loose.forEach { snippetButton(it) } }
                    div("spacer") {}
                    // terminal.js names the other mode on it, "Actions" or "Classic terminal".
                    button(type = ButtonType.button, classes = "btn sm primary") {
                        id = "mode"
                        +"Actions"
                    }
                    linkButton("/hosts/${host.id}/files", "Files", "sm")
                    linkButton("/hosts/${host.id}", "Details", "sm ghost")
                }
                div("terminal") {
                    id = "terminal"
                    attributes["data-ws"] = "/ws/terminal/${host.id}"
                }
                // Actions mode only: the two keys a running command needs and every snippet, folders open in place.
                // Named keys that terminal.js maps to bytes: the HTML parser turns a carriage return in an attribute into
                // a line feed, which is not the Enter a full-screen program or the reload after a disconnect expects.
                div("actionbar") {
                    button(type = ButtonType.button, classes = "btn") { attributes["data-key"] = "enter"; +"Enter" }
                    button(type = ButtonType.button, classes = "btn") { attributes["data-key"] = "cancel"; +"Cancel" }
                }
                div("snippet-panel") {
                    // Without snippets the Actions mode has nothing to tap, so it says where they come from.
                    if (content.snippets.isEmpty()) p("muted small") {
                        +"No snippets yet. "
                        a(href = "/snippets") { +"Add snippets" }
                        +" to run them here with a tap."
                    }
                    if (groups.loose.isNotEmpty()) div("grid") { groups.loose.forEach { snippetButton(it) } }
                    groups.folders.forEach { (folder, inFolder) ->
                        details("panel-folder") {
                            summary {
                                +folder
                                span("muted") { +inFolder.size.toString() }
                            }
                            div("grid") { inFolder.forEach { snippetButton(it) } }
                        }
                    }
                }
                div("keybar") {
                    button(type = ButtonType.button, classes = "btn sm") { id = "ctrl"; +"Ctrl" }
                    keyBar.forEach { (label, seq) -> button(type = ButtonType.button, classes = "btn sm") { attributes["data-send"] = seq; +label } }
                }
            }
        }
    }

    webSocket("/ws/terminal/{id}") {
        val actor = call.session.actor
        val token = call.session.token
        val host = dirl.vault.content?.host(call.parameters["id"].orEmpty())?.takeIf { it.jumpOnly.not() }
            ?: return@webSocket close(CloseReason(CloseReason.Codes.CANNOT_ACCEPT, "Unknown host or jump host only"))
        val cols = call.request.queryParameters["cols"]?.toIntOrNull()?.coerceIn(10, 500) ?: 80
        val rows = call.request.queryParameters["rows"]?.toIntOrNull()?.coerceIn(5, 300) ?: 24

        val client = when (val c = dirl.connections.connection(host.id)) {
            is ResultOf2.Success -> c.value
            is ResultOf2.Failure -> {
                send(Frame.Text(errorJson("Cannot connect: ${describe(c.value)}. See the host page.")))
                return@webSocket close(CloseReason(CloseReason.Codes.TRY_AGAIN_LATER, "Not connected"))
            }
        }

        val opened = withContext(Dispatchers.IO) {
            runCatching {
                val session = client.startSession()
                // A refused PTY or shell must close the session, every leftover one counts towards MaxSessions.
                val shell = runCatching {
                    runCatching { session.allocatePTY("xterm-256color", cols, rows, 0, 0, emptyMap<PTYMode, Int>()) }
                        .getOrElse { error("The server refused a terminal. The authorized_keys line needs pty, see the host page.") }
                    session.startShell()
                }.onFailure { runCatching { session.close() } }.getOrThrow()
                session to shell
            }
        }
        val (sshSession, shell) = opened.getOrElse {
            send(Frame.Text(errorJson("Cannot open a shell: ${describeChannelError(it)}")))
            return@webSocket close(CloseReason(CloseReason.Codes.INTERNAL_ERROR, "No shell"))
        }

        dirl.audit.record(actor, AuditAction.TERMINAL_OPENED, host.name)
        val sessionValid = { dirl.sessions.peek(token) != null && dirl.access.isAllowed(actor.sub) }
        val remoteIn = shell.outputStream
        val reader = launch(Dispatchers.IO) {
            val buffer = ByteArray(READ_CHUNK)
            runCatching {
                while (true) {
                    val n = shell.inputStream.read(buffer)
                    if (n < 0) break
                    send(Frame.Binary(true, buffer.copyOf(n)))
                }
            }
            close(CloseReason(CloseReason.Codes.NORMAL, "Shell closed"))
        }
        val watchdog = launch {
            while (isActive) {
                delay(30.seconds)
                if (sessionValid().not()) {
                    send(Frame.Text(errorJson("Your session ended. Sign in again.")))
                    close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "Session ended"))
                }
            }
        }

        runCatching {
            for (frame in incoming) {
                // Typing keeps the session alive, so a long terminal session does not hit the idle timeout.
                if (dirl.sessions.get(token) == null) break
                when (frame) {
                    is Frame.Binary -> withContext(Dispatchers.IO) {
                        remoteIn.write(frame.readBytes())
                        remoteIn.flush()
                    }

                    is Frame.Text -> {
                        val control = runCatching { controlJson.decodeFromString(TerminalControl.serializer(), frame.readText()) }.getOrNull()
                        if (control?.type == "resize") withContext(Dispatchers.IO) {
                            shell.changeWindowDimensions(control.cols.coerceIn(10, 500), control.rows.coerceIn(5, 300), 0, 0)
                        }
                    }

                    else -> Unit
                }
            }
        }.onFailure { staticLog(KLogger.Level.DEBUG, TAG) { "Terminal to ${host.name} ended: ${it.message}" } }

        watchdog.cancel()
        reader.cancel()
        withContext(Dispatchers.IO) {
            runCatching { shell.close() }
            runCatching { sshSession.close() }
        }
        dirl.audit.record(actor, AuditAction.TERMINAL_CLOSED, host.name)
    }
}

/** Shown instead of terminal or files for a host marked as jump host only. */
suspend fun io.ktor.server.application.ApplicationCall.jumpOnlyPage(host: Host) = page(host.name, session, Nav.HOSTS) {
    pageHeader(host.name, "Jump host only")
    card {
        p("muted") { +"${host.name} is marked as jump host only. Its key may only forward connections, so there is no terminal and no file access. Change this in the host settings if it should be a terminal target as well." }
        div("btn-row") {
            linkButton("/hosts/${host.id}", "Host details")
            linkButton("/hosts/${host.id}/edit", "Edit", "ghost")
        }
    }
}

/**
 * A button that sends [snippet] to the terminal through `terminal.js`. Marked with `{ }` when it has variables and with
 * `⏎` when a click runs it right away, without the dialog. Unmarked buttons ask first.
 */
private fun FlowContent.snippetButton(snippet: Snippet) = button(type = ButtonType.button, classes = "btn sm") {
    attributes["data-send"] = snippet.command
    attributes["data-name"] = snippet.name
    attributes["title"] = snippet.command.trimEnd('\n')
    +snippet.name
    // A snippet with variables asks for values first, the braces say so at a glance. Screen readers get it in words.
    val variables = placeholdersOf(snippet.command)
    if (variables.isNotEmpty()) {
        span("snippet-var") {
            attributes["aria-hidden"] = "true"
            +"{ }"
        }
        span("sr-only") { +", asks for ${variables.joinToString { it.name }}" }
    } else if (snippet.command.endsWith("\n")) {
        // Runs on the click, the Enter symbol warns. With variables the form comes first, so no warning there.
        span("snippet-run") {
            attributes["aria-hidden"] = "true"
            +"⏎"
        }
        span("sr-only") { +", runs immediately" }
    }
}

private val controlJson = Json { ignoreUnknownKeys = true }

private fun errorJson(message: String): String =
    controlJson.encodeToString(ErrorMessage.serializer(), ErrorMessage("error", message))

@Serializable
private data class ErrorMessage(val type: String, val message: String)
