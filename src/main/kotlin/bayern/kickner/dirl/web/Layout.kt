package bayern.kickner.dirl.web

import bayern.kickner.dirl.appVersion
import bayern.kickner.dirl.auth.Session
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.html.respondHtml
import kotlinx.html.ButtonType
import kotlinx.html.DIV
import kotlinx.html.FlowContent
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.a
import kotlinx.html.body
import kotlinx.html.button
import kotlinx.html.checkBoxInput
import kotlinx.html.dd
import kotlinx.html.div
import kotlinx.html.dl
import kotlinx.html.dt
import kotlinx.html.footer
import kotlinx.html.form
import kotlinx.html.h1
import kotlinx.html.h2
import kotlinx.html.head
import kotlinx.html.header
import kotlinx.html.hiddenInput
import kotlinx.html.id
import kotlinx.html.input
import kotlinx.html.label
import kotlinx.html.link
import kotlinx.html.main
import kotlinx.html.meta
import kotlinx.html.nav
import kotlinx.html.p
import kotlinx.html.pre
import kotlinx.html.script
import kotlinx.html.span
import kotlinx.html.textArea
import kotlinx.html.title
import java.util.concurrent.atomic.AtomicLong

/** Top navigation entries. */
enum class Nav(val label: String, val href: String) {
    HOSTS("Hosts", "/"),
    KEYS("Keys", "/keys"),
    SNIPPETS("Snippets", "/snippets"),
    AUDIT("Audit", "/audit"),
    SETTINGS("Settings", "/settings"),
}

/** How a page is framed. */
enum class PageFrame {
    /** App bar with navigation and a centered content column. */
    APP,

    /** App bar with navigation and full width content, for terminal and editor. */
    WIDE,

    /** Only a centered card, for login and unlock. */
    CENTER,
}

/**
 * Messages shown after a successful POST and redirect. The redirect only carries the key (`?done=host-saved`), so
 * no text from the URL ever ends up on the page.
 */
private val flashMessages = mapOf(
    "host-added" to "Host added. Put the authorized_keys line on the server, then connect.",
    "host-saved" to "Host saved.",
    "host-deleted" to "Host deleted.",
    "pinned" to "Host key pinned.",
    "pin-removed" to "Pinned host key removed.",
    "key-generated" to "Key generated.",
    "key-imported" to "Key imported.",
    "key-renamed" to "Key renamed.",
    "key-deleted" to "Key deleted.",
    "snippet-added" to "Snippet added.",
    "snippet-saved" to "Snippet saved.",
    "snippet-deleted" to "Snippet deleted.",
    "passphrase-changed" to "Passphrase changed.",
    "user-allowed" to "Access granted.",
    "user-revoked" to "Access removed and sessions of that user ended.",
    "request-dismissed" to "Request dismissed.",
    "session-revoked" to "Session ended.",
    "settings-saved" to "Settings saved.",
    "uploaded" to "Upload complete.",
    "saved" to "File saved.",
    "renamed" to "Renamed.",
    "deleted" to "Deleted.",
    "created" to "Directory created.",
    "restored" to "Backup restored. Unlock it with the passphrase it was created with.",
)

/** Counter for unique element IDs within a response, e.g. for copy buttons. */
private val elementCounter = AtomicLong()

/**
 * Renders a full page in the common layout. All text goes through kotlinx.html, which escapes it, so values from
 * the vault or from remote servers can never inject markup.
 *
 * @param title Browser tab title. The visible heading is part of [content], usually via [pageHeader].
 * @param session The logged-in user, `null` on pages before login. Controls whether navigation is shown.
 * @param nav The highlighted navigation entry.
 * @param frame Page framing, see [PageFrame].
 * @param refresh Content of a `<meta http-equiv="refresh">`, e.g. `60` to reload the overview for fresh metrics
 *   without script, or `0; url=/` to continue to another page.
 * @param assets Extra script and stylesheet files from `/static`.
 * @param status HTTP status of the response.
 * @param content The page body.
 */
suspend fun ApplicationCall.page(
    title: String,
    session: Session?,
    nav: Nav? = null,
    frame: PageFrame = PageFrame.APP,
    refresh: String? = null,
    assets: List<String> = emptyList(),
    status: HttpStatusCode = HttpStatusCode.OK,
    content: FlowContent.() -> Unit,
) {
    val flash = request.queryParameters["done"]?.let { flashMessages[it] }
    respondHtml(status) {
        head {
            meta(charset = "utf-8")
            meta(name = "viewport", content = "width=device-width, initial-scale=1, viewport-fit=cover")
            meta(name = "color-scheme", content = "light dark")
            if (refresh != null) meta { httpEquiv = "refresh"; this.content = refresh }
            title("$title | Dirl")
            link(rel = "icon", href = "/static/favicon.svg") { attributes["type"] = "image/svg+xml" }
            link(rel = "stylesheet", href = "/static/app.css")
            assets.filter { it.endsWith(".css") }.forEach { link(rel = "stylesheet", href = it) }
        }
        body(if (frame == PageFrame.WIDE) "fill" else null) {
            // App pages keep the presence WebSocket open (app.js), so the SSH connections stay while they are open.
            // Login, unlock and setup do not: there is nothing to keep connected.
            if (session != null && frame != PageFrame.CENTER) attributes["data-presence"] = "/ws/presence"
            if (frame != PageFrame.CENTER) header("appbar") {
                a(href = "/", classes = "brand") {
                    span("logo") { +">_" }
                    +"Dirl"
                }
                if (session != null) {
                    nav("nav") {
                        Nav.entries.forEach { entry ->
                            a(href = entry.href, classes = if (entry == nav) "active" else null) { +entry.label }
                        }
                    }
                    div("user") {
                        span("name") { +session.actor.name }
                        form(action = "/logout", method = FormMethod.post, classes = "inline") {
                            button(type = ButtonType.submit, classes = "btn ghost sm") { +"Log out" }
                        }
                    }
                }
            }
            val containerClass = when (frame) {
                PageFrame.APP -> "container"
                PageFrame.WIDE -> "container wide"
                PageFrame.CENTER -> "center-wrap"
            }
            main(containerClass) {
                if (flash != null && frame != PageFrame.CENTER) notice("success", flash)
                if (frame == PageFrame.CENTER) div("center-card") {
                    a(href = "/", classes = "brand") {
                        span("logo") { +">_" }
                        +"Dirl"
                    }
                    if (flash != null) notice("success", flash)
                    content()
                    if (session != null) form(action = "/logout", method = FormMethod.post, classes = "center-logout") {
                        span("muted small") { +"Signed in as ${session.actor.name}. " }
                        button(type = ButtonType.submit, classes = "btn ghost sm") { +"Log out" }
                    }
                } else content()
            }
            if (frame != PageFrame.WIDE) footer { +"Dirl $appVersion" }
            script(src = "/static/app.js") {}
            assets.filter { it.endsWith(".js") }.forEach { script(src = it) {} }
        }
    }
}

/** Page title with optional subtitle and action buttons on the right. */
fun FlowContent.pageHeader(title: String, subtitle: String? = null, actions: (DIV.() -> Unit)? = null) =
    div("page-header") {
        div {
            h1 { +title }
            if (subtitle != null) p("subtitle") { +subtitle }
        }
        if (actions != null) div("actions") { actions() }
    }

/** A card with an optional heading. */
fun FlowContent.card(title: String? = null, classes: String = "", content: DIV.() -> Unit) =
    div("card $classes".trim()) {
        if (title != null) h2 { +title }
        content()
    }

/** A message box. [kind] is `success`, `info`, `warn` or `error`. */
fun FlowContent.notice(kind: String, text: String) = div("notice $kind") { +text }

/** A colored status pill. [kind] is `ok`, `warn`, `error` or empty for neutral. */
fun FlowContent.pill(kind: String, text: String) = span("pill $kind".trim()) { +text }

/** A link styled as button. [kind] adds `primary`, `danger`, `ghost` or `sm`. */
fun FlowContent.linkButton(href: String, label: String, kind: String = "") =
    a(href = href, classes = "btn $kind".trim()) { +label }

/**
 * A small POST form with a single button, for actions like delete or reconnect. With [confirm] the browser asks
 * before submitting (through `app.js`).
 */
fun FlowContent.postButton(
    action: String,
    label: String,
    kind: String = "",
    confirm: String? = null,
    hidden: Map<String, String> = emptyMap(),
) = form(action = action, method = FormMethod.post, classes = "inline") {
    if (confirm != null) attributes["data-confirm"] = confirm
    hidden.forEach { (name, value) -> hiddenInput(name = name) { this.value = value } }
    button(type = ButtonType.submit, classes = "btn $kind".trim()) { +label }
}

/** A preformatted block with a copy button. */
fun FlowContent.copyBlock(text: String) = div("code") {
    val elementId = "copy-${elementCounter.incrementAndGet()}"
    pre { id = elementId; +text }
    button(type = ButtonType.button, classes = "btn sm") {
        attributes["data-copy"] = elementId
        +"Copy"
    }
}

/** A definition list of label and value pairs. */
fun FlowContent.keyValues(vararg rows: Pair<String, String>) = dl("kv") {
    rows.forEach { (label, value) ->
        dt { +label }
        dd { +value }
    }
}

/** A labeled text input with an optional hint below. */
fun FlowContent.textField(
    label: String,
    name: String,
    value: String = "",
    hint: String? = null,
    required: Boolean = true,
    placeholder: String? = null,
) = label("field") {
    span { +label }
    input(type = InputType.text, name = name) {
        this.value = value
        this.required = required
        attributes["aria-label"] = label
        if (placeholder != null) this.placeholder = placeholder
        attributes["autocomplete"] = "off"
        attributes["spellcheck"] = "false"
    }
    if (hint != null) span("hint") { +hint }
}

/** A labeled password input. */
fun FlowContent.passwordField(label: String, name: String, autocomplete: String, hint: String? = null) = label("field") {
    span { +label }
    input(type = InputType.password, name = name) {
        required = true
        attributes["aria-label"] = label
        attributes["autocomplete"] = autocomplete
    }
    if (hint != null) span("hint") { +hint }
}

/** A labeled multi-line input. */
fun FlowContent.textAreaField(label: String, name: String, value: String = "", rows: Int = 4, hint: String? = null) = label("field") {
    span { +label }
    textArea(rows = rows.toString()) {
        this.name = name
        required = true
        attributes["aria-label"] = label
        attributes["spellcheck"] = "false"
        attributes["autocomplete"] = "off"
        +value
    }
    if (hint != null) span("hint") { +hint }
}

/** A checkbox with its label text. */
fun FlowContent.checkField(label: String, name: String, checked: Boolean) = label("check") {
    checkBoxInput(name = name) { this.checked = checked }
    span { +label }
}

/** A plain primary submit button. */
fun FlowContent.submit(label: String, kind: String = "primary") =
    button(type = ButtonType.submit, classes = "btn $kind".trim()) { +label }
