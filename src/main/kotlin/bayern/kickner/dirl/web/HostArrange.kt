package bayern.kickner.dirl.web

import bayern.kickner.dirl.vault.Host
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import kotlinx.html.ButtonType
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.button
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.input
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.title
import kotnexlib.ResultOf2

/** Form field of a host's position on the arrange page, followed by the host ID. */
private const val POSITION_FIELD = "pos-"

/**
 * Reads the positions of the arrange page. Every host has a number field, the hosts are ordered by number, equal
 * numbers keep their current order. A host without a field keeps the number of its current place, so a host added
 * while the page was open stays where it is.
 *
 * @return The host IDs in the new order, or the reason the form is refused.
 */
fun parseArrangeForm(form: Parameters, hosts: List<Host>): ResultOf2<List<String>, String> {
    val positions = hosts.mapIndexed { index, host ->
        val raw = form[POSITION_FIELD + host.id]?.trim()
        val position = if (raw.isNullOrEmpty()) index + 1 else raw.toIntOrNull()
            ?: return ResultOf2.Failure("The position of ${host.name} must be a whole number.")
        Triple(host.id, position, index)
    }
    return ResultOf2.Success(positions.sortedWith(compareBy({ it.second }, { it.third })).map { it.first })
}

/** [hosts] in the [order] of their IDs. Hosts missing from [order], e.g. added in the meantime, come last. */
fun arrangeHosts(hosts: List<Host>, order: List<String>): List<Host> {
    val rank = order.withIndex().associate { it.value to it.index }
    return hosts.sortedBy { rank[it.id] ?: Int.MAX_VALUE }
}

/**
 * The arrange page: one row per host with its position as number field. Without JavaScript the numbers are typed,
 * with it the arrows move a row and renumber all of them (`app.js`). Either way one "Save order" stores everything.
 */
suspend fun ApplicationCall.arrangePage(hosts: List<Host>, error: String?) =
    page("Arrange hosts", session, Nav.HOSTS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Arrange hosts", "The order of the hosts page. Pinned hosts stay on top, in this order.") {
            linkButton("/", "Back to hosts", "ghost")
        }
        if (error != null) notice("error", error)
        form(action = "/hosts/arrange", method = FormMethod.post, classes = "stack") {
            attributes["data-arrange"] = ""
            card(classes = "arrange-list") {
                hosts.forEachIndexed { index, host ->
                    div("arrange-row") {
                        attributes["data-arrange-row"] = ""
                        input(type = InputType.number, name = POSITION_FIELD + host.id) {
                            value = (index + 1).toString()
                            min = "1"
                            attributes["aria-label"] = "Position of ${host.name}"
                            attributes["inputmode"] = "numeric"
                        }
                        div("arrange-name") {
                            +host.name
                            if (host.pinned) span("icon icon-pin") {
                                attributes["role"] = "img"
                                attributes["aria-label"] = "pinned"
                                title = "pinned"
                            }
                        }
                        div("arrange-moves") {
                            // Hidden until app.js makes them work, without JavaScript they would do nothing.
                            listOf("up" to "↑", "down" to "↓").forEach { (direction, arrow) ->
                                button(type = ButtonType.button, classes = "btn sm") {
                                    attributes["data-move"] = direction
                                    attributes["aria-label"] = "Move ${host.name} $direction"
                                    attributes["hidden"] = "hidden"
                                    +arrow
                                }
                            }
                        }
                    }
                }
            }
            div("btn-row") {
                submit("Save order")
                linkButton("/", "Cancel", "ghost")
                span("muted small") { attributes["data-arrange-state"] = "" }
            }
            p("muted small") { +"Hosts with the same number keep their current order." }
        }
    }
