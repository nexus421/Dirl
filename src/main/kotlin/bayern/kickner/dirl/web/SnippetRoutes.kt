package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.newId
import bayern.kickner.dirl.vault.Snippet
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FormMethod
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.h2
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.style

/** Longest snippet accepted. Snippets are commands, not scripts to upload. */
private const val MAX_SNIPPET_LENGTH = 4000

/**
 * Snippets: commands that the terminal page offers as buttons.
 *
 * - `GET /snippets` lists them, `POST /snippets` adds one.
 * - `GET /snippets/{id}/edit`, `POST /snippets/{id}` edit, `POST /snippets/{id}/delete` removes one.
 */
fun Route.snippetRoutes(dirl: Dirl) {
    get("/snippets") { call.snippetsPage(dirl, null) }

    post("/snippets") {
        val snippet = parseSnippet(call.receiveParameters(), newId()) ?: return@post call.snippetsPage(dirl, "Name and command are required.")
        dirl.vault.update { it.copy(snippets = it.snippets + snippet) }
        dirl.audit.record(call.session.actor, AuditAction.SNIPPET_ADDED, detail = snippet.name)
        call.respondRedirect("/snippets?done=snippet-added")
    }

    get("/snippets/{id}/edit") {
        val snippet = dirl.vault.content?.snippets?.firstOrNull { it.id == call.parameters["id"] } ?: return@get call.respondRedirect("/snippets")
        call.page("Edit ${snippet.name}", call.session, Nav.SNIPPETS) {
            pageHeader("Edit snippet")
            card { snippetForm("/snippets/${snippet.id}", snippet, "Save") }
        }
    }

    post("/snippets/{id}") {
        val id = call.parameters["id"].orEmpty()
        val existing = dirl.vault.content?.snippets?.firstOrNull { it.id == id } ?: return@post call.respondRedirect("/snippets")
        val snippet = parseSnippet(call.receiveParameters(), existing.id) ?: return@post call.snippetsPage(dirl, "Name and command are required.")
        dirl.vault.update { c -> c.copy(snippets = c.snippets.map { if (it.id == id) snippet else it }) }
        dirl.audit.record(call.session.actor, AuditAction.SNIPPET_UPDATED, detail = snippet.name)
        call.respondRedirect("/snippets?done=snippet-saved")
    }

    post("/snippets/{id}/delete") {
        val id = call.parameters["id"].orEmpty()
        val snippet = dirl.vault.content?.snippets?.firstOrNull { it.id == id }
        if (snippet != null) {
            dirl.vault.update { c -> c.copy(snippets = c.snippets.filterNot { it.id == id }) }
            dirl.audit.record(call.session.actor, AuditAction.SNIPPET_DELETED, detail = snippet.name)
        }
        call.respondRedirect("/snippets?done=snippet-deleted")
    }
}

/**
 * Builds a snippet from the form. "Run immediately" appends a newline, which executes the command when sent.
 *
 * @return the snippet, or `null` if name or command is missing.
 */
fun parseSnippet(form: Parameters, id: String): Snippet? {
    val name = form["name"].orEmpty().trim().take(64)
    val command = form["command"].orEmpty().replace("\r\n", "\n").trimEnd('\n').take(MAX_SNIPPET_LENGTH)
    if (name.isEmpty() || command.isBlank()) return null
    return Snippet(id, name, if (form["run"] == "on") "$command\n" else command)
}

private suspend fun ApplicationCall.snippetsPage(dirl: Dirl, error: String?) {
    val content = dirl.vault.content ?: return
    page("Snippets", session, Nav.SNIPPETS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Snippets", "Commands that appear as buttons above every terminal.")
        if (error != null) notice("error", error)
        div("stack") {
            if (content.snippets.isEmpty()) notice("info", "No snippets yet.")
            content.snippets.sortedBy { it.name.lowercase() }.forEach { snippet ->
                card {
                    div("card-header") {
                        h2 { +snippet.name }
                        span("pill") { +if (snippet.command.endsWith("\n")) "runs immediately" else "inserts only" }
                    }
                    copyBlock(snippet.command.trimEnd('\n'))
                    div("btn-row") {
                        style = "margin-top:12px"
                        linkButton("/snippets/${snippet.id}/edit", "Edit", "sm")
                        postButton("/snippets/${snippet.id}/delete", "Delete", "danger sm", confirm = "Delete snippet ${snippet.name}?")
                    }
                }
            }
            card("Add snippet") { snippetForm("/snippets", null, "Add") }
        }
    }
}

private fun kotlinx.html.FlowContent.snippetForm(action: String, snippet: Snippet?, label: String) =
    form(action = action, method = FormMethod.post, classes = "form") {
        textField("Name", "name", snippet?.name.orEmpty(), placeholder = "Disk usage")
        textAreaField("Command", "command", snippet?.command?.trimEnd('\n').orEmpty(), rows = 3)
        checkField("Run immediately (send Enter after the command)", "run", snippet?.command?.endsWith("\n") ?: true)
        p("muted small") { +"Snippets are sent as typed text into the terminal of whatever host is open." }
        div("btn-row") {
            submit(label)
            if (snippet != null) linkButton("/snippets", "Cancel", "ghost")
        }
    }
