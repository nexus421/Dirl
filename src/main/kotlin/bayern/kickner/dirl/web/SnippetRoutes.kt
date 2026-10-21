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
import kotlinx.html.dataList
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.h2
import kotlinx.html.id
import kotlinx.html.option
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.style
import kotnexlib.ResultOf2

/** Longest snippet accepted. Snippets are commands, not scripts to upload. */
private const val MAX_SNIPPET_LENGTH = 4000

/** Longest snippet name, it has to fit on a button. */
private const val MAX_SNIPPET_NAME = 64

/** Folder names: letters, digits, spaces and a few separators, at most 32 characters, short enough for a menu button. */
private val folderPattern = Regex("^[\\p{L}\\p{N} ._-]{1,32}$")

/**
 * Snippets: commands that the terminal page offers as buttons.
 *
 * - `GET /snippets` lists them, `POST /snippets` adds one.
 * - `GET /snippets/{id}/edit`, `POST /snippets/{id}` edit, `POST /snippets/{id}/delete` removes one.
 */
fun Route.snippetRoutes(dirl: Dirl) {
    get("/snippets") { call.snippetsPage(dirl, null, null) }

    post("/snippets") {
        val form = call.receiveParameters()
        val snippet = when (val parsed = parseSnippet(form, newId())) {
            is ResultOf2.Success -> parsed.value
            is ResultOf2.Failure -> return@post call.snippetsPage(dirl, parsed.value, form)
        }
        dirl.vault.update { it.copy(snippets = it.snippets + snippet) }
        dirl.audit.record(call.session.actor, AuditAction.SNIPPET_ADDED, detail = snippet.label)
        call.respondRedirect("/snippets?done=snippet-added")
    }

    get("/snippets/{id}/edit") {
        val content = dirl.vault.content ?: return@get call.respondRedirect("/snippets")
        val snippet = content.snippets.firstOrNull { it.id == call.parameters["id"] } ?: return@get call.respondRedirect("/snippets")
        call.editSnippetPage(snippet, content.snippets, null, null)
    }

    post("/snippets/{id}") {
        val id = call.parameters["id"].orEmpty()
        val content = dirl.vault.content ?: return@post call.respondRedirect("/snippets")
        val existing = content.snippets.firstOrNull { it.id == id } ?: return@post call.respondRedirect("/snippets")
        val form = call.receiveParameters()
        val snippet = when (val parsed = parseSnippet(form, existing.id)) {
            is ResultOf2.Success -> parsed.value
            is ResultOf2.Failure -> return@post call.editSnippetPage(existing, content.snippets, parsed.value, form)
        }
        dirl.vault.update { c -> c.copy(snippets = c.snippets.map { if (it.id == id) snippet else it }) }
        dirl.audit.record(call.session.actor, AuditAction.SNIPPET_UPDATED, detail = snippet.label)
        call.respondRedirect("/snippets?done=snippet-saved")
    }

    post("/snippets/{id}/delete") {
        val id = call.parameters["id"].orEmpty()
        val snippet = dirl.vault.content?.snippets?.firstOrNull { it.id == id }
        if (snippet != null) {
            dirl.vault.update { c -> c.copy(snippets = c.snippets.filterNot { it.id == id }) }
            dirl.audit.record(call.session.actor, AuditAction.SNIPPET_DELETED, detail = snippet.label)
        }
        call.respondRedirect("/snippets?done=snippet-deleted")
    }
}

/**
 * Snippets split for display, everything sorted by name ignoring case.
 *
 * @property loose Snippets without a folder.
 * @property folders Folder names with their snippets. Grouped by the exact name: "Docker" and "docker" are two
 *   folders, as typed, none of them gets lost.
 */
data class SnippetGroups(val loose: List<Snippet>, val folders: List<Pair<String, List<Snippet>>>)

/** Groups [snippets] by folder, see [SnippetGroups]. */
fun groupSnippets(snippets: List<Snippet>): SnippetGroups {
    val byName = compareBy<Snippet> { it.name.lowercase() }
    val folders = snippets.mapNotNull { s -> s.folder?.let { it to s } }
        .groupBy({ it.first }, { it.second })
        .map { (folder, inFolder) -> folder to inFolder.sortedWith(byName) }
        .sortedBy { it.first.lowercase() }
    return SnippetGroups(snippets.filter { it.folder == null }.sortedWith(byName), folders)
}

/** `folder/name` for the audit log, the name alone without a folder. */
private val Snippet.label: String get() = folder?.let { "$it/$name" } ?: name

/**
 * Builds a snippet from the form. "Run immediately" appends a newline, which executes the command when sent. Too long
 * input is refused, not cut: a shortened command sent to a terminal could do something else than intended. An empty
 * folder means none.
 *
 * @return the snippet, or the reason to show.
 */
fun parseSnippet(form: Parameters, id: String): ResultOf2<Snippet, String> {
    val name = form["name"].orEmpty().trim()
    val command = form["command"].orEmpty().replace("\r\n", "\n").trimEnd('\n')
    val folder = form["folder"].orEmpty().trim().ifEmpty { null }
    return when {
        name.isEmpty() || command.isBlank() -> ResultOf2.Failure("Name and command are required.")
        name.length > MAX_SNIPPET_NAME -> ResultOf2.Failure("Name is longer than $MAX_SNIPPET_NAME characters.")
        command.length > MAX_SNIPPET_LENGTH -> ResultOf2.Failure("Command is longer than $MAX_SNIPPET_LENGTH characters.")
        folder != null && folderPattern.matches(folder).not() ->
            ResultOf2.Failure("Folder may only contain letters, digits, spaces, dots, dashes and underscores, at most 32 characters.")
        else -> ResultOf2.Success(Snippet(id, name, if (form["run"] == "on") "$command\n" else command, folder))
    }
}

/** The edit page of [snippet], after a failed save with [error] and the submitted [form]. */
private suspend fun ApplicationCall.editSnippetPage(snippet: Snippet, all: List<Snippet>, error: String?, form: Parameters?) =
    page("Edit ${snippet.name}", session, Nav.SNIPPETS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Edit snippet")
        if (error != null) notice("error", error)
        card { snippetForm("/snippets/${snippet.id}", snippet, "Save", form, all) }
    }

/** The list with the add form, after a failed add with [error] and the submitted [form]. */
private suspend fun ApplicationCall.snippetsPage(dirl: Dirl, error: String?, form: Parameters?) {
    val content = dirl.vault.content ?: return
    page("Snippets", session, Nav.SNIPPETS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Snippets", "Commands that appear as buttons above every terminal.")
        if (error != null) notice("error", error)
        div("stack") {
            if (content.snippets.isEmpty()) notice("info", "No snippets yet.")
            val groups = groupSnippets(content.snippets)
            // Without folders the page stays a plain list, headings only appear once there is something to tell apart.
            if (groups.folders.isNotEmpty() && groups.loose.isNotEmpty()) groupTitle("No folder", groups.loose.size)
            groups.loose.forEach { snippetCard(it) }
            groups.folders.forEach { (folder, inFolder) ->
                groupTitle(folder, inFolder.size)
                inFolder.forEach { snippetCard(it) }
            }
            card("Add snippet") { snippetForm("/snippets", null, "Add", form, content.snippets) }
        }
    }
}

private fun kotlinx.html.FlowContent.groupTitle(title: String, count: Int) = h2("group-title") {
    +title
    span("muted") { +" $count" }
}

private fun kotlinx.html.FlowContent.snippetCard(snippet: Snippet) = card {
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

/**
 * Add or edit form. A submitted [form] wins over [snippet], so a refused input is not lost. The folder field suggests
 * the folders of [all] snippets, which avoids two folders through a typo.
 */
private fun kotlinx.html.FlowContent.snippetForm(action: String, snippet: Snippet?, label: String, form: Parameters?, all: List<Snippet>) =
    form(action = action, method = FormMethod.post, classes = "form") {
        textField("Name", "name", form?.get("name") ?: snippet?.name.orEmpty(), placeholder = "Disk usage")
        textField(
            "Folder", "folder", form?.get("folder") ?: snippet?.folder.orEmpty(), required = false, placeholder = "Docker",
            hint = "Optional. Snippets of a folder share a menu above the terminal.", list = "snippet-folders",
        )
        dataList {
            id = "snippet-folders"
            groupSnippets(all).folders.forEach { (folder, _) -> option { value = folder } }
        }
        textAreaField("Command", "command", form?.get("command") ?: snippet?.command?.trimEnd('\n').orEmpty(), rows = 3)
        val run = if (form != null) form["run"] == "on" else snippet?.command?.endsWith("\n") ?: true
        checkField("Run immediately (send Enter after the command)", "run", run)
        p("muted small") { +"Snippets are sent as typed text into the terminal of whatever host is open." }
        div("btn-row") {
            submit(label)
            if (snippet != null) linkButton("/snippets", "Cancel", "ghost")
        }
    }
