package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.newId
import bayern.kickner.dirl.vault.Snippet
import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveMultipart
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.header
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.utils.io.discard
import io.ktor.utils.io.readRemaining
import kotlinx.io.readByteArray
import kotlinx.html.FormEncType
import kotlinx.html.FormMethod
import kotlinx.html.checkBoxInput
import kotlinx.html.dataList
import kotlinx.html.details
import kotlinx.html.div
import kotlinx.html.fileInput
import kotlinx.html.form
import kotlinx.html.hiddenInput
import kotlinx.html.id
import kotlinx.html.label
import kotlinx.html.li
import kotlinx.html.option
import kotlinx.html.p
import kotlinx.html.pre
import kotlinx.html.radioInput
import kotlinx.html.span
import kotlinx.html.style
import kotlinx.html.summary
import kotlinx.html.title
import kotlinx.html.ul
import kotnexlib.ResultOf2
import java.time.LocalDate

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
 * - `GET /snippets/export` downloads all snippets as [SnippetFile].
 * - `POST /snippets/import` reads an uploaded or pasted file and shows the preview, nothing is saved yet.
 *   `POST /snippets/import/apply` saves the rows selected there.
 * - `GET /snippets/tmux` shows the same preview for the ready-made [tmuxSnippets].
 */
fun Route.snippetRoutes(dirl: Dirl) {
    get("/snippets") { call.snippetsPage(dirl, null, null) }

    get("/snippets/export") {
        val content = dirl.vault.content ?: return@get call.respondRedirect("/snippets")
        dirl.audit.record(call.session.actor, AuditAction.SNIPPETS_EXPORTED, detail = "${content.snippets.size} snippets")
        call.response.header(
            HttpHeaders.ContentDisposition,
            ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, "dirl-snippets-${LocalDate.now()}.json").toString(),
        )
        call.respondText(exportSnippets(content.snippets), ContentType.Application.Json)
    }

    post("/snippets/import") {
        val text = when (val received = runCatching { call.receiveSnippetFile() }.getOrElse { ResultOf2.Failure("The upload could not be read.") }) {
            is ResultOf2.Success -> received.value
            is ResultOf2.Failure -> return@post call.snippetsPage(dirl, null, null, ImportInput("", listOf(received.value)))
        }
        val entries = when (val parsed = parseSnippetFile(text)) {
            is ResultOf2.Success -> parsed.value
            // A pasted text comes back into the field for correcting, an uploaded file is too large to echo.
            is ResultOf2.Failure -> return@post call.snippetsPage(dirl, null, null, ImportInput(text.takeIf { it.length <= MAX_ECHOED_IMPORT }.orEmpty(), parsed.value))
        }
        val content = dirl.vault.content ?: return@post call.respondRedirect("/snippets")
        call.importPreviewPage(entries, content.snippets)
    }

    get("/snippets/tmux") {
        val content = dirl.vault.content ?: return@get call.respondRedirect("/snippets")
        call.importPreviewPage(tmuxSnippets, content.snippets, readyMade = "tmux")
    }

    post("/snippets/import/apply") {
        val form = call.receiveParameters()
        // The preview sent the entries on, they are checked again like any input.
        val entries = when (val parsed = parseSnippetFile(form["data"].orEmpty())) {
            is ResultOf2.Success -> parsed.value
            is ResultOf2.Failure -> return@post call.snippetsPage(dirl, null, null, ImportInput("", parsed.value))
        }
        val selected = form.getAll("take").orEmpty().mapNotNull { it.toIntOrNull() }.toSet()
        val replaceAll = form["replaceAll"] == "on"
        var result: ImportResult? = null
        // Planned against the snippets at this moment, a change since the preview is taken into account.
        dirl.vault.update { c ->
            val outcome = applyImport(c.snippets, planImport(entries, c.snippets), selected, replaceAll, ::newId)
            result = outcome
            c.copy(snippets = outcome.snippets)
        }
        val outcome = result ?: return@post call.respondRedirect("/snippets")
        dirl.audit.record(
            call.session.actor, AuditAction.SNIPPETS_IMPORTED,
            detail = "added=${outcome.added} replaced=${outcome.replaced} deleted=${outcome.deleted}" + if (replaceAll) " replaceAll" else "",
        )
        call.respondRedirect("/snippets?done=snippets-imported")
    }

    post("/snippets") {
        val form = call.receiveParameters()
        val snippet = when (val parsed = parseSnippet(form, newId())) {
            is ResultOf2.Success -> parsed.value
            is ResultOf2.Failure -> return@post call.snippetsPage(dirl, parsed.value, form)
        }
        dirl.vault.update { it.copy(snippets = it.snippets + snippet) }
        dirl.audit.record(call.session.actor, AuditAction.SNIPPET_ADDED, detail = snippet.label)
        call.respondRedirect("/snippets?done=snippet-added&$OPEN_PARAM=${snippet.id}")
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
        call.respondRedirect("/snippets?done=snippet-saved&$OPEN_PARAM=${snippet.id}")
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
    snippetProblem(name, command, folder)?.let { return ResultOf2.Failure(it) }
    return ResultOf2.Success(Snippet(id, name, if (form["run"] == "on") "$command\n" else command, folder))
}

/**
 * The rules every snippet follows, from the form or from an import: name and command are required, both have a
 * maximum length, at most [MAX_PLACEHOLDERS] placeholders, the folder a fixed set of characters. [name] and [folder] are expected trimmed, [command] without
 * a trailing newline.
 *
 * @return The reason the snippet is refused, `null` if it is fine.
 */
fun snippetProblem(name: String, command: String, folder: String?): String? = when {
    name.isEmpty() || command.isBlank() -> "Name and command are required."
    name.length > MAX_SNIPPET_NAME -> "Name is longer than $MAX_SNIPPET_NAME characters."
    command.length > MAX_SNIPPET_LENGTH -> "Command is longer than $MAX_SNIPPET_LENGTH characters."
    placeholdersOf(command).size > MAX_PLACEHOLDERS -> "At most $MAX_PLACEHOLDERS different placeholders like {{Name}} per snippet."
    folder != null && folderPattern.matches(folder).not() ->
        "Folder may only contain letters, digits, spaces, dots, dashes and underscores, at most 32 characters."
    else -> null
}

/** The edit page of [snippet], after a failed save with [error] and the submitted [form]. */
private suspend fun ApplicationCall.editSnippetPage(snippet: Snippet, all: List<Snippet>, error: String?, form: Parameters?) =
    page("Edit ${snippet.name}", session, Nav.SNIPPETS, status = if (error == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Edit snippet")
        if (error != null) notice("error", error)
        card { snippetForm("/snippets/${snippet.id}", snippet, "Save", form, all) }
    }

/** Query parameter naming the snippet just added or saved, its folder opens on the snippets page. */
private const val OPEN_PARAM = "open"

/** Longest pasted import that comes back into the text field after a refusal. */
private const val MAX_ECHOED_IMPORT = 64 * 1024

/**
 * A refused import, shown in the import card.
 *
 * @property text What was pasted, empty for an upload.
 * @property problems Why it was refused.
 */
private data class ImportInput(val text: String, val problems: List<String>)

/**
 * Reads the import form: the uploaded file if one was chosen, otherwise the pasted text. A file larger than
 * [MAX_SNIPPET_FILE_LENGTH] bytes is read to the end and dropped, so the browser still gets the answer.
 *
 * @return The text, or why it cannot be used.
 */
private suspend fun ApplicationCall.receiveSnippetFile(): ResultOf2<String, String> {
    var file: String? = null
    var pasted: String? = null
    var tooLarge = false
    // The pasted text may be somewhat larger than the file limit, parseSnippetFile refuses it with a message.
    receiveMultipart(formFieldLimit = 4L * MAX_SNIPPET_FILE_LENGTH).forEachPart { part ->
        when {
            part is PartData.FileItem && part.name == "file" && file == null -> {
                val channel = part.provider()
                val bytes = channel.readRemaining(MAX_SNIPPET_FILE_LENGTH + 1L).readByteArray()
                if (bytes.size > MAX_SNIPPET_FILE_LENGTH) tooLarge = true.also { channel.discard() }
                else file = bytes.decodeToString()
            }
            part is PartData.FormItem && part.name == "json" -> pasted = part.value
        }
        part.release()
    }
    if (tooLarge) return ResultOf2.Failure("The file is larger than ${MAX_SNIPPET_FILE_LENGTH / 1024} KiB.")
    return ResultOf2.Success(file?.takeIf { it.isNotBlank() } ?: pasted.orEmpty())
}

/**
 * The list with the add form, after a failed add with [error] and the submitted [form], or after a refused
 * [import].
 */
private suspend fun ApplicationCall.snippetsPage(dirl: Dirl, error: String?, form: Parameters?, import: ImportInput? = null) {
    val content = dirl.vault.content ?: return
    page("Snippets", session, Nav.SNIPPETS, status = if (error == null && import == null) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Snippets", "Commands that appear as buttons above every terminal.")
        if (error != null) notice("error", error)
        if (import != null) notice("error", "The import was refused, nothing changed. See below.")
        div("stack") {
            if (content.snippets.isEmpty()) notice("info", "No snippets yet.")
            val groups = groupSnippets(content.snippets)
            // The folder of the snippet just added or saved opens, the others stay folded.
            val open = request.queryParameters[OPEN_PARAM]?.let { id -> content.snippets.firstOrNull { it.id == id } }
            // Without folders the page stays a plain list, folding only starts once there is something to tell apart.
            if (groups.folders.isEmpty()) {
                if (groups.loose.isNotEmpty()) div("card snippet-list") { groups.loose.forEach { snippetRow(it) } }
            } else {
                div("snippet-folders") {
                    if (groups.loose.isNotEmpty()) snippetFolder("No folder", groups.loose, open != null && open.folder == null)
                    groups.folders.forEach { (folder, inFolder) -> snippetFolder(folder, inFolder, open?.folder == folder) }
                }
            }
            card("Ready-made snippets") {
                p("muted small") {
                    +"tmux keeps a job running when the connection drops, for example when the phone locks. Tap Start tmux before a long job "
                    +"and again to get back to it, Stop tmux ends it. tmux must be installed on the host."
                }
                div("btn-row") { linkButton("/snippets/tmux", "Add tmux snippets", "sm") }
            }
            card("Add snippet") { snippetForm("/snippets", null, "Add", form, content.snippets) }
            importCard(content.snippets.size, import)
        }
    }
}

/** Export of all snippets and the import form, with the problems of a refused [import]. */
private fun kotlinx.html.FlowContent.importCard(count: Int, import: ImportInput?) = card("Import and export") {
    div("btn-row") {
        if (count > 0) linkButton("/snippets/export", "Export all $count snippets")
        else span("muted small") { +"Nothing to export yet." }
    }
    p("muted small") {
        +"A JSON file to share, to keep or to have an AI tool fill: {\"dirlSnippets\": 1, \"snippets\": [{\"name\": \"Disk usage\", \"command\": \"df -h\", \"folder\": \"System\", \"run\": true}]}. "
        +"Folder and run are optional. A plain list of snippets works as well."
    }
    if (import != null) div("notice error import-problems") {
        ul { import.problems.forEach { li { +it } } }
    }
    form(action = "/snippets/import", method = FormMethod.post, encType = FormEncType.multipartFormData, classes = "form") {
        // The whole area is the label of the hidden file input, a click opens the file chooser without JavaScript.
        // Dropping a file and showing its name is app.js.
        label("drop-zone") {
            attributes["data-drop"] = ""
            fileInput(name = "file", classes = "drop-input") {
                accept = ".json,application/json"
                attributes["aria-label"] = "Snippet file"
            }
            span("icon icon-upload") { }
            span("drop-main") { +"Drop a JSON file here" }
            span("drop-sub") {
                +"or "
                span("drop-link") { +"choose one" }
                +", at most ${MAX_SNIPPET_FILE_LENGTH / 1024 / 1024} MiB"
            }
        }
        textAreaField("Or paste the JSON", "json", import?.text.orEmpty(), rows = 5, required = false)
        p("muted small") { +"Nothing is saved yet, the next page shows what the import would change." }
        div("btn-row") { submit("Show preview", "") }
    }
}

/**
 * What the import of [entries] would change in [existing], with a checkbox per snippet. For the ready-made snippets
 * named by [readyMade] it is titled after them and does not offer to delete all other snippets.
 */
private suspend fun ApplicationCall.importPreviewPage(entries: List<SnippetEntry>, existing: List<Snippet>, readyMade: String? = null) {
    val rows = planImport(entries, existing)
    val conflicts = rows.count { it.state is ImportState.Replaces }
    val fileKeys = entries.map { matchKey(it.folder, it.name) }.toSet()
    val notInFile = existing.count { matchKey(it.folder, it.name) !in fileKeys }
    val title = readyMade?.let { "Add $it snippets" } ?: "Import snippets"
    val counted = if (readyMade == null) "${entries.size} snippets in the file" else "${entries.size} ready-made snippets"
    page(title, session, Nav.SNIPPETS) {
        pageHeader(title, "$counted: ${rows.count { it.state == ImportState.New }} new, $conflicts replacing existing ones, ${rows.count { it.state is ImportState.Unchanged }} unchanged.")
        notice("info", "Nothing is saved until you import. Snippets marked \"runs immediately\" execute on the server as soon as you click them in a terminal.")
        form(action = "/snippets/import/apply", method = FormMethod.post, classes = "stack") {
            hiddenInput(name = "data") { value = encodeSnippetEntries(entries) }
            if (conflicts > 0) card("When a snippet already exists") {
                div("form") {
                    label("check") {
                        radioInput(name = "conflicts") { value = "replace"; checked = true; attributes["data-import-conflicts"] = "replace" }
                        span { +"Replace the existing one" }
                    }
                    label("check") {
                        radioInput(name = "conflicts") { value = "keep"; attributes["data-import-conflicts"] = "keep" }
                        span { +"Keep the existing one" }
                    }
                    p("muted small") { +"Only sets the checkboxes below, every row can still be changed." }
                }
            }
            card(classes = "import-rows") { rows.forEach { importRow(it) } }
            if (readyMade == null) card {
                checkField("Delete all other snippets and keep only the ones selected here", "replaceAll", false)
                p("muted small") {
                    +"Deletes the $notInFile of your ${existing.size} snippets that are not in the file, and every existing snippet whose row is not ticked. "
                    +"Off: snippets that are not in the file stay as they are."
                }
            }
            div("btn-row") {
                submit("Import selected")
                linkButton("/snippets", "Cancel", "ghost")
            }
        }
    }
}

/** One row of the import preview: checkbox, name, state and the command, for a replacement also the old one. */
private fun kotlinx.html.FlowContent.importRow(row: ImportRow) = div("import-row") {
    val state = row.state
    val checkboxId = "import-${row.index}"
    checkBoxInput(name = "take") {
        id = checkboxId
        value = row.index.toString()
        checked = state !is ImportState.Unchanged
        disabled = state is ImportState.Unchanged
        if (state is ImportState.Replaces) attributes["data-conflict"] = "1"
    }
    div("import-body") {
        div("import-title") {
            if (row.entry.folder != null) span("muted") { +"${row.entry.folder} / " }
            label("import-name") {
                htmlFor = checkboxId
                +row.entry.name
            }
            when (state) {
                ImportState.New -> pill("ok", "new")
                is ImportState.Replaces -> pill("warn", if (state.existing.size == 1) "replaces existing" else "replaces ${state.existing.size} existing")
                is ImportState.Unchanged -> pill("", "already there, unchanged")
            }
            if (row.entry.run) pill("error", "runs immediately")
            variablesPill(row.entry.command)
        }
        if (state is ImportState.Replaces) {
            state.existing.forEach { old ->
                p("muted small") { +"Existing ${old.folder?.let { "$it / " }.orEmpty()}${old.name}, ${if (old.command.endsWith("\n")) "runs immediately" else "asks first"}:" }
                div("code") { pre { +old.command.trimEnd('\n') } }
            }
            p("muted small") { +"From the file:" }
        }
        div("code") { pre { +row.entry.command } }
    }
}

/** A folded folder of the snippets page with the number of its snippets, [open] for the one just changed. */
private fun kotlinx.html.FlowContent.snippetFolder(title: String, snippets: List<Snippet>, open: Boolean) = details("snippet-folder") {
    if (open) attributes["open"] = "open"
    summary {
        span("snippet-folder-name") { +title }
        span("muted") { +snippets.size.toString() }
    }
    div("snippet-list") { snippets.forEach { snippetRow(it) } }
}

/** A pill naming the variables [command] asks for before it is sent, nothing without variables. */
private fun kotlinx.html.FlowContent.variablesPill(command: String) {
    val variables = placeholdersOf(command)
    if (variables.isNotEmpty()) pill("accent", "variables: ${variables.joinToString { it.name }}")
}

/** One snippet as a compact row: name, whether it runs, the command on one line (complete as tooltip), actions. */
private fun kotlinx.html.FlowContent.snippetRow(snippet: Snippet) = div("snippet-row") {
    val command = snippet.command.trimEnd('\n')
    div("snippet-main") {
        div("snippet-title") {
            span("snippet-name") { +snippet.name }
            if (snippet.command.endsWith("\n")) pill("error", "runs immediately") else pill("", "asks first")
            variablesPill(snippet.command)
        }
        div("snippet-command") {
            title = command
            +command.lineSequence().first().let { if (command.contains('\n')) "$it …" else it }
        }
    }
    div("btn-row") {
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
        textAreaField(
            "Command", "command", form?.get("command") ?: snippet?.command?.trimEnd('\n').orEmpty(), rows = 3,
            hint = "Variables like {{Name}} or {{Name:default}} are asked for when the snippet is clicked, e.g. docker logs --tail {{Lines:100}} {{Container}}.",
        )
        val run = if (form != null) form["run"] == "on" else snippet?.command?.endsWith("\n") ?: true
        checkField("Run immediately, without asking first", "run", run)
        p("muted small") { +"Snippets are sent as typed text into the terminal of whatever host is open. Without \"Run immediately\" a click shows the command first, with Send and Cancel." }
        div("btn-row") {
            submit(label)
            if (snippet != null) linkButton("/snippets", "Cancel", "ghost")
        }
    }
