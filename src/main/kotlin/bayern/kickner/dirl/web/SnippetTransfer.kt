package bayern.kickner.dirl.web

import bayern.kickner.dirl.vault.Snippet
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotnexlib.ResultOf2

/** Version of the snippet file format, the value of [SnippetFile.dirlSnippets]. */
const val SNIPPET_FORMAT_VERSION = 1

/** Most snippets one import may carry, far above any real collection. */
const val MAX_IMPORTED_SNIPPETS = 500

/** Largest snippet file accepted, in characters. 500 snippets of a few hundred characters fit many times. */
const val MAX_SNIPPET_FILE_LENGTH = 1024 * 1024

/** Most problems listed for a refused file, the rest is summed up. */
private const val MAX_LISTED_PROBLEMS = 20

/** The keys an entry may have, anything else is refused instead of silently dropped. */
private val entryKeys = setOf("name", "command", "folder", "run")

/** Pretty printed and with `run` always written, so the file reads well for people and AI tools. */
private val snippetJson = Json {
    prettyPrint = true
    encodeDefaults = true
    explicitNulls = false
}

/**
 * The file `GET /snippets/export` writes and the import reads.
 *
 * @property dirlSnippets Format version, marks the file as Dirl snippets.
 * @property snippets The snippets.
 */
@Serializable
data class SnippetFile(val dirlSnippets: Int, val snippets: List<SnippetEntry>)

/**
 * One snippet in a [SnippetFile]. Without the ID, which means nothing on another instance, and with [run] as its
 * own field instead of the trailing newline [Snippet.command] uses for it.
 *
 * @property name Display name.
 * @property command The command, without a trailing newline.
 * @property folder Optional folder.
 * @property run Whether Enter is sent after the command.
 */
@Serializable
data class SnippetEntry(val name: String, val command: String, val folder: String? = null, val run: Boolean = false) {
    /** The snippet this entry becomes, with [id]. */
    fun toSnippet(id: String): Snippet = Snippet(id, name, if (run) "$command\n" else command, folder)
}

/**
 * Ready-made snippets for tmux, which keeps a job running when the connection drops, for example when a phone locks.
 * Start attaches to the session `dirl` if it runs, so tapping it again after a disconnect shows the job again. Stop
 * ends the session from inside and outside of it, and asks first because it ends a running job. Added through the
 * import preview as ordinary snippets, so they can be changed or deleted like any other.
 */
val tmuxSnippets = listOf(
    SnippetEntry("Start tmux", "tmux new -A -s dirl", "tmux", run = true),
    SnippetEntry("Stop tmux", "tmux kill-session -t dirl", "tmux", run = false),
)

/** The entry for [this] snippet. */
fun Snippet.toEntry(): SnippetEntry = SnippetEntry(name, command.trimEnd('\n'), folder, command.endsWith("\n"))

/** Writes [snippets] as snippet file, sorted like the snippets page. */
fun exportSnippets(snippets: List<Snippet>): String {
    val groups = groupSnippets(snippets)
    val sorted = groups.loose + groups.folders.flatMap { it.second }
    return snippetJson.encodeToString(SnippetFile.serializer(), SnippetFile(SNIPPET_FORMAT_VERSION, sorted.map { it.toEntry() }))
}

/** Writes [entries] in the export format, for the preview to send them on to the apply step. */
fun encodeSnippetEntries(entries: List<SnippetEntry>): String =
    snippetJson.encodeToString(SnippetFile.serializer(), SnippetFile(SNIPPET_FORMAT_VERSION, entries))

/**
 * Reads a snippet file: the export format, or a bare array of entries as an AI tool may write it. Every entry must
 * pass the same rules as the snippet form, and two entries must not share folder and name (ignoring case). A file
 * with any problem is refused as a whole, nothing is imported halfway.
 *
 * A trailing newline in a command is dropped, [SnippetEntry.run] alone decides whether the command runs.
 *
 * @return The entries in file order, or the problems to show, each naming the entry by its number.
 */
fun parseSnippetFile(text: String): ResultOf2<List<SnippetEntry>, List<String>> {
    if (text.length > MAX_SNIPPET_FILE_LENGTH) return ResultOf2.Failure(listOf("The file is larger than ${MAX_SNIPPET_FILE_LENGTH / 1024} KiB."))
    if (text.isBlank()) return ResultOf2.Failure(listOf("Choose a file or paste the snippets."))
    val root = runCatching { Json.parseToJsonElement(text) }
        .getOrElse { return ResultOf2.Failure(listOf("This is not valid JSON.")) }
    val items = when {
        root is JsonArray -> root
        root is JsonObject && "dirlSnippets" in root -> {
            val version = (root["dirlSnippets"] as? JsonPrimitive)?.intOrNull
            if (version != SNIPPET_FORMAT_VERSION) return ResultOf2.Failure(listOf("Unknown format version, this Dirl reads version $SNIPPET_FORMAT_VERSION."))
            root["snippets"] as? JsonArray ?: return ResultOf2.Failure(listOf("\"snippets\" must be a list."))
        }
        else -> return ResultOf2.Failure(listOf("This is not a Dirl snippet file. Expected {\"dirlSnippets\": 1, \"snippets\": [...]} or a list of snippets."))
    }
    if (items.isEmpty()) return ResultOf2.Failure(listOf("The file contains no snippets."))
    if (items.size > MAX_IMPORTED_SNIPPETS) return ResultOf2.Failure(listOf("The file contains ${items.size} snippets, at most $MAX_IMPORTED_SNIPPETS can be imported at once."))

    // All problems at once, also duplicates among the valid entries, so one round of corrections is enough.
    val problems = mutableListOf<String>()
    val firstByKey = mutableMapOf<String, Int>()
    val entries = items.mapIndexedNotNull { index, item ->
        when (val entry = parseEntry(item)) {
            is ResultOf2.Success -> entry.value.also {
                val first = firstByKey.putIfAbsent(matchKey(it.folder, it.name), index)
                if (first != null) problems += "Snippet ${index + 1} (${it.label}): same folder and name as snippet ${first + 1}."
            }
            is ResultOf2.Failure -> null.also { problems += "Snippet ${index + 1}${entryLabel(item)}: ${entry.value}" }
        }
    }
    if (problems.isEmpty()) return ResultOf2.Success(entries)
    val listed = problems.take(MAX_LISTED_PROBLEMS)
    return ResultOf2.Failure(if (problems.size > listed.size) listed + "And ${problems.size - listed.size} more problems." else listed)
}

/** One entry of the file, checked like the snippet form. */
private fun parseEntry(item: JsonElement): ResultOf2<SnippetEntry, String> {
    val obj = item as? JsonObject ?: return ResultOf2.Failure("must be an object with name and command.")
    val unknown = obj.keys - entryKeys
    if (unknown.isNotEmpty()) return ResultOf2.Failure("unknown field ${unknown.sorted().joinToString { "\"$it\"" }}, allowed are name, command, folder and run.")
    fun text(key: String): ResultOf2<String?, String> = when (val value = obj[key]) {
        null, JsonNull -> ResultOf2.Success(null)
        is JsonPrimitive -> if (value.isString) ResultOf2.Success(value.content) else ResultOf2.Failure("\"$key\" must be text.")
        else -> ResultOf2.Failure("\"$key\" must be text.")
    }
    val name = when (val r = text("name")) { is ResultOf2.Success -> r.value.orEmpty().trim(); is ResultOf2.Failure -> return r }
    val command = when (val r = text("command")) {
        is ResultOf2.Success -> r.value.orEmpty().replace("\r\n", "\n").trimEnd('\n')
        is ResultOf2.Failure -> return r
    }
    val folder = when (val r = text("folder")) { is ResultOf2.Success -> r.value?.trim()?.ifEmpty { null }; is ResultOf2.Failure -> return r }
    val run = when (val value = obj["run"]) {
        null, JsonNull -> false
        else -> (value as? JsonPrimitive)?.takeIf { it.isString.not() }?.booleanOrNull ?: return ResultOf2.Failure("\"run\" must be true or false.")
    }
    snippetProblem(name, command, folder)?.let { return ResultOf2.Failure(it.replaceFirstChar(Char::lowercaseChar)) }
    return ResultOf2.Success(SnippetEntry(name, command, folder, run))
}

/** ` (name)` for a problem message when the entry has a readable name, otherwise nothing. */
private fun entryLabel(item: JsonElement): String {
    val name = ((item as? JsonObject)?.get("name") as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim().orEmpty()
    return if (name.isEmpty()) "" else " (${name.take(64)})"
}

/** `folder/name` of an entry, for messages. */
val SnippetEntry.label: String get() = folder?.let { "$it/$name" } ?: name

/** Folder and name ignoring case, what decides whether an imported snippet already exists. */
fun matchKey(folder: String?, name: String): String = "${folder.orEmpty().lowercase()}/${name.lowercase()}"

/** What importing one entry would do. */
sealed interface ImportState {
    /** No snippet with this folder and name exists. */
    data object New : ImportState

    /** Exactly this snippet exists already, importing it changes nothing. */
    data class Unchanged(val existing: Snippet) : ImportState

    /** Snippets with the same folder and name exist and would be replaced, usually one. */
    data class Replaces(val existing: List<Snippet>) : ImportState
}

/**
 * One row of the import preview.
 *
 * @property index Position of [entry] in the file, what the preview form sends back.
 * @property entry The imported snippet.
 * @property state What importing it would do.
 */
data class ImportRow(val index: Int, val entry: SnippetEntry, val state: ImportState)

/** Compares [entries] with the [existing] snippets, see [ImportState]. */
fun planImport(entries: List<SnippetEntry>, existing: List<Snippet>): List<ImportRow> {
    val byKey = existing.groupBy { matchKey(it.folder, it.name) }
    return entries.mapIndexed { index, entry ->
        val matches = byKey[matchKey(entry.folder, entry.name)].orEmpty()
        val state = when {
            matches.isEmpty() -> ImportState.New
            matches.size == 1 && matches[0].toEntry() == entry -> ImportState.Unchanged(matches[0])
            else -> ImportState.Replaces(matches)
        }
        ImportRow(index, entry, state)
    }
}

/**
 * The outcome of an import.
 *
 * @property snippets All snippets afterwards.
 * @property added Snippets that did not exist.
 * @property replaced Existing snippets replaced by an imported one.
 * @property deleted Existing snippets removed, by [applyImport] with `replaceAll` or as extra matches of a replaced one.
 */
data class ImportResult(val snippets: List<Snippet>, val added: Int, val replaced: Int, val deleted: Int)

/**
 * Applies the rows of the preview the user selected.
 *
 * A selected row adds its snippet, or replaces the existing one with the same folder and name. The replacement keeps
 * the ID of the first match, so it stays in place, further matches are removed. Unchanged rows need nothing.
 * Unselected rows change nothing.
 *
 * With [replaceAll] only the snippets of the file are left afterwards: the selected rows and the unchanged ones,
 * every other snippet is deleted.
 *
 * @param rows The rows of [planImport] against the current snippets.
 * @param selected Indexes of the rows to import, others are ignored.
 * @param newId Source of IDs for added snippets.
 */
fun applyImport(existing: List<Snippet>, rows: List<ImportRow>, selected: Set<Int>, replaceAll: Boolean, newId: () -> String): ImportResult {
    val taken = rows.filter { it.index in selected && it.state !is ImportState.Unchanged }
    // The ID each replaced snippet gets back, and the IDs removed because another match keeps its place.
    val replacements = mutableMapOf<String, Snippet>()
    val dropped = mutableSetOf<String>()
    val added = mutableListOf<Snippet>()
    taken.forEach { row ->
        when (val state = row.state) {
            is ImportState.Replaces -> {
                replacements[state.existing[0].id] = row.entry.toSnippet(state.existing[0].id)
                state.existing.drop(1).forEach { dropped += it.id }
            }
            else -> added += row.entry.toSnippet(newId())
        }
    }
    val kept = rows.mapNotNull { (it.state as? ImportState.Unchanged)?.existing?.id }.toSet() + replacements.keys
    val updated = existing.mapNotNull { snippet ->
        when {
            snippet.id in dropped -> null
            snippet.id in replacements -> replacements.getValue(snippet.id)
            replaceAll && snippet.id !in kept -> null
            else -> snippet
        }
    } + added
    return ImportResult(updated, added.size, replacements.size, existing.size + added.size - updated.size)
}
