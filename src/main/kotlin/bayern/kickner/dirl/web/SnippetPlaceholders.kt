package bayern.kickner.dirl.web

/**
 * A placeholder in a snippet command, a variable with an optional default: `{{Name}}` or `{{Name:default}}`. Clicking
 * the snippet in a terminal asks for its value first (`terminal.js`), a name used several times is asked for once.
 *
 * @property name Letters in either case, digits, `_` and `-`, at most 32.
 * @property default Prefilled value, `null` without one.
 */
data class Placeholder(val name: String, val default: String?)

/**
 * `{{Name}}` and `{{Name:default}}`. The name holds letters, digits, `_` and `-`, no spaces. Everything after the colon
 * up to the closing `}}` is the default, braces included (`{{Path:${HOME}/logs}}`), only line breaks are not.
 * Templates with a dot or a space stay what they are (`{{.Names}}`, `{{ .Status }}`, `{{json .Config}}`), bare words
 * like `{{end}}` in a Go template do count as variables, the snippets page shows them. `terminal.js` has its own copy
 * with the `u` flag, so it counts characters like Kotlin. `SnippetPlaceholdersTest` checks that the copy is the same
 * pattern with that flag.
 */
val PLACEHOLDER_PATTERN = "\\{\\{([A-Za-z0-9_-]{1,32})(?::((?:(?!}})[^\\r\\n]){0,200}))?}}".toRegex()

/** Most different placeholders in one snippet, more would not fit the question above the terminal. */
const val MAX_PLACEHOLDERS = 10

/**
 * The placeholders of [command] in order of their first appearance, each name once. When a name appears several
 * times, the first default given for it counts.
 */
fun placeholdersOf(command: String): List<Placeholder> {
    val byName = linkedMapOf<String, String?>()
    PLACEHOLDER_PATTERN.findAll(command).forEach { match ->
        val name = match.groupValues[1]
        val default = match.groups[2]?.value
        if (name !in byName || (byName[name] == null && default != null)) byName[name] = default
    }
    return byName.map { (name, default) -> Placeholder(name, default) }
}
