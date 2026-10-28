package bayern.kickner.dirl.web

/**
 * A placeholder in a snippet command, `{{Name}}` or `{{Name:default}}`. Clicking the snippet in a terminal asks for
 * its value first (`terminal.js`), a name used several times is asked for once.
 *
 * @property name Letters, digits, `_` and `-`, starting with a capital letter.
 * @property default Prefilled value, `null` without one.
 */
data class Placeholder(val name: String, val default: String?)

/**
 * `{{Name}}` and `{{Name:default}}`. The name has to start with a capital letter: Go templates of Docker, kubectl and
 * Helm (`{{.Names}}`, `{{ .Status }}`, `{{end}}`, `{{else}}`) and the usual template variables are lower case or start
 * with a dot or a space, they stay what they are. A default ends at the closing braces and holds no braces and no
 * line breaks. `terminal.js` uses the same pattern, keep them equal.
 */
val PLACEHOLDER_PATTERN = Regex("\\{\\{([A-Z][A-Za-z0-9_-]{0,31})(?::([^{}\\r\\n]{0,200}))?\\}\\}")

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
