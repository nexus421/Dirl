package bayern.kickner.dirl.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Runs the placeholder code of `terminal.js` in Node, the JavaScript engine the browser logic was written for, and
 * compares it with [PLACEHOLDER_PATTERN] and [placeholdersOf]. [SnippetPlaceholdersTest] only runs the copy of the
 * pattern with Java's engine and cannot see where JavaScript counts differently. Skipped without `node` on the path,
 * the GitHub runners have it.
 */
class TerminalJsTest {
    private val script = javaClass.getResource("/static/terminal.js")!!.readText()

    /** The pattern and the functions that find and fill placeholders, from the pattern up to `fillPlaceholders`. */
    private val placeholderCode = Regex("(?s)  const placeholderPattern = .*?\n  function fillPlaceholders\\(command, values\\) \\{.*?\n  }\n")
        .find(script)?.value ?: error("placeholder code not found in terminal.js, update TerminalJsTest")

    /** `askValues`, which collects the typed values from the fields above the terminal. */
    private val askValuesCode = Regex("(?s)  function askValues\\(\\) \\{.*?\n  }\n")
        .find(script)?.value ?: error("askValues not found in terminal.js, update TerminalJsTest")

    private fun nodeAvailable() = runCatching {
        val process = ProcessBuilder("node", "--version").redirectErrorStream(true).start()
        process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0
    }.getOrDefault(false)

    /** Runs [body] in Node after the code from `terminal.js`, `input` holds [input], whatever it writes is returned. */
    private fun runInNode(input: String, body: String): String {
        val dir = Files.createTempDirectory("dirl-js").toFile()
        try {
            val inputFile = File(dir, "input.json").apply { writeText(input) }
            // askFields is the form above the terminal in the page, here a stand-in with the same querySelectorAll.
            val program = File(dir, "test.js").apply {
                writeText("const input = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));\nlet askFields;\n$placeholderCode$askValuesCode$body\n")
            }
            val process = ProcessBuilder("node", program.absolutePath, inputFile.absolutePath).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "node did not finish")
            assertEquals(0, process.exitValue(), output)
            return output
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `terminal js finds the same placeholders and defaults as the server, emoji included`() {
        assumeTrue(nodeAvailable(), "No node on the path")
        val emoji = "\uD83D\uDE00"
        val fixed = listOf(
            "docker logs --tail {{Lines:100}} -f {{Container}}", "{{Path:\${HOME}/logs}}", "{{.Names}}", "{{ .Status }}", "{{end}}",
            "{{a:}}", "{{a:b}c}}", "{{a:}}}}", "{{a:{{b}}}}", "{{x:line\nbreak}}", "{{A:\r}}", "{{}}", "{{A}} {{A:later}} {{A:ignored}}",
            "touch /tmp/x {{Note:" + emoji.repeat(150) + "}}\n",
        ) + (98..102).map { "{{a:" + emoji.repeat(it) + "}}" } + (198..202).map { "{{a:" + emoji.repeat(it) + "}}" } +
            (198..202).map { "{{a:" + "x".repeat(it) + "}}" } + (30..34).map { "{{" + "n".repeat(it) + "}}" }
        // Whole characters only, a lone half of a surrogate pair cannot come from a browser form.
        val alphabet = listOf("{", "}", ":", "a", "_", "-", ".", " ", "\n", "\r", "$", "x", emoji, "\u00e4")
        val random = Random(42)
        val cases = fixed + List(20_000) { List(random.nextInt(0, 24)) { alphabet[random.nextInt(alphabet.size)] }.joinToString("") }

        val output = runInNode(
            Json.encodeToString(JsonArray.serializer(), JsonArray(cases.map(::JsonPrimitive))),
            """
            process.stdout.write(JSON.stringify(input.map(text => ({
              matches: [...text.matchAll(placeholderPattern)].map(m => [m.index, m.index + m[0].length, m[1] ?? null, m[2] ?? null]),
              names: [...placeholdersOf(text).entries()].map(([name, value]) => [name, value ?? null]),
            }))));
            """.trimIndent(),
        )
        val inBrowser = Json.parseToJsonElement(output).jsonArray
        assertEquals(cases.size, inBrowser.size)

        fun JsonArray.strings() = map { (it as? JsonPrimitive)?.takeIf { p -> p !is JsonNull }?.content }
        val differing = cases.indices.filter { i ->
            val js = inBrowser[i].jsonObject
            val jsMatches = js["matches"]!!.jsonArray.map { it.jsonArray.strings() }
            val ktMatches = PLACEHOLDER_PATTERN.findAll(cases[i]).map { listOf(it.range.first.toString(), (it.range.last + 1).toString(), it.groups[1]?.value, it.groups[2]?.value) }.toList()
            val jsNames = js["names"]!!.jsonArray.map { it.jsonArray.strings() }
            val ktNames = placeholdersOf(cases[i]).map { listOf(it.name, it.default) }
            jsMatches != ktMatches || jsNames != ktNames
        }
        assertEquals(emptyList(), differing.take(5).map { cases[it] }, "${differing.size} of ${cases.size} inputs differ")
    }

    @Test
    fun `values named like object properties are filled in, control characters dropped`() {
        assumeTrue(nodeAvailable(), "No node on the path")
        val command = "echo {{__proto__}} {{constructor}} {{toString}} {{Name:x}}"
        val fields = listOf("__proto__" to "a", "constructor" to "b", "toString" to "c", "Name" to "d\u0007e\nf")
        val input = buildJsonObject {
            put("command", command)
            put("fields", buildJsonArray { fields.forEach { (name, value) -> add(buildJsonArray { add(JsonPrimitive(name)); add(JsonPrimitive(value)) }) } })
        }
        val output = runInNode(
            input.toString(),
            """
            askFields = { querySelectorAll: () => input.fields.map(([name, value]) => ({ name, value })) };
            process.stdout.write(JSON.stringify({ sent: fillPlaceholders(input.command, askValues()) }));
            """.trimIndent(),
        )
        val result = Json.parseToJsonElement(output).jsonObject
        assertEquals("echo a b c def", result["sent"]!!.jsonPrimitive.content)
    }
}
