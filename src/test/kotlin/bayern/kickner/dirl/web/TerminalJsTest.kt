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

    /** `pasteNeedsConfirm`, which decides whether pasted text asks before it reaches the shell. */
    private val pasteNeedsConfirmCode = Regex("(?s)  function pasteNeedsConfirm\\(text, bracketed\\) \\{.*?\n  }\n")
        .find(script)?.value ?: error("pasteNeedsConfirm not found in terminal.js, update TerminalJsTest")

    /** `showControls`, which makes control characters visible in the paste preview. */
    private val showControlsCode = Regex("(?s)  function showControls\\(text\\) \\{.*?\n  }\n")
        .find(script)?.value ?: error("showControls not found in terminal.js, update TerminalJsTest")

    /** `hintPosition`, which places the "Copied" hint near the mouse inside the terminal. */
    private val hintPositionCode = Regex("(?s)  function hintPosition\\(x, y, width, height, boxWidth, boxHeight\\) \\{.*?\n  }\n")
        .find(script)?.value ?: error("hintPosition not found in terminal.js, update TerminalJsTest")

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
                writeText("const input = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));\nlet askFields;\n$placeholderCode$askValuesCode$pasteNeedsConfirmCode$showControlsCode$hintPositionCode$body\n")
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
    fun `pasted text asks only when a line break would run it`() {
        assumeTrue(nodeAvailable(), "No node on the path")
        val cases = listOf(
            Triple("ls", false, false),
            Triple("ls\n", false, true),
            Triple("a\r\nb", false, true),
            Triple("a\rb", false, true),
            Triple("a\nb", true, false),
            Triple("", false, false),
            Triple("a\tb", true, false),
            // Bracketed paste does not protect against an escape: xterm passes it on, \e[201~ ends the bracket early.
            Triple("a\u001b[201~rm -rf ~\r", true, true),
            Triple("x\u001b", false, true),
            Triple("a\u0003", true, true),
            Triple("a\u007f", true, true),
        )
        val input = buildJsonArray { cases.forEach { (text, bracketed, _) -> add(buildJsonArray { add(JsonPrimitive(text)); add(JsonPrimitive(bracketed)) }) } }
        val output = runInNode(
            input.toString(),
            "process.stdout.write(JSON.stringify(input.map(([text, bracketed]) => pasteNeedsConfirm(text, bracketed))));",
        )
        assertEquals(cases.map { it.third }, Json.parseToJsonElement(output).jsonArray.map { it.jsonPrimitive.content.toBoolean() })
    }

    @Test
    fun `the paste preview shows control characters`() {
        assumeTrue(nodeAvailable(), "No node on the path")
        val cases = listOf("ls -l\nwho\r\n" to "ls -l\nwho\n", "a\tb" to "a\tb", "a\u001b[201~b" to "a^[[201~b", "\u0003\u007f" to "^C^?")
        val input = buildJsonArray { cases.forEach { add(JsonPrimitive(it.first)) } }
        val output = runInNode(input.toString(), "process.stdout.write(JSON.stringify(input.map(showControls)));")
        assertEquals(cases.map { it.second }, Json.parseToJsonElement(output).jsonArray.map { it.jsonPrimitive.content })
    }

    /** Runs `hintPosition` in Node for each `[x, y, width, height, boxWidth, boxHeight]`, `null` for a missing number. */
    private fun hintPositions(cases: List<List<Double?>>): List<Pair<Double, Double>> {
        val input = buildJsonArray { cases.forEach { case -> add(buildJsonArray { case.forEach { add(JsonPrimitive(it)) } }) } }
        val output = runInNode(input.toString(), "process.stdout.write(JSON.stringify(input.map(a => { const p = hintPosition(...a); return [p.left, p.top]; })));")
        return Json.parseToJsonElement(output).jsonArray.map { it.jsonArray[0].jsonPrimitive.content.toDouble() to it.jsonArray[1].jsonPrimitive.content.toDouble() }
    }

    @Test
    fun `the copied hint sits above the mouse and moves inside the terminal at its edges`() {
        assumeTrue(nodeAvailable(), "No node on the path")
        // A 60 x 20 hint in an 800 x 400 terminal, unless the case says otherwise.
        val cases = listOf(
            listOf(200.0, 100.0) to (170.0 to 74.0), // centred, a gap above the mouse
            listOf(200.0, 30.0) to (170.0 to 4.0), // just enough room above
            listOf(200.0, 29.0) to (170.0 to 49.0), // no room above: below the mouse pointer
            listOf(200.0, 0.0) to (170.0 to 20.0), // top edge
            listOf(0.0, 100.0) to (4.0 to 74.0), // left edge
            listOf(10.0, 100.0) to (4.0 to 74.0), // near the left edge
            listOf(800.0, 100.0) to (736.0 to 74.0), // right edge
            listOf(800.0, 400.0) to (736.0 to 374.0), // bottom right corner
            listOf(0.0, 0.0) to (4.0 to 20.0), // top left corner
            listOf(1000.0, 600.0) to (736.0 to 374.0), // drag ended right of and below the terminal
            listOf(-50.0, -30.0) to (4.0 to 20.0), // drag ended left of and above the terminal
            listOf(null, null) to (4.0 to 20.0), // not a number counts as the top left
            listOf(200.6, 100.4) to (171.0 to 74.0), // whole pixels
        )
        val output = hintPositions(cases.map { it.first + listOf(60.0, 20.0, 800.0, 400.0) })
        assertEquals(cases.map { it.second }, output)

        // A terminal too small for the hint pins it to the top left instead of a negative position, a flat one keeps
        // it inside below the mouse.
        assertEquals(listOf(0.0 to 0.0, 370.0 to 16.0), hintPositions(listOf(listOf(25.0, 10.0, 60.0, 20.0, 50.0, 20.0), listOf(400.0, 5.0, 60.0, 20.0, 800.0, 40.0))))
    }

    @Test
    fun `the copied hint stays inside the terminal and never covers the mouse, wherever it lets go`() {
        assumeTrue(nodeAvailable(), "No node on the path")
        val random = Random(7)
        val points = (-100..900 step 25).flatMap { x -> (-100..500 step 25).map { y -> x.toDouble() to y.toDouble() } } +
            List(2000) { random.nextDouble(-200.0, 1000.0) to random.nextDouble(-200.0, 600.0) }
        val output = hintPositions(points.map { (x, y) -> listOf(x, y, 60.0, 20.0, 800.0, 400.0) })
        points.zip(output).forEach { (point, at) ->
            val (left, top) = at
            val x = point.first.coerceIn(0.0, 800.0)
            val y = point.second.coerceIn(0.0, 400.0)
            assertTrue(left in 4.0..736.0 && top in 4.0..376.0, "$point gives $at outside the terminal")
            assertTrue(left == Math.rint(left) && top == Math.rint(top), "$point gives $at, not whole pixels")
            assertTrue(y < top || y > top + 20, "$point gives $at over the mouse")
        }
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
