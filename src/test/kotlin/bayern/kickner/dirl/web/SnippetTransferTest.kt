package bayern.kickner.dirl.web

import bayern.kickner.dirl.vault.Snippet
import kotnexlib.ResultOf2
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SnippetTransferTest {
    private val existing = listOf(
        Snippet("a", "Disk usage", "df -h\n", "System"),
        Snippet("b", "Logs", "docker compose logs -f", "Docker"),
        Snippet("c", "Uptime", "uptime\n", null),
    )

    private fun ok(text: String) = assertIs<ResultOf2.Success<List<SnippetEntry>>>(parseSnippetFile(text), text).value
    private fun problems(text: String) = assertIs<ResultOf2.Failure<List<String>>>(parseSnippetFile(text), text).value

    private var ids = 0
    private fun newId() = "new-${++ids}"

    @Test
    fun `an export reads back as the same snippets`() {
        val text = exportSnippets(existing)
        // run is always written, a missing folder is left out, there are no IDs.
        assertTrue(text.contains("\"dirlSnippets\": 1"), text)
        assertTrue(text.contains("\"run\": false"), text)
        assertTrue(text.contains("\"id\"").not(), text)
        assertTrue(text.contains("\"folder\": null").not(), text)
        val entries = ok(text)
        assertEquals(existing.map { it.toEntry() }.toSet(), entries.toSet())
        assertEquals(existing.toSet(), entries.map { e -> e.toSnippet(existing.first { matchKey(it.folder, it.name) == matchKey(e.folder, e.name) }.id) }.toSet())
        // Sorted like the snippets page: no folder first, then folders by name.
        assertEquals(listOf("Uptime", "Logs", "Disk usage"), entries.map { it.name })
        assertEquals(entries, ok(encodeSnippetEntries(entries)))
    }

    @Test
    fun `a bare list as an AI tool writes it is read too`() {
        val entries = ok("""[{"name": " ps ", "command": "docker ps\r\n", "folder": " Docker ", "run": true}, {"name": "top", "command": "htop", "folder": ""}]""")
        assertEquals(listOf(SnippetEntry("ps", "docker ps", "Docker", true), SnippetEntry("top", "htop", null, false)), entries)
        assertEquals("docker ps\n", entries[0].toSnippet("x").command, "run becomes the trailing newline")
        // A trailing newline in the file does not run the command, only run does.
        assertEquals(SnippetEntry("ls", "ls", null, false), ok("""[{"name": "ls", "command": "ls\n"}]""").single())
    }

    @Test
    fun `a refused file names every problem with the number of the snippet`() {
        val found = problems(
            """{"dirlSnippets": 1, "snippets": [
                {"name": "ok", "command": "ls"},
                {"name": "", "command": "ls"},
                {"name": "long", "command": "${"x".repeat(4001)}"},
                {"name": "bad folder", "command": "ls", "folder": "a/b"},
                {"name": "typo", "comand": "ls"},
                {"name": "run as text", "command": "ls", "run": "yes"},
                {"name": 5, "command": "ls"},
                "just text"
            ]}""",
        )
        assertEquals(7, found.size, found.joinToString("\n"))
        assertTrue(found[0].startsWith("Snippet 2: name and command are required"), found[0])
        assertTrue(found[1].startsWith("Snippet 3 (long): command is longer than 4000"), found[1])
        assertTrue(found[2].startsWith("Snippet 4 (bad folder): folder may only contain"), found[2])
        assertTrue(found[3].contains("unknown field \"comand\""), found[3])
        assertTrue(found[4].contains("\"run\" must be true or false"), found[4])
        assertTrue(found[5].contains("\"name\" must be text"), found[5])
        assertTrue(found[6].startsWith("Snippet 8: must be an object"), found[6])
    }

    @Test
    fun `two snippets with the same folder and name ignoring case are refused`() {
        val found = problems("""[{"name": "Logs", "command": "a", "folder": "Docker"}, {"name": "logs", "command": "b", "folder": "docker"}, {"name": "logs", "command": "c"}]""")
        assertEquals(listOf("Snippet 2 (docker/logs): same folder and name as snippet 1."), found)
        // Reported together with the other problems, in file order.
        assertEquals(
            listOf("Snippet 2: name and command are required.", "Snippet 3 (OK): same folder and name as snippet 1."),
            problems("""[{"name": "ok", "command": "ls"}, {"name": "", "command": "ls"}, {"name": "OK", "command": "ls -la"}]"""),
        )
    }

    @Test
    fun `files that are not snippets or too large are refused`() {
        assertEquals(listOf("This is not valid JSON."), problems("{nope"))
        assertTrue(problems("""{"hosts": []}""").single().startsWith("This is not a Dirl snippet file"))
        assertTrue(problems("""{"dirlSnippets": 2, "snippets": []}""").single().startsWith("Unknown format version"))
        assertEquals(listOf("The file contains no snippets."), problems("[]"))
        assertEquals(listOf("Choose a file or paste the snippets."), problems("  "))
        val many = (1..501).joinToString(",", "[", "]") { """{"name": "s$it", "command": "ls"}""" }
        assertTrue(problems(many).single().contains("501 snippets, at most 500"))
        assertTrue(problems(" ".repeat(MAX_SNIPPET_FILE_LENGTH + 1)).single().contains("larger than 1024 KiB"))
        // At most 20 problems are listed, the rest is counted.
        val broken = (1..30).joinToString(",", "[", "]") { """{"name": "", "command": "ls"}""" }
        assertEquals(21, problems(broken).size)
        assertEquals("And 10 more problems.", problems(broken).last())
    }

    @Test
    fun `the preview tells new, unchanged and replacing snippets apart ignoring case`() {
        val twin = Snippet("d", "logs", "docker logs", "docker")
        val rows = planImport(
            listOf(
                SnippetEntry("Disk usage", "df -h", "System", true),
                SnippetEntry("disk usage", "df -h", "system", true),
                SnippetEntry("Logs", "docker compose logs -f --tail=100", "Docker"),
                SnippetEntry("Uptime", "uptime", null, false),
                SnippetEntry("Free", "free -h", null, true),
            ),
            existing + twin,
        )
        assertEquals(ImportState.Unchanged(existing[0]), rows[0].state)
        assertEquals(ImportState.Replaces(listOf(existing[0])), rows[1].state, "another spelling replaces")
        assertEquals(ImportState.Replaces(listOf(existing[1], twin)), rows[2].state, "every match is named")
        assertEquals(ImportState.Replaces(listOf(existing[2])), rows[3].state, "only run differs")
        assertEquals(ImportState.New, rows[4].state)
        assertEquals((0..4).toList(), rows.map { it.index })
    }

    private val file = listOf(
        SnippetEntry("Disk usage", "df -h", "System", true),
        SnippetEntry("Logs", "docker compose logs -f --tail=100", "Docker"),
        SnippetEntry("Free", "free -h", null, true),
    )

    private fun import(selected: Set<Int>, replaceAll: Boolean, current: List<Snippet> = existing) =
        applyImport(current, planImport(file, current), selected, replaceAll, ::newId)

    @Test
    fun `importing and replacing existing ones keeps their place and ID`() {
        val result = import(setOf(0, 1, 2), replaceAll = false)
        assertEquals(
            listOf(
                existing[0],
                Snippet("b", "Logs", "docker compose logs -f --tail=100", "Docker"),
                existing[2],
                Snippet("new-1", "Free", "free -h\n", null),
            ),
            result.snippets,
        )
        assertEquals(ImportResult(result.snippets, added = 1, replaced = 1, deleted = 0), result)
    }

    @Test
    fun `importing and keeping existing ones only adds new snippets`() {
        // "Keep the existing one" unticks every row that would replace one.
        val result = import(setOf(0, 2), replaceAll = false)
        assertEquals(existing + Snippet("new-1", "Free", "free -h\n", null), result.snippets)
        assertEquals(1, result.added)
        assertEquals(0, result.replaced)
    }

    @Test
    fun `choosing single rows imports only those`() {
        val result = import(setOf(1), replaceAll = false)
        assertEquals(listOf(existing[0], Snippet("b", "Logs", "docker compose logs -f --tail=100", "Docker"), existing[2]), result.snippets)
        assertEquals(existing, import(emptySet(), replaceAll = false).snippets, "nothing selected changes nothing")
        assertEquals(existing, import(setOf(7, -1), replaceAll = false).snippets, "unknown rows are ignored")
    }

    @Test
    fun `replacing all keeps only the snippets of the file`() {
        val result = import(setOf(0, 1, 2), replaceAll = true)
        assertEquals(
            listOf(existing[0], Snippet("b", "Logs", "docker compose logs -f --tail=100", "Docker"), Snippet("new-1", "Free", "free -h\n", null)),
            result.snippets,
        )
        assertEquals(1, result.deleted, "Uptime is not in the file")
        // An unticked row that would replace a snippet deletes the existing one as well.
        val unticked = import(setOf(0, 2), replaceAll = true)
        assertEquals(listOf(existing[0], Snippet("new-2", "Free", "free -h\n", null)), unticked.snippets)
        assertEquals(2, unticked.deleted)
        // The unchanged one stays even though its row cannot be ticked.
        assertEquals(listOf(existing[0]), import(emptySet(), replaceAll = true).snippets)
    }

    @Test
    fun `a replacement removes further snippets with the same folder and name`() {
        val twin = Snippet("d", "logs", "docker logs", "docker")
        val result = import(setOf(1), replaceAll = false, current = existing + twin)
        assertEquals(listOf(existing[0], Snippet("b", "Logs", "docker compose logs -f --tail=100", "Docker"), existing[2]), result.snippets)
        assertEquals(1, result.replaced)
        assertEquals(1, result.deleted)
    }
}
