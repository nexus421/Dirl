package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.ssh.generateEd25519Key
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.Snippet
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.parameters
import io.ktor.http.parametersOf
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotnexlib.ResultOf2
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SnippetFolderTest {
    private val dataDir = Files.createTempDirectory("dirl-snippets").toFile()
    private val dirl = createDirl(
        AppConfig(
            publicUrl = "https://ssh.example.com",
            dataDir = dataDir.absolutePath,
            oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret"),
        ),
        dataDir,
    )
    private val actor = Actor("user-1", "Ada")

    init {
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), actor)
    }

    private fun form(vararg pairs: Pair<String, String>) = parametersOf(*pairs.map { it.first to listOf(it.second) }.toTypedArray())

    private fun ApplicationTestBuilder.loggedIn(): Pair<io.ktor.client.HttpClient, String> {
        application { dirlModule(dirl) }
        return createClient { followRedirects = false } to "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"
    }

    @Test
    fun `the folder is optional, trimmed and validated`() {
        fun folderOf(folder: String) = parseSnippet(form("name" to "ps", "command" to "docker ps", "folder" to folder), "id")
        assertEquals(null, (folderOf("   ") as ResultOf2.Success).value.folder, "an empty folder means none")
        assertEquals("Docker Hosts", (folderOf("  Docker Hosts ") as ResultOf2.Success).value.folder)
        assertEquals("Überwachung_2.x-neu", (folderOf("Überwachung_2.x-neu") as ResultOf2.Success).value.folder)
        assertEquals(null, (parseSnippet(form("name" to "ps", "command" to "docker ps"), "id") as ResultOf2.Success).value.folder)
        listOf("a/b", "<b>", "x".repeat(33)).forEach { bad ->
            assertTrue((folderOf(bad) as ResultOf2.Failure).value.startsWith("Folder may only contain"), bad)
        }
    }

    @Test
    fun `folders that only differ in case stay two folders and everything is sorted ignoring case`() {
        val snippets = listOf(
            Snippet("1", "logs", "docker logs", "docker"),
            Snippet("2", "ps", "docker ps", "Docker"),
            Snippet("3", "b", "b", null),
            Snippet("4", "A", "a", null),
            Snippet("5", "images", "docker images", "Docker"),
            Snippet("6", "df", "df -h", "Alpha"),
        )
        val groups = groupSnippets(snippets)
        assertEquals(listOf("A", "b"), groups.loose.map { it.name })
        assertEquals(setOf("docker", "Docker"), groups.folders.map { it.first }.drop(1).toSet(), "no folder may get lost")
        assertEquals("Alpha", groups.folders.first().first)
        assertEquals(listOf("images", "ps"), groups.folders.first { it.first == "Docker" }.second.map { it.name })
        assertEquals(6, groups.loose.size + groups.folders.sumOf { it.second.size })
    }

    @Test
    fun `adding a snippet with a folder stores it, audits folder and name, and a bad folder keeps the input`(): Unit = testApplication {
        val (client, cookie) = loggedIn()
        suspend fun add(name: String, folder: String) = client.submitForm("/snippets", parameters {
            append("name", name); append("command", "docker ps"); append("folder", folder); append("run", "on")
        }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }

        assertEquals(HttpStatusCode.Found, add("ps", "Docker").status)
        assertEquals("Docker", dirl.vault.content!!.snippets.single().folder)
        assertTrue(dirl.audit.tail().any { it.action == AuditAction.SNIPPET_ADDED && it.detail == "Docker/ps" })

        val refused = add("images", "Docker/Images")
        assertEquals(HttpStatusCode.BadRequest, refused.status)
        val page = refused.bodyAsText()
        assertTrue(page.contains("Folder may only contain") && page.contains("value=\"Docker/Images\"") && page.contains("value=\"images\""))
        assertEquals(1, dirl.vault.content!!.snippets.size)
        // The existing folder is offered in the form.
        assertTrue(page.contains("<datalist id=\"snippet-folders\"><option value=\"Docker\">"), "folder suggestions missing")
    }

    @Test
    fun `the snippets page folds folders, opens the one just changed and stays a plain list without folders`(): Unit = testApplication {
        val (client, cookie) = loggedIn()
        suspend fun page(query: String = "") = client.get("/snippets$query") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        fun folders(page: String) = Regex("<details class=\"snippet-folder\"( open=\"open\")?><summary><span class=\"snippet-folder-name\">([^<]+)</span><span class=\"muted\">(\\d+)</span>")
            .findAll(page).map { "${it.groupValues[2]} ${it.groupValues[3]}" + if (it.groupValues[1].isEmpty()) "" else " open" }.toList()

        dirl.vault.update { it.copy(snippets = listOf(Snippet("1", "df", "df -h"))) }
        val plain = page()
        assertTrue(plain.contains("<details").not() && plain.contains("class=\"snippet-row\""), "without folders the page stays a plain list")

        dirl.vault.update { it.copy(snippets = it.snippets + Snippet("2", "ps", "docker ps\n", "Docker") + Snippet("3", "logs", "docker logs -f\nmore", "Docker")) }
        assertEquals(listOf("No folder 1", "Docker 2"), folders(page()), "all folded, No folder first, with the number of snippets")
        assertEquals(listOf("No folder 1", "Docker 2 open"), folders(page("?done=snippet-saved&open=2")), "the folder of the saved snippet opens")
        assertEquals(listOf("No folder 1 open", "Docker 2"), folders(page("?open=1")))
        assertEquals(listOf("No folder 1", "Docker 2"), folders(page("?open=nope")), "an unknown snippet opens nothing")

        val rows = page()
        assertTrue(rows.contains("<span class=\"pill error\">runs immediately</span>") && rows.contains("<span class=\"pill\">asks first</span>"))
        assertTrue(rows.contains("title=\"docker logs -f\nmore\">docker logs -f …</div>"), "a command of several lines shows its first line, all of it as tooltip")

        // Adding and saving lead back with the folder open.
        val added = client.submitForm("/snippets", parameters { append("name", "top"); append("command", "htop"); append("folder", "Docker") }) {
            header(HttpHeaders.Cookie, cookie)
            header(HttpHeaders.Origin, "https://ssh.example.com")
        }
        val id = dirl.vault.content!!.snippets.first { it.name == "top" }.id
        assertEquals("/snippets?done=snippet-added&open=$id", added.headers[HttpHeaders.Location])
    }

    @Test
    fun `the import is a drop zone around the file input`(): Unit = testApplication {
        val (client, cookie) = loggedIn()
        val page = client.get("/snippets") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        val zone = page.substringAfter("<label class=\"drop-zone\" data-drop=\"\">").substringBefore("</label>")
        assertTrue(zone.contains("<input type=\"file\" name=\"file\" class=\"drop-input\" accept=\".json,application/json\""), zone)
        assertTrue(zone.contains("Drop a JSON file here") && zone.contains("choose one"))
    }

    @Test
    fun `the terminal bar shows a menu per folder outside the scrolling row`(): Unit = testApplication {
        val (client, cookie) = loggedIn()
        val key = generateEd25519Key("k")
        val host = Host(id = "h", name = "web", address = "127.0.0.1", port = 1, username = "u", keyId = key.id)
        dirl.vault.update { it.copy(keys = listOf(key), hosts = listOf(host), snippets = listOf(Snippet("1", "df", "df -h\n"))) }
        suspend fun bar() = client.get("/hosts/h/terminal") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
            .substringAfter("<div class=\"term-bar\">").substringBefore("<div class=\"terminal\"")

        val plain = bar()
        assertTrue(plain.contains("<details").not(), "without folders the bar stays as it was")
        assertTrue(plain.contains("<div class=\"snippets\"><button type=\"button\" class=\"btn sm\" data-send=\"df -h"))

        dirl.vault.update { it.copy(snippets = it.snippets + Snippet("2", "ps", "docker ps\n", "Docker") + Snippet("3", "logs", "docker logs ", "docker")) }
        val withFolders = bar()
        val menus = Regex("<details class=\"menu\"><summary class=\"btn sm\">([^<]+)</summary>").findAll(withFolders).map { it.groupValues[1] }.toList()
        assertEquals(listOf("docker ▾", "Docker ▾"), menus.sortedBy { it != "docker ▾" }, "two folders, none lost")
        val snippetsRow = withFolders.substringAfter("<div class=\"snippets\">").substringBefore("</div>")
        assertTrue(snippetsRow.contains("df -h") && snippetsRow.contains("docker").not(), "only snippets without folder in the scrolling row")
        assertTrue(withFolders.indexOf("<details") < withFolders.indexOf("<div class=\"snippets\">"), "menus come before the row, not inside it")
    }

    @Test
    fun `the terminal page offers the actions mode with Enter, Cancel and every snippet in a panel`(): Unit = testApplication {
        val (client, cookie) = loggedIn()
        val key = generateEd25519Key("k")
        val host = Host(id = "h", name = "web", address = "127.0.0.1", port = 1, username = "u", keyId = key.id)
        val snippets = listOf(Snippet("1", "df", "df -h\n"), Snippet("2", "ps", "docker ps\n", "Docker"), Snippet("3", "logs", "docker logs ", "Docker"))
        dirl.vault.update { it.copy(keys = listOf(key), hosts = listOf(host), snippets = snippets) }
        val page = client.get("/hosts/h/terminal") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()

        val bar = page.substringAfter("<div class=\"term-bar\">").substringBefore("<div class=\"terminal\"")
        assertTrue(bar.contains("<button type=\"button\" class=\"btn sm primary\" id=\"mode\""), "the mode toggle sits in the bar")
        assertTrue(bar.indexOf("id=\"mode\"") < bar.indexOf("Files"), "before Files and Details")

        val actionBar = page.substringAfter("<div class=\"actionbar\">").substringBefore("</div>")
        assertEquals(listOf("\r", "\u0003"), Regex("data-send=\"([^\"]*)\"").findAll(actionBar).map { it.groupValues[1] }.toList(), "Enter and Ctrl+C")
        assertTrue(actionBar.contains(">Enter") && actionBar.contains(">Cancel"))

        val panel = page.substringAfter("<div class=\"snippet-panel\">").substringBefore("<div class=\"keybar\">")
        assertTrue(page.indexOf("<div class=\"actionbar\">") < page.indexOf("<div class=\"snippet-panel\">"), "the panel follows the action bar")
        assertTrue(Regex("<details class=\"panel-folder\"><summary>Docker<span class=\"muted\">2</span></summary>").containsMatchIn(panel), panel)
        snippets.forEach { s ->
            assertTrue(panel.contains("data-send=\"${s.command}\""), "${s.name} in the panel")
            assertEquals(2, Regex(Regex.escape("data-send=\"${s.command}\"")).findAll(page).count(), "${s.name} in the bar and in the panel")
        }
    }
}
