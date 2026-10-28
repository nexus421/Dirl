package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import bayern.kickner.dirl.ssh.generateEd25519Key
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.Snippet
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.server.testing.testApplication
import kotnexlib.ResultOf2
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Placeholders in snippets: what counts as one, the limits, and where they show. */
class SnippetPlaceholdersTest {
    private fun names(command: String) = placeholdersOf(command).map { "${it.name}=${it.default}" }

    @Test
    fun `placeholders are found once each, in order, with the first default`() {
        assertEquals(listOf("Lines=100", "Container=null"), names("docker logs --tail {{Lines:100}} -f {{Container}}"))
        assertEquals(listOf("Name=World"), names("echo {{Name}} {{Name:World}} {{Name:Other}}"), "a later default fills a missing one, the first default wins")
        assertEquals(listOf("A=", "B_2-x=v a/l:ue"), names("{{A:}} {{B_2-x:v a/l:ue}}"), "an empty default is a default, a default may hold spaces, slashes and colons")
        assertEquals(emptyList(), names("no placeholder here"))
    }

    @Test
    fun `templates of docker and kubectl and other braces stay as they are`() {
        listOf(
            "docker ps --format '{{.Names}}'",
            "docker inspect -f '{{ .State.Status }}' web",
            "docker inspect -f '{{json .Config}}' web",
            "kubectl get pods -o go-template='{{range .items}}{{.metadata.name}}{{end}}'",
            "echo {{1st}} {{ Name }} {{Name }} {Name} {{{Name}",
            "helm template {{ .Release.Name }} {{- if .Values.x }}{{ else }}{{ end }}",
            "echo {{end}} {{else}} {{container}} {{name:default}}",
            "echo {{Name:a{b}}}",
            "echo {{Name:line\nbreak}}",
            "echo {{${"x".repeat(33)}}}",
        ).forEach { assertEquals(emptyList(), names(it), it) }
        // Mixed: only the real placeholder counts.
        assertEquals(listOf("Format=null"), names("docker ps --format '{{.Names}}' {{Format}}"))
    }

    @Test
    fun `a snippet may ask for at most ten different values`() {
        fun command(count: Int) = (1..count).joinToString(" ") { "{{V$it}}" } + " {{V1}}"
        assertNull(snippetProblem("ten", command(10), null))
        assertEquals("At most 10 different placeholders like {{Name}} per snippet.", snippetProblem("eleven", command(11), null))
        // An import checks the same.
        val file = """[{"name": "eleven", "command": "${command(11)}"}]"""
        assertTrue(assertIs<ResultOf2.Failure<List<String>>>(parseSnippetFile(file)).value.single().contains("at most 10 different placeholders"))
    }

    @Test
    fun `the snippets page names the values, the terminal gets the command unchanged`(): Unit = testApplication {
        val dataDir = Files.createTempDirectory("dirl-placeholders").toFile()
        val dirl = createDirl(
            AppConfig(
                publicUrl = "https://ssh.example.com",
                dataDir = dataDir.absolutePath,
                oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret"),
            ),
            dataDir,
        )
        val actor = Actor("user-1", "Ada")
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), actor)
        val key = generateEd25519Key("k")
        val logs = Snippet("1", "Logs", "docker logs --tail {{Lines:100}} -f {{Container}}", null)
        val names = Snippet("2", "Names", "docker ps --format '{{.Names}}'\n", null)
        dirl.vault.update {
            it.copy(keys = listOf(key), hosts = listOf(Host(id = "h", name = "web", address = "127.0.0.1", port = 1, username = "u", keyId = key.id)), snippets = listOf(logs, names))
        }
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"

        val page = client.get("/snippets") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(page.contains("<span class=\"snippet-asks\">asks for Lines, Container</span>"), page)
        assertEquals(1, Regex("snippet-asks").findAll(page).count(), "a Go template asks for nothing")
        assertTrue(page.contains("{{Name}} or {{Name:default}}, starting with a capital letter, is asked for when the snippet is clicked"), "the form explains it")

        val terminal = client.get("/hosts/h/terminal") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(terminal.contains("data-send=\"docker logs --tail {{Lines:100}} -f {{Container}}\""), "the browser fills the values, the page sends the command as stored")
        assertTrue(terminal.contains("<script src=\"/static/terminal.js\">"))
    }
}
