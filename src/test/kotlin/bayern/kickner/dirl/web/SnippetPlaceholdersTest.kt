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
        assertEquals(listOf("container=null", "1st=null", "a_b-2=null"), names("{{container}} {{1st}} {{a_b-2}}"), "lower case and digits anywhere")
        assertEquals(listOf("Name=null", "name=null"), names("{{Name}} {{name}}"), "names are case sensitive")
        assertEquals(emptyList(), names("no placeholder here"))
    }

    @Test
    fun `the default is everything after the colon up to the closing braces`() {
        assertEquals(listOf("A="), names("{{A:}}"), "an empty default is a default")
        assertEquals(listOf("B=v a/l:ue"), names("{{B:v a/l:ue}}"), "spaces, slashes and more colons")
        assertEquals(listOf("Path=\${HOME}/logs"), names("tail {{Path:\${HOME}/logs}}"), "braces of the shell")
        assertEquals(listOf("C=a{b"), names("{{C:a{b}}}"), "the first closing pair ends it, a third brace stays text")
        assertEquals(listOf("D=x}y"), names("{{D:x}y}}"), "a single closing brace is part of the default")
        assertEquals(emptyList(), names("echo {{E:line\nbreak}}"), "no line breaks")
    }

    @Test
    fun `templates with a dot or a space stay as they are, bare words count`() {
        listOf(
            "docker ps --format '{{.Names}}'",
            "docker inspect -f '{{ .State.Status }}' web",
            "docker inspect -f '{{json .Config}}' web",
            "helm template {{ .Release.Name }} {{- if .Values.x }}",
            "echo {{ Name }} {{Name }} {Name} {{{Name}",
            "echo {{${"x".repeat(33)}}}",
            "echo {{a.b}} {{a b}} {{ä}}",
        ).forEach { assertEquals(emptyList(), names(it), it) }
        // Known and accepted: a bare keyword of a Go template is a variable, the pill on the snippets page names it.
        assertEquals(listOf("else=null", "end=null"), names("docker ps --format '{{if .Ports}}{{.Ports}}{{else}}none{{end}}'"))
        assertEquals(listOf("Format=null"), names("docker ps --format '{{.Names}}' {{Format}}"))
    }

    @Test
    fun `the marks of the preview have no rules of their own outside the preview`() {
        // terminal.js marks values with these classes. A page wide rule for one of them, like the padding of .empty,
        // would bend the preview.
        val css = javaClass.getResource("/static/app.css")!!.readText().replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        val selectors = Regex("([^{}]+)\\{[^{}]*\\}").findAll(css).flatMap { it.groupValues[1].split(',') }.map { it.trim() }
        selectors.filter { Regex("(^|\\s)\\.(var|missing|active)\\b").containsMatchIn(it) }
            .forEach { assertTrue(it.startsWith(".snippet-ask-preview "), "a rule for a mark outside the preview: $it") }
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
        val hello = Snippet("3", "Hello", "echo {{Name}}\n", null)
        val free = Snippet("4", "Free", "free -h", null)
        dirl.vault.update {
            it.copy(keys = listOf(key), hosts = listOf(Host(id = "h", name = "web", address = "127.0.0.1", port = 1, username = "u", keyId = key.id)), snippets = listOf(logs, names, hello, free))
        }
        application { dirlModule(dirl) }
        val client = createClient { followRedirects = false }
        val cookie = "$SESSION_COOKIE=${dirl.sessions.create(actor).token}"

        val page = client.get("/snippets") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(page.contains("<span class=\"pill accent\">variables: Lines, Container</span>"), page)
        assertEquals(2, Regex("pill accent").findAll(page).count(), "Logs and Hello, a Go template asks for nothing")
        assertTrue(page.contains("Variables like {{Name}} or {{Name:default}} are asked for when the snippet is clicked"), "the form explains it")

        val terminal = client.get("/hosts/h/terminal") { header(HttpHeaders.Cookie, cookie) }.bodyAsText()
        assertTrue(terminal.contains("data-send=\"docker logs --tail {{Lines:100}} -f {{Container}}\""), "the browser fills the values, the page sends the command as stored")
        // A button with variables carries the braces, one that runs on the click the Enter symbol, both say it to
        // screen readers. Variables win: the form comes first, so a snippet that runs immediately is no warning then.
        fun button(name: String) = terminal.substringAfter("data-name=\"$name\"").substringBefore("</button>")
        val runMark = "<span class=\"snippet-run\" aria-hidden=\"true\">⏎</span><span class=\"sr-only\">, runs immediately</span>"
        val logsButton = button("Logs")
        assertTrue(logsButton.contains("<span class=\"snippet-var\" aria-hidden=\"true\">{ }</span>") && logsButton.contains("<span class=\"sr-only\">, asks for Lines, Container</span>"), logsButton)
        assertTrue(logsButton.contains("snippet-run").not(), logsButton)
        assertTrue(button("Names").contains(runMark) && button("Names").contains("snippet-var").not(), button("Names"))
        assertTrue(button("Hello").contains("snippet-var") && button("Hello").contains("snippet-run").not(), button("Hello"))
        assertTrue(button("Free").contains("snippet-").not() && button("Free").contains("sr-only").not(), button("Free"))
        assertTrue(terminal.contains("<script src=\"/static/terminal.js\">"))
    }
}
