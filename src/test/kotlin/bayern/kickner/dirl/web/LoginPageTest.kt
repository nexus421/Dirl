package bayern.kickner.dirl.web

import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import java.net.ServerSocket
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The login page: the scanning terminal, the sign in and how it reports an unreachable provider. */
class LoginPageTest {
    // A provider on a port nobody listens on, so starting a login fails right away.
    private val closedPort = ServerSocket(0).use { it.localPort }
    private val dataDir = Files.createTempDirectory("dirl-login-page").toFile()
    private val dirl = createDirl(
        AppConfig(
            publicUrl = "https://ssh.example.com",
            dataDir = dataDir.absolutePath,
            oidc = OidcConfig(issuer = "http://127.0.0.1:$closedPort", clientId = "dirl", clientSecret = "secret"),
        ),
        dataDir,
    )

    @Test
    fun `the login page shows the scan and one way to sign in, without app bar or inline script`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val response = createClient { followRedirects = false }.get("/login")
        assertEquals(HttpStatusCode.OK, response.status)
        val page = response.bodyAsText()

        // The logo is decoration for screen readers, the heading names the page instead.
        assertTrue(page.contains("<pre class=\"login-logo\" aria-hidden=\"true\">"), page)
        assertTrue(page.contains("|____/|_|_|  |_|"), "the logo arrives as text, escaped like everything else")
        assertTrue(page.contains("<h1 class=\"sr-only\">Dirl, web SSH for your servers</h1>"))
        listOf("terminal", "files", "status", "vault", "you").forEachIndexed { index, name ->
            assertTrue(page.contains("<div class=\"term-line term-found\" style=\"--i:$index\">") && page.contains("<span class=\"term-name\">$name</span>"), name)
        }
        assertTrue(page.contains("not signed in yet"))
        assertEquals(1, Regex("href=\"/auth/start\"").findAll(page).count(), "exactly one sign in")
        assertTrue(page.contains("class=\"btn primary block login-button\""))
        assertFalse(page.contains("class=\"appbar\"") || page.contains("data-presence"), "no app bar and no presence before the login")
        assertFalse(Regex("<script(?![^>]*src=)").containsMatchIn(page), "no inline script, the CSP forbids it")
        assertTrue(page.contains("<main class=\"split-wrap\">"))
    }

    @Test
    fun `the styles of the scan stay on the login and leave the terminal bar alone`() {
        val css = javaClass.getResource("/static/app.css")!!.readText().replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        // Selector lists of every rule, also inside @media.
        val rules = Regex("([^{}]+)\\{([^{}]*)\\}").findAll(css).map { it.groupValues[1].trim() to it.groupValues[2] }.toList()
        val scanClasses = listOf("term-line", "term-ok", "term-accent", "term-muted", "term-name", "term-type", "scan-bar", "term-scan", "term-found", "term-cursor")
        rules.forEach { (selectors, _) ->
            selectors.split(',').map { it.trim() }.forEach { selector ->
                scanClasses.filter { Regex("\\.$it\\b").containsMatchIn(selector) }.forEach { cls ->
                    assertTrue(selector.startsWith(".login-term "), "$cls outside the login: $selector")
                }
            }
        }
        // The bar above the terminal: a flex row, never the width or the motion of the scan.
        val termBar = rules.filter { (selectors, _) -> selectors.split(',').any { it.trim() == ".term-bar" } }
        assertTrue(termBar.isNotEmpty())
        termBar.forEach { (_, body) -> assertFalse(body.contains("width") || body.contains("animation") || body.contains("inline-block"), body) }
    }

    @Test
    fun `an unreachable provider is reported on the login page itself`(): Unit = testApplication {
        application { dirlModule(dirl) }
        val response = createClient { followRedirects = false }.get("/auth/start")
        assertEquals(HttpStatusCode.ServiceUnavailable, response.status)
        val card = response.bodyAsText().substringAfter("<div class=\"login-card\">").substringBefore("</div></div></div>")
        assertTrue(card.contains("<div class=\"notice error\">The identity provider is not reachable. Try again in a moment.</div>"), card)
        assertTrue(card.contains("href=\"/auth/start\""), "trying again is one click")
    }
}
