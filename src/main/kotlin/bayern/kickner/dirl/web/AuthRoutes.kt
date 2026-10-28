package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.auth.LoginError
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.html.a
import kotlinx.html.div
import kotlinx.html.h1
import kotlinx.html.h2
import kotlinx.html.p
import kotlinx.html.pre
import kotlinx.html.span
import kotlinx.html.style
import kotnexlib.ResultOf2
import kotlin.time.Duration.Companion.hours

private const val TAG = "AuthRoutes"

/**
 * Login and logout.
 *
 * - `GET /login` shows a plain link, not a form, because `form-action 'self'` in the CSP would block a form
 *   redirecting to the provider.
 * - `GET /auth/start` creates the login attempt and redirects to the provider.
 * - `GET /auth/callback` validates everything, checks [bayern.kickner.dirl.auth.AccessControl] and creates the
 *   session. A user who is not allowed yet shows up as access request under Settings.
 * - `POST /logout` ends the session.
 */
fun Route.authRoutes(dirl: Dirl) {
    get("/login") {
        val loggedIn = dirl.sessions.peek(call.request.cookies[SESSION_COOKIE])?.takeIf { dirl.access.isAllowed(it.actor.sub) }
        if (loggedIn != null) return@get call.respondRedirect("/")
        call.loginPage(null, HttpStatusCode.OK)
    }

    get("/auth/start") {
        when (val start = withContext(Dispatchers.IO) { dirl.oidc.startLogin() }) {
            is ResultOf2.Success -> {
                // Lax, so the cookie survives the top-level navigation back from the provider
                call.response.cookies.append(secureCookie(LOGIN_COOKIE, start.value.cookie, 600, "Lax"))
                call.respondRedirect(start.value.redirectUrl)
            }

            is ResultOf2.Failure -> {
                staticLog(KLogger.Level.ERROR, TAG) { "Cannot start login: ${start.value}" }
                call.loginPage("The identity provider is not reachable. Try again in a moment.", HttpStatusCode.ServiceUnavailable)
            }
        }
    }

    get("/auth/callback") {
        val q = call.request.queryParameters
        val loginCookie = call.request.cookies[LOGIN_COOKIE]
        call.response.cookies.append(secureCookie(LOGIN_COOKIE, "", 0, "Lax"))

        val result = withContext(Dispatchers.IO) {
            dirl.oidc.finishLogin(loginCookie, q["state"], q["code"], q["error"], q["error_description"])
        }
        val claims = when (result) {
            is ResultOf2.Success -> result.value
            is ResultOf2.Failure -> {
                staticLog(KLogger.Level.WARN, TAG) { "Login failed: ${result.value}" }
                return@get call.loginPage(loginErrorText(result.value), HttpStatusCode.Forbidden)
            }
        }

        val actor = Actor(claims.sub, claims.name)
        if (dirl.access.isAllowed(claims.sub).not()) {
            dirl.access.recordRequest(claims.sub, claims.name)
            dirl.audit.record(actor, AuditAction.LOGIN_REJECTED, detail = "not in the allowed users")
            staticLog(KLogger.Level.WARN, TAG) { "Rejected login of '${claims.name}' (${claims.sub}), listed as access request" }
            return@get call.page("Access requested", null, frame = PageFrame.CENTER, status = HttpStatusCode.Forbidden) {
                centerCard {
                    notice("info", "Hello ${claims.name}. Your login worked, but this account has no access to Dirl yet.")
                    p { +"Your request is listed under Settings. Once someone with access allows it, sign in again." }
                    linkButton("/login", "Back to sign in", "block")
                }
            }
        }

        val session = dirl.sessions.create(actor, call.request.headers[HttpHeaders.UserAgent].orEmpty())
        dirl.audit.record(actor, AuditAction.LOGIN)
        val maxAge = dirl.config.session.maxAgeHours.hours.inWholeSeconds.toInt()
        call.response.cookies.append(secureCookie(SESSION_COOKIE, session.token, maxAge, "Strict"))
        // A redirect would still belong to the cross-site navigation from the provider, and the browser would not
        // send the SameSite=Strict cookie with it. A same-site refresh from this page does send it.
        call.page("Signed in", null, frame = PageFrame.CENTER, refresh = "0; url=/") {
            centerCard {
                p { +"Signed in as ${claims.name}." }
                linkButton("/", "Continue", "primary block")
            }
        }
    }

    post("/logout") {
        val token = call.request.cookies[SESSION_COOKIE]
        dirl.sessions.peek(token)?.let { dirl.audit.record(it.actor, AuditAction.LOGOUT) }
        dirl.sessions.remove(token)
        call.response.cookies.append(secureCookie(SESSION_COOKIE, "", 0, "Strict"))
        call.respondRedirect("/login")
    }
}

/** The card of a [PageFrame.CENTER] page (login, unlock, setup). The page frame adds the brand above it. */
fun kotlinx.html.FlowContent.centerCard(content: kotlinx.html.DIV.() -> Unit) = card { content() }

/** `>_ Dirl` in the style of figlet's standard font, the logo of the login page. */
private val LOGIN_LOGO = listOf(
    "__             ____  _      _",
    "\\ \\           |  _ \\(_)_ __| |",
    " \\ \\          | | | | | '__| |",
    " / /  _____   | |_| | | |  | |",
    "/_/  |_____|  |____/|_|_|  |_|",
).joinToString("\n")

/** What the scan on the login page finds, name and a few words. */
private val LOGIN_FEATURES = listOf(
    "terminal" to "xterm, snippets, jump hosts",
    "files" to "SFTP up and down",
    "status" to "bars, warnings, round trip",
    "vault" to "sealed, AES-256-GCM",
)

/**
 * The login page: on the left a terminal that types `dirl scan` and finds, line by line, what Dirl does, on the right
 * the sign in. Every motion is CSS (`app.css`), runs once and stops with `prefers-reduced-motion`. On a phone the
 * sign in comes first.
 */
private suspend fun ApplicationCall.loginPage(error: String?, status: HttpStatusCode) =
    page("Sign in", null, frame = PageFrame.SPLIT, status = status) {
        div("login") {
            div("login-intro") {
                div("login-term") {
                    pre("login-logo") {
                        attributes["aria-hidden"] = "true"
                        +LOGIN_LOGO
                    }
                    h1("sr-only") { +"Dirl, web SSH for your servers" }
                    div("term-line") {
                        attributes["aria-hidden"] = "true"
                        span("term-ok") { +"$" }
                        +" "
                        span("term-type") { +"dirl scan" }
                    }
                    div("term-line term-scan") {
                        attributes["aria-hidden"] = "true"
                        span("term-muted") { +"[" }
                        span("term-bar") { +"#".repeat(24) }
                        span("term-muted") { +"]" }
                    }
                    LOGIN_FEATURES.forEachIndexed { index, (name, words) ->
                        div("term-line term-found") {
                            style = "--i:$index"
                            span("term-ok") { +"◆" }
                            span("term-name") { +name }
                            span("term-muted") { +words }
                        }
                    }
                    div("term-line term-found") {
                        style = "--i:${LOGIN_FEATURES.size}"
                        span("term-accent") { +"◆" }
                        span("term-name") { +"you" }
                        span("term-muted") { +"not signed in yet" }
                        span("term-cursor") { attributes["aria-hidden"] = "true" }
                    }
                }
            }
            div("login-panel") {
                div("login-card") {
                    h2 { +"Sign in" }
                    p("muted") { +"with your identity provider" }
                    if (error != null) notice("error", error)
                    linkButton("/auth/start", "Continue", "primary block login-button")
                }
            }
        }
    }

/** User-facing text for a failed login. Details stay in the log. */
private fun loginErrorText(error: LoginError): String = when (error) {
    is LoginError.Denied -> "The identity provider denied the login: ${error.description}"
    LoginError.UnknownAttempt -> "The login took too long or was started in another browser. Please start again."
    LoginError.StateMismatch -> "The login response did not belong to this browser. Please start again."
    is LoginError.ProviderUnavailable -> "The identity provider is not reachable."
    is LoginError.InvalidToken -> "The identity provider's answer could not be verified."
}
