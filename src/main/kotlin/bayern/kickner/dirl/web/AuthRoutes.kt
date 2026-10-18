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
import kotlinx.html.p
import kotlinx.html.span
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

private suspend fun ApplicationCall.loginPage(error: String?, status: HttpStatusCode) =
    page("Sign in", null, frame = PageFrame.CENTER, status = status) {
        centerCard {
            if (error != null) notice("error", error)
            p("muted") { +"Web SSH for your servers. Sign in with your identity provider to continue." }
            linkButton("/auth/start", "Sign in", "primary block")
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
