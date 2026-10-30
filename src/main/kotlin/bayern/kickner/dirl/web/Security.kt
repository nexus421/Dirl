package bayern.kickner.dirl.web

import bayern.kickner.dirl.auth.Session
import bayern.kickner.dirl.vault.VaultState
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.util.AttributeKey
import java.net.URI

/** Name of the session cookie. The `__Host-` prefix makes the browser reject it unless Secure, host-only and `Path=/`. */
const val SESSION_COOKIE = "__Host-session"

/** Name of the short-lived cookie that ties the OIDC callback to the login attempt. */
const val LOGIN_COOKIE = "__Host-login"

/**
 * Content Security Policy for every response.
 *
 * `style-src 'unsafe-inline'` is required: xterm.js 6 creates `<style>` elements for its theme and cell metrics and
 * has no nonce support. `script-src` stays strict, no inline scripts and no `eval`. `manifest-src 'self'` lets the
 * browser read `/static/manifest.json`, which makes Dirl installable as an app.
 */
const val CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; " +
    "form-action 'self'"

/**
 * Paths reachable without a session, matched exactly. Everything else requires a login, so a new route is protected
 * by default, also one that only starts like a public path (`/login-history`, `/auth/tokens`).
 */
private val publicPaths = setOf("/login", "/auth/start", "/auth/callback", "/healthz")

/** The only public prefix: the static files (styles, scripts, icons) the login page needs. */
private const val STATIC_PREFIX = "/static/"

/** Paths reachable with a session while the vault is not unlocked. */
private val sealedAllowed = setOf("/unlock", "/setup", "/setup/restore", "/logout")

/**
 * Query parameter of automatic page reloads (the host overview reloads itself every minute). Such a request does
 * not count as activity, otherwise an unattended browser with the overview open would never reach the idle timeout.
 */
const val AUTO_REFRESH_PARAM = "autorefresh"

/**
 * Path of the presence WebSocket that every page opens (see [presenceRoutes]). Opening it does not count as activity
 * either, every automatic reload of the overview opens a new one.
 */
const val PRESENCE_PATH = "/ws/presence"

/** Key of the [Session] in the call attributes, set by [installGuards] for every protected path. */
val SessionKey = AttributeKey<Session>("dirl.session")

/** The session of the current call. Only valid on protected paths, where [installGuards] guarantees it. */
val ApplicationCall.session: Session get() = attributes[SessionKey]

/**
 * Installs the security checks that run before routing, for every request:
 *
 * 1. Security headers (CSP, `nosniff`, referrer only same-origin, no caching, cross-origin isolation, HSTS behind
 *    https).
 * 2. Origin check: state-changing requests and WebSocket upgrades must come from [Dirl.publicOrigin]. Ktor does not
 *    check the `Origin` of WebSockets itself, and together with `SameSite=Strict` this is the CSRF protection.
 * 3. Login check: no valid session, or a user no longer allowed by [bayern.kickner.dirl.auth.AccessControl], leads to
 *    `/login` (pages) or 401 (everything else). Automatic reloads ([AUTO_REFRESH_PARAM]) and the presence WebSocket
 *    ([PRESENCE_PATH]) only check the session, every other request also counts as activity for the idle timeout.
 * 4. Vault check: while the vault is not unlocked only the unlock and setup pages work.
 * 5. Presence: every request that passed the checks counts as somebody using Dirl until it is done, a WebSocket until
 *    it is closed, see [bayern.kickner.dirl.ssh.Presence]. Public paths and rejected requests do not count.
 */
fun Application.installGuards(dirl: Dirl) {
    intercept(ApplicationCallPipeline.Plugins) {
        val headers = call.response.headers
        headers.append("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        headers.append("X-Content-Type-Options", "nosniff")
        // Not no-referrer: with it, browsers send "Origin: null" on form posts and the origin check below rejects them.
        headers.append("Referrer-Policy", "same-origin")
        headers.append("X-Frame-Options", "DENY")
        headers.append(HttpHeaders.CacheControl, "no-store")
        headers.append("Cross-Origin-Opener-Policy", "same-origin")
        headers.append("Cross-Origin-Resource-Policy", "same-origin")
        headers.append("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
        if (dirl.config.publicUrl.startsWith("https://")) headers.append("Strict-Transport-Security", "max-age=31536000")

        val path = call.request.path()
        val isWebSocket = call.request.headers[HttpHeaders.Upgrade].equals("websocket", ignoreCase = true)
        val needsOrigin = isWebSocket || call.request.httpMethod !in setOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options)
        val originOk = call.request.headers[HttpHeaders.Origin] == dirl.publicOrigin
        if (needsOrigin && originOk.not()) {
            call.respond(HttpStatusCode.Forbidden, "Origin not allowed")
            return@intercept finish()
        }

        if (path in publicPaths || path.startsWith(STATIC_PREFIX)) return@intercept

        val token = call.request.cookies[SESSION_COOKIE]
        val automatic = call.request.queryParameters[AUTO_REFRESH_PARAM] != null || path == PRESENCE_PATH
        val valid = if (automatic) dirl.sessions.peek(token) else dirl.sessions.get(token)
        val session = valid?.takeIf { dirl.access.isAllowed(it.actor.sub) }
        if (session == null) {
            // A session of a user whose access was removed ends here.
            dirl.sessions.remove(token)
            if (call.request.httpMethod == HttpMethod.Get && isWebSocket.not()) call.respondRedirect("/login")
            else call.respond(HttpStatusCode.Unauthorized, "Not logged in")
            return@intercept finish()
        }
        call.attributes.put(SessionKey, session)

        val unlocked = dirl.vault.state is VaultState.Unlocked
        if (unlocked.not() && path !in sealedAllowed) {
            if (call.request.httpMethod == HttpMethod.Get && isWebSocket.not()) call.respondRedirect("/unlock")
            else call.respond(HttpStatusCode.Locked, "Vault is sealed")
            return@intercept finish()
        }

        dirl.presence.hold { proceed() }
    }
}

/** Origin (`scheme://host[:port]`) of a URL, the form browsers send in the `Origin` header. */
fun originOf(url: String): String {
    val uri = URI(url)
    return "${uri.scheme}://${uri.rawAuthority}"
}

/** A cookie with the attributes Dirl uses everywhere: Secure, HttpOnly, `Path=/`, no domain. */
fun secureCookie(name: String, value: String, maxAgeSeconds: Int, sameSite: String): Cookie = Cookie(
    name = name,
    value = value,
    maxAge = maxAgeSeconds,
    path = "/",
    secure = true,
    httpOnly = true,
    extensions = mapOf("SameSite" to sameSite),
)
