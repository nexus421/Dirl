package bayern.kickner.dirl.auth

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.randomToken
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration

/**
 * A logged-in browser.
 *
 * @property token 256 bit random value, the content of the `__Host-session` cookie. Never shown in the UI.
 * @property id Separate random ID to show and revoke the session in the UI without exposing [token].
 * @property actor The user from the ID token.
 * @property userAgent The browser's `User-Agent` at login, only to recognize the session in the list.
 * @property createdAt Unix milliseconds of the login.
 * @property lastSeen Unix milliseconds of the latest request or terminal input.
 */
class Session(
    val token: String,
    val id: String,
    val actor: Actor,
    val userAgent: String,
    val createdAt: Long,
    @Volatile var lastSeen: Long,
)

/**
 * Sessions in memory. A restart logs everybody out, which is fine for a small team and avoids storing tokens.
 *
 * @property idleTimeout A session without requests for this long expires.
 * @property maxAge A session expires this long after the login, active or not.
 * @property clock Unix milliseconds, injectable for tests.
 */
class SessionStore(
    private val idleTimeout: Duration,
    private val maxAge: Duration,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val sessions = ConcurrentHashMap<String, Session>()

    /** Creates a session for [actor]. Expired sessions are purged on the way. */
    fun create(actor: Actor, userAgent: String = ""): Session {
        purgeExpired()
        val now = clock()
        return Session(randomToken(), randomToken(9), actor, userAgent.take(200), now, now).also { sessions[it.token] = it }
    }

    /** Returns the valid session for [token] and marks it as used, or `null` if unknown or expired. */
    fun get(token: String?): Session? {
        val session = peek(token) ?: return null
        session.lastSeen = clock()
        return session
    }

    /** Returns the valid session for [token] without marking it as used. */
    fun peek(token: String?): Session? {
        val session = token?.let { sessions[it] } ?: return null
        if (isExpired(session, clock())) {
            sessions.remove(session.token)
            return null
        }
        return session
    }

    /** All valid sessions, newest first. */
    fun list(): List<Session> {
        purgeExpired()
        return sessions.values.sortedByDescending { it.createdAt }
    }

    /** Ends the session for [token]. */
    fun remove(token: String?) {
        token?.let { sessions.remove(it) }
    }

    /** Ends the session with the display [id]. */
    fun removeById(id: String) {
        sessions.values.removeIf { it.id == id }
    }

    /** Ends every session of [sub], e.g. after access was revoked. */
    fun removeAllFor(sub: String) {
        sessions.values.removeIf { it.actor.sub == sub }
    }

    private fun purgeExpired() {
        val now = clock()
        sessions.values.removeIf { isExpired(it, now) }
    }

    private fun isExpired(session: Session, now: Long): Boolean =
        now - session.lastSeen > idleTimeout.inWholeMilliseconds || now - session.createdAt > maxAge.inWholeMilliseconds
}
