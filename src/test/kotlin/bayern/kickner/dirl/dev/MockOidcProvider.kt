package bayern.kickner.dirl.dev

import bayern.kickner.dirl.auth.pkceChallenge
import bayern.kickner.dirl.randomToken
import bayern.kickner.dirl.toBase64Url
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * A user the mock provider can log in.
 *
 * @property sub Stable subject.
 * @property name Display name.
 */
data class MockUser(val sub: String, val name: String)

/**
 * A minimal OpenID Connect provider for tests and local development. Never part of the production JAR, it lives in
 * the test sources.
 *
 * It implements just enough of the protocol to exercise Dirl's client for real: discovery, an authorization page
 * that lets you pick a user (or logs in [autoLogin] right away), and a token endpoint that checks client ID, client
 * secret (HTTP Basic), redirect URI and the PKCE verifier before issuing an unsigned ID token with the requested nonce.
 *
 * @property clientSecret The secret the token endpoint expects from the client.
 * @property users Users offered on the authorization page.
 * @property autoLogin If set, `/authorize` redirects back immediately as this user, for automated tests.
 */
class MockOidcProvider(
    port: Int = 0,
    private val host: String = "localhost",
    val clientSecret: String = "mock-client-secret",
    val users: List<MockUser> = listOf(MockUser("dev-ada", "Ada Lovelace"), MockUser("dev-bob", "Bob Builder")),
    var autoLogin: MockUser? = null,
) : AutoCloseable {

    private data class PendingCode(val user: MockUser, val nonce: String, val challenge: String, val redirectUri: String, val clientId: String)

    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", port), 0)
    private val codes = ConcurrentHashMap<String, PendingCode>()

    /** Issuer URL, e.g. `http://localhost:18081`. */
    val issuer: String get() = "http://$host:${server.address.port}"

    init {
        server.createContext("/.well-known/openid-configuration") { ex ->
            val doc = buildJsonObject {
                put("issuer", issuer)
                put("authorization_endpoint", "$issuer/authorize")
                put("token_endpoint", "$issuer/token")
            }
            respond(ex, 200, "application/json", doc.toString())
        }
        server.createContext("/authorize") { ex -> authorize(ex) }
        server.createContext("/token") { ex -> token(ex) }
        server.start()
    }

    private fun authorize(ex: HttpExchange) {
        val q = parse(ex.requestURI.rawQuery.orEmpty())
        val redirectUri = q["redirect_uri"].orEmpty()
        val chosen = autoLogin ?: q["login_as"]?.let { sub -> users.firstOrNull { it.sub == sub } }
        if (chosen == null) {
            val links = users.joinToString("") { u ->
                "<li><a href=\"/authorize?${ex.requestURI.rawQuery}&login_as=${enc(u.sub)}\">Log in as ${u.name} (${u.sub})</a></li>"
            }
            respond(ex, 200, "text/html", "<!doctype html><title>Mock OIDC</title><h1>Mock OIDC provider</h1><ul>$links</ul>")
            return
        }
        val code = randomToken()
        codes[code] = PendingCode(chosen, q["nonce"].orEmpty(), q["code_challenge"].orEmpty(), redirectUri, q["client_id"].orEmpty())
        ex.responseHeaders.add("Location", "$redirectUri?code=${enc(code)}&state=${enc(q["state"].orEmpty())}")
        ex.sendResponseHeaders(302, -1)
        ex.close()
    }

    private fun token(ex: HttpExchange) {
        val form = parse(ex.requestBody.readBytes().decodeToString())
        val pending = codes.remove(form["code"].orEmpty())
        val valid = pending != null && pending.clientId == form["client_id"] && pending.redirectUri == form["redirect_uri"] &&
            pkceChallenge(form["code_verifier"].orEmpty()) == pending.challenge &&
            basicCredentials(ex) == (pending.clientId to clientSecret)
        if (valid.not()) return respond(ex, 400, "application/json", """{"error":"invalid_grant"}""")

        val now = System.currentTimeMillis() / 1000
        val payload = buildJsonObject {
            put("iss", issuer)
            put("aud", pending.clientId)
            put("sub", pending.user.sub)
            put("name", pending.user.name)
            put("nonce", pending.nonce)
            put("iat", now)
            put("exp", now + 300)
        }
        val idToken = """{"alg":"none"}""".toByteArray().toBase64Url() + "." + payload.toString().toByteArray().toBase64Url() + ".mock"
        respond(ex, 200, "application/json", """{"id_token":"$idToken","access_token":"mock","token_type":"Bearer"}""")
    }

    override fun close() = server.stop(0)

    private fun respond(ex: HttpExchange, status: Int, type: String, body: String) {
        val bytes = body.toByteArray()
        ex.responseHeaders.add("Content-Type", "$type; charset=utf-8")
        ex.sendResponseHeaders(status, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
    }

    private fun parse(query: String): Map<String, String> = query.split('&').filter { it.contains('=') }.associate {
        val (k, v) = it.split('=', limit = 2)
        URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
    }

    private fun enc(v: String) = URLEncoder.encode(v, Charsets.UTF_8)

    /** Client ID and secret from `Authorization: Basic`, form-urlencoded inside as RFC 6749 section 2.3.1 requires. */
    private fun basicCredentials(ex: HttpExchange): Pair<String, String>? = runCatching {
        val header = ex.requestHeaders.getFirst("Authorization").orEmpty()
        val (id, secret) = Base64.getDecoder().decode(header.removePrefix("Basic ")).decodeToString().split(':', limit = 2)
        URLDecoder.decode(id, Charsets.UTF_8) to URLDecoder.decode(secret, Charsets.UTF_8)
    }.getOrNull()
}
