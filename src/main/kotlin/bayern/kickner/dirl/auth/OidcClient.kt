package bayern.kickner.dirl.auth

import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.config.isLoopback
import bayern.kickner.dirl.randomToken
import bayern.kickner.dirl.toBase64Url
import bayern.kickner.klogger.infoLog
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotnexlib.ResultOf2
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.minutes

/**
 * The parts of the provider's discovery document (`/.well-known/openid-configuration`) Dirl needs.
 *
 * @property issuer Must equal the configured issuer exactly.
 * @property authorizationEndpoint Where the browser is sent to log in.
 * @property tokenEndpoint Where the authorization code is exchanged, server to server.
 */
@Serializable
data class ProviderMetadata(
    val issuer: String,
    @SerialName("authorization_endpoint") val authorizationEndpoint: String,
    @SerialName("token_endpoint") val tokenEndpoint: String,
)

/**
 * A login in progress, between the redirect to the provider and the callback. Kept on the server, the browser only
 * holds a random ID in a short-lived cookie, so none of the values can be tampered with.
 *
 * @property state Echoed back by the provider, binds the callback to this browser.
 * @property nonce Ends up in the ID token, binds the token to this login.
 * @property codeVerifier PKCE secret, only its SHA-256 hash went to the provider.
 * @property createdAt Unix milliseconds, attempts expire after [OidcClient.ATTEMPT_TTL].
 */
class LoginAttempt(val state: String, val nonce: String, val codeVerifier: String, val createdAt: Long)

/**
 * Result of [OidcClient.startLogin].
 *
 * @property attemptId Value for the short-lived login cookie.
 * @property redirectUrl The provider's authorization URL to redirect the browser to.
 */
data class LoginStart(val attemptId: String, val redirectUrl: String)

/** Why a login failed. Shown to the user only in general terms, the detail goes to the log. */
sealed interface LoginError {
    /** The provider could not be reached or returned something unusable. @property reason For the log. */
    data class ProviderUnavailable(val reason: String) : LoginError

    /** Callback without a matching login attempt (expired, cookie missing, replayed). */
    data object UnknownAttempt : LoginError

    /** The `state` parameter does not match: a forged or mixed-up callback. */
    data object StateMismatch : LoginError

    /** The provider reported an error, e.g. the user is not in the allowed group. @property description From the provider. */
    data class Denied(val description: String) : LoginError

    /** The code exchange or the ID token validation failed. @property reason For the log. */
    data class InvalidToken(val reason: String) : LoginError
}

/**
 * OpenID Connect Authorization Code Flow with PKCE (S256) against Pocket ID, without an OIDC or JWT library.
 *
 * HTTP goes through the JDK's [HttpClient]. All calls are blocking and must run off the request thread.
 *
 * @property config The `oidc` section of the config.
 * @property redirectUri `publicUrl + "/auth/callback"`, registered as callback URL in the provider.
 * @property http HTTP client for discovery and token exchange.
 * @property clock Unix milliseconds, injectable for tests.
 */
class OidcClient(
    private val config: OidcConfig,
    private val redirectUri: String,
    private val http: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val attempts = ConcurrentHashMap<String, LoginAttempt>()

    @Volatile
    private var metadata: ProviderMetadata? = null

    /** Creates a login attempt and the provider URL to send the browser to. */
    fun startLogin(): ResultOf2<LoginStart, LoginError> {
        purgeExpired()
        // Unauthenticated callers can start logins, so the map is capped to keep memory bounded.
        if (attempts.size >= MAX_PENDING_ATTEMPTS) return ResultOf2.Failure(LoginError.ProviderUnavailable("Too many pending logins"))

        val provider = providerMetadata().getOrElse { return ResultOf2.Failure(LoginError.ProviderUnavailable(it.message ?: it.toString())) }
        val attempt = LoginAttempt(randomToken(), randomToken(), randomToken(), clock())
        val attemptId = randomToken()
        attempts[attemptId] = attempt

        val params = buildMap {
            put("response_type", "code")
            put("client_id", config.clientId)
            put("redirect_uri", redirectUri)
            put("scope", config.scopes.joinToString(" "))
            put("state", attempt.state)
            put("nonce", attempt.nonce)
            put("code_challenge", pkceChallenge(attempt.codeVerifier))
            put("code_challenge_method", "S256")
            if (config.forceReauth) put("prompt", "login")
        }
        return ResultOf2.Success(LoginStart(attemptId, provider.authorizationEndpoint + "?" + formEncode(params)))
    }

    /**
     * Completes the login from the callback parameters. The attempt is consumed in any case, a callback URL can
     * never be used twice.
     *
     * @param attemptId Value of the login cookie, `null` if the browser did not send it.
     * @param state, code, error, errorDescription Query parameters of the callback.
     */
    fun finishLogin(
        attemptId: String?,
        state: String?,
        code: String?,
        error: String?,
        errorDescription: String?,
    ): ResultOf2<IdTokenClaims, LoginError> {
        val attempt = attemptId?.let { attempts.remove(it) } ?: return ResultOf2.Failure(LoginError.UnknownAttempt)
        val expired = clock() - attempt.createdAt > ATTEMPT_TTL.inWholeMilliseconds
        if (expired) return ResultOf2.Failure(LoginError.UnknownAttempt)
        if (state == null || constantTimeEquals(state, attempt.state).not()) return ResultOf2.Failure(LoginError.StateMismatch)
        if (error != null) return ResultOf2.Failure(LoginError.Denied(errorDescription ?: error))
        if (code.isNullOrBlank()) return ResultOf2.Failure(LoginError.InvalidToken("Callback without code"))

        val provider = providerMetadata().getOrElse { return ResultOf2.Failure(LoginError.ProviderUnavailable(it.message ?: it.toString())) }
        val idToken = exchangeCode(provider, code, attempt.codeVerifier).getOrElse {
            return ResultOf2.Failure(LoginError.InvalidToken(it.message ?: it.toString()))
        }
        return when (val result = validateIdToken(idToken, config.issuer, config.clientId, attempt.nonce, clock() / 1000)) {
            is ResultOf2.Success -> result
            is ResultOf2.Failure -> ResultOf2.Failure(LoginError.InvalidToken(result.value))
        }
    }

    /** Fetches and caches the discovery document. A failed fetch is retried on the next login. */
    private fun providerMetadata(): Result<ProviderMetadata> = metadata?.let { Result.success(it) } ?: runCatching {
        val request = HttpRequest.newBuilder(URI("${config.issuer}/.well-known/openid-configuration"))
            .timeout(Duration.ofSeconds(10)).GET().build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        check(response.statusCode() == 200) { "Discovery returned HTTP ${response.statusCode()}" }

        val parsed = json.decodeFromString(ProviderMetadata.serializer(), response.body())
        check(parsed.issuer == config.issuer) { "Discovery issuer \"${parsed.issuer}\" differs from the configured issuer" }
        check(isSecureEndpoint(parsed.tokenEndpoint)) { "Token endpoint must use https" }
        check(isSecureEndpoint(parsed.authorizationEndpoint)) { "Authorization endpoint must use https" }
        infoLog { "Loaded OIDC discovery document of ${parsed.issuer}" }
        parsed.also { metadata = it }
    }

    /** Exchanges the code for tokens and returns the raw ID token. */
    private fun exchangeCode(provider: ProviderMetadata, code: String, codeVerifier: String): Result<String> = runCatching {
        val form = formEncode(
            mapOf(
                "grant_type" to "authorization_code",
                "code" to code,
                "redirect_uri" to redirectUri,
                "client_id" to config.clientId,
                "code_verifier" to codeVerifier,
            )
        )
        val request = HttpRequest.newBuilder(URI(provider.tokenEndpoint))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .apply { config.clientSecret?.let { header("Authorization", basicAuth(config.clientId, it)) } }
            .POST(HttpRequest.BodyPublishers.ofString(form))
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        check(response.statusCode() == 200) { "Token endpoint returned HTTP ${response.statusCode()}" }

        val body = json.decodeFromString(TokenResponse.serializer(), response.body())
        body.idToken ?: error("Token response contains no id_token")
    }

    private fun purgeExpired() {
        val oldest = clock() - ATTEMPT_TTL.inWholeMilliseconds
        attempts.entries.removeIf { it.value.createdAt < oldest }
    }

    private fun isSecureEndpoint(url: String): Boolean {
        val uri = runCatching { URI(url) }.getOrNull() ?: return false
        return uri.scheme == "https" || (uri.scheme == "http" && uri.host != null && isLoopback(uri.host))
    }

    @Serializable
    private data class TokenResponse(@SerialName("id_token") val idToken: String? = null)

    companion object {
        /** How long a login may take between redirect and callback. */
        val ATTEMPT_TTL = 10.minutes

        /** Upper bound of logins in progress. */
        const val MAX_PENDING_ATTEMPTS = 1000
    }
}

/** PKCE S256 challenge: Base64url of the SHA-256 of the verifier (RFC 7636). */
fun pkceChallenge(verifier: String): String =
    MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)).toBase64Url()

/** `application/x-www-form-urlencoded` encoding of [params]. */
fun formEncode(params: Map<String, String>): String =
    params.entries.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}" }

/** HTTP Basic credentials for `client_secret_basic`, both parts form-encoded first as RFC 6749 section 2.3.1 requires. */
private fun basicAuth(user: String, password: String): String {
    val raw = "${URLEncoder.encode(user, Charsets.UTF_8)}:${URLEncoder.encode(password, Charsets.UTF_8)}"
    return "Basic " + Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
}
