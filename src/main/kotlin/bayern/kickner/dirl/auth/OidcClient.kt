package bayern.kickner.dirl.auth

import bayern.kickner.dirl.cleanText
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.config.isLoopback
import bayern.kickner.dirl.randomToken
import bayern.kickner.dirl.secureRandom
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
import java.util.*
import java.util.concurrent.Semaphore
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

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
 * A login in progress, between the redirect to the provider and the callback. It travels in the short-lived login
 * cookie, signed with a per-process HMAC key (see [OidcClient.startLogin]), so the server keeps no state for logins
 * that were started but never finished.
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
 * @property cookie Value for the short-lived login cookie: the signed [LoginAttempt].
 * @property redirectUrl The provider's authorization URL to redirect the browser to.
 */
data class LoginStart(val cookie: String, val redirectUrl: String)

/** Why a login failed. Shown to the user only in general terms, the detail goes to the log. */
sealed interface LoginError {
    /**
     * The provider cannot answer right now: no connection, a timeout, an HTTP 5xx or 429, or all
     * [OidcClient.MAX_CONCURRENT_PROVIDER_CALLS] slots are taken. Trying again later can help. @property reason For the log.
     */
    data class ProviderUnavailable(val reason: String) : LoginError

    /**
     * The provider answers, but not in a way that fits the `oidc` settings: the discovery document is missing or
     * unreadable, names another issuer or an endpoint without https, or the token endpoint does not accept the client
     * ID and secret. Trying again does not help, the settings in Dirl or in the provider need a change.
     * @property reason For the log.
     */
    data class ProviderMisconfigured(val reason: String) : LoginError

    /** Callback without a valid login cookie (expired, missing, tampered with, or from before a restart). */
    data object UnknownAttempt : LoginError

    /** The `state` parameter does not match: a forged or mixed-up callback. */
    data object StateMismatch : LoginError

    /**
     * The provider reported an error, e.g. the user is not in the allowed group. @property description From the
     * callback URL, so cleaned with [cleanText] and at most [OidcClient.MAX_ERROR_LENGTH] characters.
     */
    data class Denied(val description: String) : LoginError

    /**
     * The provider refused the code (expired, already used, made up) or the ID token did not pass the validation.
     * @property reason For the log.
     */
    data class InvalidToken(val reason: String) : LoginError
}

/**
 * OpenID Connect Authorization Code Flow with PKCE (S256) against any provider with a discovery document, without an
 * OIDC or JWT library.
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

    /** Signs login cookies. New on every start, so a restart invalidates logins in progress, nothing else. */
    private val cookieKey = SecretKeySpec(ByteArray(32).also(secureRandom::nextBytes), "HmacSHA256")

    @Volatile
    private var metadata: ProviderMetadata? = null

    /** The last failed discovery fetch, repeated without a new fetch for [DISCOVERY_RETRY_AFTER]. */
    @Volatile
    private var discoveryFailure: DiscoveryFailure? = null

    /**
     * Limits blocking calls to the provider. Anonymous requests can trigger them (`/auth/start` before the discovery
     * is cached, `/auth/callback` with a signed cookie), and with a slow or unreachable provider each one holds an IO
     * thread for up to ten seconds. Without a limit that starves terminals and file transfers.
     */
    private val providerCalls = Semaphore(MAX_CONCURRENT_PROVIDER_CALLS)

    /**
     * Creates a login attempt and the provider URL to send the browser to.
     *
     * Anybody on the internet can call this, so it keeps no state on the server: the attempt goes into the signed
     * login cookie instead. Earlier versions kept attempts in a capped map, and a thousand anonymous requests locked
     * every user out of the login.
     *
     * An authorization endpoint may come with a query of its own, RFC 6749 section 3.1 requires keeping it, so the
     * parameters are then appended with `&`.
     */
    fun startLogin(): ResultOf2<LoginStart, LoginError> {
        val provider = when (val metadata = providerMetadata()) {
            is ResultOf2.Success -> metadata.value
            is ResultOf2.Failure -> return metadata
        }
        val attempt = LoginAttempt(randomToken(), randomToken(), randomToken(), clock())

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
        val separator = if ('?' in provider.authorizationEndpoint) "&" else "?"
        return ResultOf2.Success(LoginStart(signAttempt(attempt), provider.authorizationEndpoint + separator + formEncode(params)))
    }

    /**
     * Completes the login from the callback parameters. The route deletes the login cookie in any case, and the
     * provider accepts each code only once, so a callback URL cannot be used twice.
     *
     * @param cookie Value of the login cookie, `null` if the browser did not send it.
     * @param state, code, error, errorDescription Query parameters of the callback.
     */
    fun finishLogin(
        cookie: String?,
        state: String?,
        code: String?,
        error: String?,
        errorDescription: String?,
    ): ResultOf2<IdTokenClaims, LoginError> {
        val attempt = cookie?.let(::verifyAttempt) ?: return ResultOf2.Failure(LoginError.UnknownAttempt)
        val expired = clock() - attempt.createdAt > ATTEMPT_TTL.inWholeMilliseconds
        if (expired) return ResultOf2.Failure(LoginError.UnknownAttempt)
        if (state == null || constantTimeEquals(state, attempt.state).not()) return ResultOf2.Failure(LoginError.StateMismatch)
        // The callback URL is anybody's to write, a line break in the reason would forge a line in the log.
        if (error != null) return ResultOf2.Failure(LoginError.Denied(cleanText(errorDescription ?: error, MAX_ERROR_LENGTH) ?: "no reason given"))
        if (code.isNullOrBlank()) return ResultOf2.Failure(LoginError.InvalidToken("Callback without code"))

        val provider = when (val metadata = providerMetadata()) {
            is ResultOf2.Success -> metadata.value
            is ResultOf2.Failure -> return metadata
        }
        val idToken = when (val exchanged = exchangeCode(provider, code, attempt.codeVerifier)) {
            is ResultOf2.Success -> exchanged.value
            is ResultOf2.Failure -> return exchanged
        }
        return when (val result = validateIdToken(idToken, config.issuer, config.clientId, attempt.nonce, clock() / 1000)) {
            is ResultOf2.Success -> result
            is ResultOf2.Failure -> ResultOf2.Failure(LoginError.InvalidToken(result.value))
        }
    }

    /**
     * Fetches and caches the discovery document. After a failure no new fetch happens for [DISCOVERY_RETRY_AFTER], the
     * same failure is returned instead, so a flood of login attempts against an unreachable provider does not turn into
     * a flood of requests, and a wrong setting is not reported as an unreachable provider in the meantime.
     *
     * A trailing slash of the issuer (Authentik: `https://auth.example.com/application/o/dirl/`) is dropped before the
     * path is appended, as OpenID Connect Discovery 1.0 section 4 requires. The `iss` check still uses the issuer as
     * configured.
     */
    private fun providerMetadata(): ResultOf2<ProviderMetadata, LoginError> {
        metadata?.let { return ResultOf2.Success(it) }
        val failure = discoveryFailure
        if (failure != null && clock() - failure.at < DISCOVERY_RETRY_AFTER.inWholeMilliseconds) return ResultOf2.Failure(failure.repeated())
        val fetched = fetchMetadata()
        when (fetched) {
            is ResultOf2.Success -> {
                infoLog { "Loaded OIDC discovery document of ${fetched.value.issuer}" }
                metadata = fetched.value
            }

            is ResultOf2.Failure -> discoveryFailure = DiscoveryFailure(clock(), fetched.value)
        }
        return fetched
    }

    /** One fetch of the discovery document, see [providerMetadata]. */
    private fun fetchMetadata(): ResultOf2<ProviderMetadata, LoginError> {
        val request = runCatching {
            HttpRequest.newBuilder(URI("${config.issuer.removeSuffix("/")}/.well-known/openid-configuration"))
                .timeout(Duration.ofSeconds(10)).GET().build()
        }.getOrElse { return ResultOf2.Failure(LoginError.ProviderMisconfigured("Issuer is not a valid URL: ${it.message}")) }
        val response = runCatching { limited { http.send(request, HttpResponse.BodyHandlers.ofString()) } }
            .getOrElse { return ResultOf2.Failure(LoginError.ProviderUnavailable(it.message ?: it.toString())) }

        val status = response.statusCode()
        if (isTemporary(status)) return ResultOf2.Failure(LoginError.ProviderUnavailable("Discovery returned HTTP $status"))
        // A 404 or a redirect: the issuer does not point at the discovery document.
        if (status != 200) return ResultOf2.Failure(LoginError.ProviderMisconfigured("Discovery returned HTTP $status"))

        val parsed = runCatching { json.decodeFromString<ProviderMetadata>(response.body()) }
            .getOrElse { return ResultOf2.Failure(LoginError.ProviderMisconfigured("Discovery document is unreadable: ${it.message}")) }
        val mismatch = when {
            parsed.issuer != config.issuer -> "Discovery issuer \"${parsed.issuer}\" differs from the configured issuer"
            isSecureEndpoint(parsed.tokenEndpoint).not() -> "Token endpoint must use https"
            isSecureEndpoint(parsed.authorizationEndpoint).not() -> "Authorization endpoint must use https"
            else -> null
        }
        if (mismatch != null) return ResultOf2.Failure(LoginError.ProviderMisconfigured(mismatch))
        return ResultOf2.Success(parsed)
    }

    /**
     * Runs [call] if a provider slot is free right now, fails otherwise. Waiting for a slot would hold an IO thread per
     * waiting request, and a flood of anonymous callbacks would then starve the terminals.
     */
    private fun <T> limited(call: () -> T): T {
        check(providerCalls.tryAcquire()) { "Too many concurrent requests to the identity provider" }
        return try {
            call()
        } finally {
            providerCalls.release()
        }
    }

    /**
     * Exchanges the code for tokens and returns the raw ID token.
     *
     * The token endpoint answers `invalid_client` (RFC 6749 section 5.2, also with HTTP 401) when it does not accept the
     * client ID or secret, and `unauthorized_client` when the client may not use this grant: both are settings, not a
     * bad code. Every other refusal is [LoginError.InvalidToken].
     */
    private fun exchangeCode(provider: ProviderMetadata, code: String, codeVerifier: String): ResultOf2<String, LoginError> {
        val form = formEncode(
            mapOf(
                "grant_type" to "authorization_code",
                "code" to code,
                "redirect_uri" to redirectUri,
                "client_id" to config.clientId,
                "code_verifier" to codeVerifier,
            )
        )
        val response = runCatching {
            val request = HttpRequest.newBuilder(URI(provider.tokenEndpoint))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("Authorization", basicAuth(config.clientId, config.clientSecret))
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build()
            limited { http.send(request, HttpResponse.BodyHandlers.ofString()) }
        }.getOrElse { return ResultOf2.Failure(LoginError.ProviderUnavailable(it.message ?: it.toString())) }

        val status = response.statusCode()
        if (isTemporary(status)) return ResultOf2.Failure(LoginError.ProviderUnavailable("Token endpoint returned HTTP $status"))
        val body = runCatching { json.decodeFromString<TokenResponse>(response.body()) }.getOrNull()
        if (status != 200) {
            // The error code comes from the provider, cleaned like every other text from outside before it is logged.
            val error = body?.error?.let { cleanText(it, MAX_ERROR_LENGTH) }
            val reason = "Token endpoint returned HTTP $status" + (error?.let { " ($it)" } ?: "")
            val refusedClient = status == 401 || error == "invalid_client" || error == "unauthorized_client"
            return ResultOf2.Failure(if (refusedClient) LoginError.ProviderMisconfigured(reason) else LoginError.InvalidToken(reason))
        }
        if (body == null) return ResultOf2.Failure(LoginError.InvalidToken("Token response is unreadable"))
        return body.idToken?.let { ResultOf2.Success(it) } ?: ResultOf2.Failure(LoginError.InvalidToken("Token response contains no id_token"))
    }

    /** An answer that may be different in a moment: the provider is overloaded, restarting or failing. */
    private fun isTemporary(status: Int): Boolean = status >= 500 || status == 429

    /** `payload.signature`, both Base64url. The payload fields are Base64url tokens and a number, `|` never occurs in them. */
    private fun signAttempt(attempt: LoginAttempt): String {
        val payload = "${attempt.state}|${attempt.nonce}|${attempt.codeVerifier}|${attempt.createdAt}".toByteArray(Charsets.UTF_8)
        return payload.toBase64Url() + "." + hmac(payload).toBase64Url()
    }

    /** The attempt from a login cookie, or `null` if the signature does not match or the format is broken. */
    private fun verifyAttempt(cookie: String): LoginAttempt? = runCatching {
        val (payloadPart, signaturePart) = cookie.split('.').takeIf { it.size == 2 } ?: return null
        val payload = Base64.getUrlDecoder().decode(payloadPart)
        if (MessageDigest.isEqual(hmac(payload), Base64.getUrlDecoder().decode(signaturePart)).not()) return null
        val fields = payload.decodeToString().split('|')
        if (fields.size != 4) return null
        LoginAttempt(fields[0], fields[1], fields[2], fields[3].toLong())
    }.getOrNull()

    private fun hmac(data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").apply { init(cookieKey) }.doFinal(data)

    private fun isSecureEndpoint(url: String): Boolean {
        val uri = runCatching { URI(url) }.getOrNull() ?: return false
        return uri.scheme == "https" || (uri.scheme == "http" && uri.host != null && isLoopback(uri.host))
    }

    @Serializable
    private data class TokenResponse(@SerialName("id_token") val idToken: String? = null, val error: String? = null)

    /**
     * A failed discovery fetch.
     *
     * @property at Unix milliseconds of the fetch.
     * @property error What it returned, [repeated] until [DISCOVERY_RETRY_AFTER] has passed.
     */
    private class DiscoveryFailure(val at: Long, val error: LoginError) {
        /** The same failure, with a reason that says no new fetch happened. */
        fun repeated(): LoginError = when (error) {
            is LoginError.ProviderUnavailable -> error.copy(reason = "${error.reason} (failed recently, retrying later)")
            is LoginError.ProviderMisconfigured -> error.copy(reason = "${error.reason} (failed recently, retrying later)")
            else -> error
        }
    }

    companion object {
        /** How long a login may take between redirect and callback. */
        val ATTEMPT_TTL = 10.minutes

        /** Pause after a failed discovery fetch before the next one. */
        val DISCOVERY_RETRY_AFTER = 15.seconds

        /** Blocking calls to the provider at the same time, logins of a few people never need more. */
        const val MAX_CONCURRENT_PROVIDER_CALLS = 4

        /** Longest reason of a denied login that is shown and logged, longer ones are cut. */
        const val MAX_ERROR_LENGTH = 200
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
