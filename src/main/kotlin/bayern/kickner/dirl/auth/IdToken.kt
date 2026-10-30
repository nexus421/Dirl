package bayern.kickner.dirl.auth

import bayern.kickner.dirl.cleanText
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotnexlib.ResultOf2
import java.security.MessageDigest
import java.util.Base64

/**
 * The claims Dirl uses from a validated ID token.
 *
 * @property sub Stable user ID at the provider, checked against `oidc.allowedSubjects`.
 * @property name Display name (`name`, falling back to `preferred_username`, then `sub`), cleaned with [cleanText].
 */
data class IdTokenClaims(val sub: String, val name: String)

/**
 * Longest display name Dirl keeps. Users choose their name at the provider, so it is cut and stripped of control and
 * formatting characters before it reaches pages, the audit log and the app log.
 */
const val MAX_NAME_LENGTH = 80

/**
 * Validates an ID token received directly from the token endpoint.
 *
 * The signature is deliberately not checked. OpenID Connect Core 1.0 section 3.1.3.7 allows the TLS server
 * validation of the token endpoint to replace the signature check when the token comes straight from that endpoint,
 * which is the only way Dirl ever receives one. That saves a JWT library and a JWKS cache. Everything else is
 * checked: `iss` byte for byte, `aud` contains the client ID (and `azp` matches if there are several audiences),
 * `exp` in the future, `iat` not in the future, `nonce` equal to the one sent with the authorization request.
 *
 * @param idToken The compact JWT.
 * @param issuer Expected `iss`.
 * @param clientId Expected audience.
 * @param nonce The nonce of this login attempt.
 * @param nowSeconds Current Unix time in seconds.
 * @param leewaySeconds Tolerated clock skew between Dirl and the provider.
 * @return the claims, or a reason for the log (never shown with token contents).
 */
fun validateIdToken(
    idToken: String,
    issuer: String,
    clientId: String,
    nonce: String,
    nowSeconds: Long,
    leewaySeconds: Long = 60,
): ResultOf2<IdTokenClaims, String> {
    val parts = idToken.split('.')
    if (parts.size != 3) return ResultOf2.Failure("ID token is not a compact JWT")

    val payload = runCatching {
        Json.parseToJsonElement(Base64.getUrlDecoder().decode(parts[1]).decodeToString()).jsonObject
    }.getOrElse { return ResultOf2.Failure("ID token payload is not valid JSON") }

    val iss = payload.string("iss")
    if (iss != issuer) return ResultOf2.Failure("Unexpected issuer \"$iss\"")

    val audiences = when (val aud = payload["aud"]) {
        is JsonPrimitive -> listOfNotNull(aud.contentOrNull)
        is JsonArray -> aud.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        else -> emptyList()
    }
    if (clientId !in audiences) return ResultOf2.Failure("ID token was not issued for this client")
    val azpMismatch = audiences.size > 1 && payload.string("azp") != clientId
    if (azpMismatch) return ResultOf2.Failure("ID token has several audiences and azp is not this client")

    val exp = payload.long("exp") ?: return ResultOf2.Failure("ID token has no exp")
    if (nowSeconds > exp + leewaySeconds) return ResultOf2.Failure("ID token expired")
    val iat = payload.long("iat")
    if (iat != null && iat > nowSeconds + leewaySeconds) return ResultOf2.Failure("ID token issued in the future")

    val tokenNonce = payload.string("nonce") ?: return ResultOf2.Failure("ID token has no nonce")
    if (constantTimeEquals(tokenNonce, nonce).not()) return ResultOf2.Failure("ID token nonce does not match")

    val sub = payload.string("sub")
    if (sub.isNullOrBlank()) return ResultOf2.Failure("ID token has no sub")

    val name = listOf("name", "preferred_username").firstNotNullOfOrNull { claim -> payload.string(claim)?.let { cleanText(it, MAX_NAME_LENGTH) } } ?: sub
    return ResultOf2.Success(IdTokenClaims(sub, name))
}

/** Compares two strings without leaking the position of the first difference through timing. */
fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull
