package bayern.kickner.dirl.auth

import bayern.kickner.dirl.toBase64Url
import kotnexlib.ResultOf2
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class IdTokenTest {
    private val issuer = "https://id.example.com"
    private val clientId = "dirl"
    private val nonce = "n-123"
    private val now = 1_800_000_000L

    private fun token(payload: String): String =
        """{"alg":"RS256"}""".toByteArray().toBase64Url() + "." + payload.toByteArray().toBase64Url() + ".signature"

    private fun claims(
        iss: String = issuer,
        aud: String = "\"$clientId\"",
        exp: Long = now + 300,
        nonce: String = this.nonce,
        extra: String = "",
    ) = token("""{"iss":"$iss","aud":$aud,"exp":$exp,"iat":${now - 5},"nonce":"$nonce","sub":"user-1","name":"Ada"$extra}""")

    private fun validate(t: String) = validateIdToken(t, issuer, clientId, nonce, now)

    @Test
    fun `accepts a valid token`() {
        assertEquals(ResultOf2.Success(IdTokenClaims("user-1", "Ada")), validate(claims()))
    }

    @Test
    fun `rejects wrong issuer, audience, expiry and nonce`() {
        assertIs<ResultOf2.Failure<String>>(validate(claims(iss = "https://id.example.com/")))
        assertIs<ResultOf2.Failure<String>>(validate(claims(aud = "\"other\"")))
        assertIs<ResultOf2.Failure<String>>(validate(claims(exp = now - 120)))
        assertIs<ResultOf2.Failure<String>>(validate(claims(nonce = "n-124")))
        assertIs<ResultOf2.Failure<String>>(validate("not.a-jwt"))
    }

    @Test
    fun `several audiences need azp`() {
        assertIs<ResultOf2.Failure<String>>(validate(claims(aud = """["$clientId","other"]""")))
        assertIs<ResultOf2.Success<IdTokenClaims>>(validate(claims(aud = """["$clientId","other"]""", extra = ""","azp":"$clientId"""")))
    }

    @Test
    fun `PKCE challenge matches the RFC 7636 example`() {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
    }
}
