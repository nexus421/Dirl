package bayern.kickner.dirl.crypto

import bayern.kickner.dirl.secureRandom
import kotlinx.serialization.Serializable
import kotnexlib.fromBase64ToByteArray
import kotnexlib.toBase64
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom

/**
 * Argon2id parameters, stored in plain text in the vault so the key can be derived again.
 *
 * The defaults (64 MiB, 3 passes) are well above the OWASP minimum (19 MiB, 2 passes). The 64 MiB are allocated on
 * the heap for the duration of one derivation, `-Xmx` in the systemd unit accounts for that.
 *
 * The parameters are not authenticated. Someone with write access to the vault file can change them, but that only
 * makes the derived key wrong and the unlock fail, it reveals nothing.
 *
 * @property alg Always `argon2id`, kept for future formats.
 * @property memKiB Memory cost in KiB.
 * @property iterations Number of passes.
 * @property parallelism Number of lanes.
 * @property salt Base64 encoded random salt (16 bytes).
 */
@Serializable
data class KdfParams(
    val alg: String = "argon2id",
    val memKiB: Int = 65536,
    val iterations: Int = 3,
    val parallelism: Int = 1,
    val salt: String,
) {
    companion object {
        /** Fresh parameters with the defaults and a new random salt. */
        fun generate(random: SecureRandom = secureRandom): KdfParams =
            KdfParams(salt = ByteArray(16).also(random::nextBytes).toBase64())
    }
}

/**
 * Derives a 256 bit key encryption key (KEK) from a passphrase with Argon2id.
 *
 * Uses BouncyCastle directly because KotNexLib's `Argon2Helper` only produces password hashes, not raw key
 * material. The caller owns [passphrase] and should wipe it, the returned array as well once the key is used.
 *
 * @throws IllegalArgumentException if [params] names another algorithm.
 */
fun deriveKek(passphrase: CharArray, params: KdfParams): ByteArray {
    require(params.alg == "argon2id") { "Unsupported KDF ${params.alg}" }
    val generator = Argon2BytesGenerator().apply {
        init(
            Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(params.memKiB)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
                .withSalt(params.salt.fromBase64ToByteArray())
                .build()
        )
    }
    return ByteArray(32).also { generator.generateBytes(passphrase, it) }
}
