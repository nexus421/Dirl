@file:OptIn(ExperimentalKotNexLibAPI::class)

package bayern.kickner.dirl.crypto

import kotlinx.serialization.Serializable
import kotnexlib.ExperimentalKotNexLibAPI
import kotnexlib.crypto.AES
import kotnexlib.fromBase64ToByteArray
import kotnexlib.toBase64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * One AES-256-GCM ciphertext together with the nonce it was encrypted with, both Base64 encoded.
 *
 * KotNexLib's `AES.GCM.encrypt` returns only the ciphertext. With its default nonce argument the nonce is lost and
 * the result can never be decrypted again, so [Aead.seal] always creates the nonce itself and keeps it here.
 *
 * @property nonce 12 random bytes, new for every encryption.
 * @property ct Ciphertext including the 128 bit authentication tag.
 */
@Serializable
data class SealedBox(val nonce: String, val ct: String)

/**
 * Authenticated encryption with AES-256-GCM through KotNexLib.
 *
 * GCM protects integrity as well as confidentiality: a modified ciphertext or a wrong key makes [open] fail instead
 * of returning garbage. That is what makes a wrong passphrase detectable and keeps someone with write access to the
 * vault from silently swapping a pinned host key.
 *
 * Compression stays off on purpose. Compressing before encrypting leaks information through the ciphertext length.
 *
 * A random 96 bit nonce per encryption is safe for up to 2^32 encryptions with one key (the NIST limit). A vault
 * that is rewritten on every change never gets anywhere near that.
 */
object Aead {

    /** Encrypts [plain] with a fresh random nonce. */
    fun seal(plain: ByteArray, key: SecretKey): SealedBox {
        val nonce = AES.Common.generateNonce()
        val ct = AES.GCM.encrypt(plain, key, nonce, compress = false).getOrThrow()
        return SealedBox(nonce.toBase64(), ct)
    }

    /** Decrypts [box]. Fails on a wrong key or any modification of nonce or ciphertext. */
    fun open(box: SealedBox, key: SecretKey): Result<ByteArray> = runCatching {
        AES.GCM.decryptToByteArray(box.ct, key, box.nonce.fromBase64ToByteArray(), isCompressed = false).getOrThrow()
    }

    /** Generates a new random 256 bit data encryption key. */
    fun generateKey(): SecretKey = AES.Common.generateAESKey(256)

    /**
     * Wraps raw key bytes as an AES key. [SecretKeySpec] copies the array, so the caller can and should wipe its
     * own copy afterwards. The copy inside the key object cannot be wiped, `destroy()` is not implemented by the JDK.
     */
    fun keyOf(bytes: ByteArray): SecretKey = SecretKeySpec(bytes, "AES")
}
