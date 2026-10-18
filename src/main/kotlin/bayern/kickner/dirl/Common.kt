package bayern.kickner.dirl

import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale

/**
 * Format of every timestamp this project prints, e.g. `15.10.2026 19:40:12 CEST`. Pinned to [Locale.ENGLISH] so the
 * zone abbreviation stays the same on every host.
 */
val timestampFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss z", Locale.ENGLISH)

/** Formats Unix milliseconds with [timestampFormat] in the host's time zone. */
fun formatTimestamp(epochMillis: Long): String =
    Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault()).format(timestampFormat)

/** Version and build time for the start banner and the page footer. */
val appVersion: String = "${BuildConfig.VERSION} (built ${formatTimestamp(BuildConfig.BUILD_TIME)})"

/** One shared generator. `SecureRandom()` uses the non-blocking system source on Linux. */
val secureRandom: SecureRandom = SecureRandom()

/** URL-safe Base64 without padding, the encoding of tokens, PKCE values and JWT parts. */
private val base64Url = Base64.getUrlEncoder().withoutPadding()

/** Encodes as URL-safe Base64 without padding. */
fun ByteArray.toBase64Url(): String = base64Url.encodeToString(this)

/**
 * Returns [bytes] random bytes encoded as URL-safe Base64. Used for session tokens, OIDC `state` and `nonce`, PKCE
 * verifiers and object IDs.
 */
fun randomToken(bytes: Int = 32, random: SecureRandom = secureRandom): String =
    ByteArray(bytes).also(random::nextBytes).toBase64Url()

/** Short random ID for hosts, keys and snippets (96 bit, URL-safe). */
fun newId(random: SecureRandom = secureRandom): String = randomToken(12, random)

/** Overwrites the array with zeros. Best effort only: the JVM may have copied the contents before. */
fun ByteArray.wipe() = fill(0)

/** Overwrites the array with zeros. Best effort only: the JVM may have copied the contents before. */
fun CharArray.wipe() = fill('\u0000')

/**
 * Limits [file] to its owner (`0600`). Defense in depth next to `UMask=0077` in the systemd unit, ignored on file
 * systems without POSIX permissions.
 */
fun restrictToOwner(file: File) {
    runCatching { Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------")) }
}

/**
 * Reads the stream up to its end, but at most [max] bytes. Everything a remote server sends is untrusted, a
 * compromised server could otherwise stream until the heap is gone, and `-XX:+ExitOnOutOfMemoryError` would then
 * restart Dirl sealed.
 *
 * @return the bytes, or `null` if the stream holds more than [max] bytes.
 */
fun InputStream.readAtMost(max: Int): ByteArray? {
    val bytes = readNBytes(max + 1)
    return if (bytes.size > max) null else bytes
}
