package bayern.kickner.dirl

import bayern.kickner.klogger.KLogger
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.*

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
    runCatching {
        Files.setPosixFilePermissions(
            file.toPath(), setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        )
    }
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

private val whitespace = "\\s+".toRegex()

/** Terminal escape sequences like colors (`ESC [ 31 m`), dropped as a whole instead of leaving `[31m` behind. */
private val ansiEscape = "\u001B\\[[0-9;?]*[ -/]*[@-~]|\u001B[@-Z\\\\-_]".toRegex()

/** Control characters such as line breaks and tabs, they become a space so the words around them stay apart. */
private val controlChar = "\\p{Cc}".toRegex()

/** Invisible formatting characters such as U+202E, which turns the text after it around on screen. */
private val formatChar = "\\p{Cf}".toRegex()

/**
 * Untrusted text as it may be shown and logged: no terminal escapes, no control or formatting characters (which could
 * hide or reorder text, or forge log lines), whitespace collapsed, at most [max] characters. Used for text from
 * servers and for display names and login errors from the identity provider.
 *
 * @return the cleaned text, `null` if nothing is left.
 */
fun cleanText(raw: String, max: Int): String? = raw
    .replace(ansiEscape, "")
    .replace(controlChar, " ")
    .replace(formatChar, "")
    .replace(whitespace, " ").trim().take(max).trim().ifEmpty { null }

/** Control characters except line break and tab, invisible formatting characters and the Unicode line separators. */
private val logUnsafe = "[\\p{Cc}\\p{Cf}\\u2028\\u2029&&[^\\n\\t]]".toRegex()

/**
 * A log message as it may reach the console and `app.log`, see [logLine]. Control and formatting characters become
 * visible escapes such as `\x1b`, so text from a server or a user cannot run escape sequences in the terminal of
 * whoever reads the log. Line breaks stay for stack traces, but every further line is indented, so no part of a
 * message can pass for a log line of its own.
 */
fun logSafe(message: String): String = message
    .replace(logUnsafe) { match -> match.value[0].code.let { if (it <= 0xff) "\\x%02x".format(it) else "\\u%04x".format(it) } }
    .replace("\n", "\n    ")

/** The line format of the console and `app.log`: Klogger's default with the message made safe by [logSafe]. */
fun logLine(level: KLogger.Level, tag: String, message: String): String = KLogger.formatLogDefault(level, tag, logSafe(message))
