package bayern.kickner.dirl

import bayern.kickner.dirl.vault.Vault
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.InputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

private const val TAG = "UpdateCheck"

/** GitHub's answer for the newest published release of Dirl. */
private const val LATEST_RELEASE_API = "https://api.github.com/repos/nexus421/Dirl/releases/latest"

/** Release pages of Dirl, a release is at `$RELEASES_URL/tag/v1.2.3`. */
const val RELEASES_URL = "https://github.com/nexus421/Dirl/releases"

/** Minimum time between two questions to GitHub, failed ones included. */
const val UPDATE_CHECK_INTERVAL_MILLIS = 60L * 60 * 1000

/**
 * Upper bound for GitHub's answer. A release with its notes is a few KiB, GitHub allows 125000 characters of notes.
 * Like everything read from outside, the answer is capped so it cannot exhaust the heap.
 */
const val MAX_RELEASE_ANSWER_BYTES = 1024 * 1024

private val releaseTag = Regex("""v(\d{1,9})\.(\d{1,9})\.(\d{1,9})""")
private val plainVersion = Regex("""(\d{1,9})\.(\d{1,9})\.(\d{1,9})""")
private val releaseJson = Json { ignoreUnknownKeys = true }

/** No redirects (the JDK default), a release answer comes straight from the API. */
private val http: HttpClient by lazy { HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build() }

@Serializable
private data class Release(@SerialName("tag_name") val tagName: String)

/**
 * The version of a release tag, `v1.2.3` becomes `1.2.3`.
 *
 * @return `null` for anything else, so nothing else from GitHub's answer ever reaches a page or a link.
 */
fun releaseVersion(tag: String): String? = releaseTag.matchEntire(tag)?.let { tag.removePrefix("v") }

/**
 * Whether [candidate] is a later version than [current], both plain `major.minor.patch`.
 *
 * @return `false` if either is no plain version, for example a build with a suffix.
 */
fun isNewerVersion(candidate: String, current: String): Boolean {
    val new = plainVersion.matchEntire(candidate)?.groupValues?.drop(1)?.map { it.toLong() } ?: return false
    val old = plainVersion.matchEntire(current)?.groupValues?.drop(1)?.map { it.toLong() } ?: return false
    val firstDifference = new.zip(old).firstOrNull { (a, b) -> a != b } ?: return false
    return firstDifference.first > firstDifference.second
}

/**
 * The release version from GitHub's JSON answer, see [releaseVersion].
 *
 * @param body The answer, `null` if it was too large.
 * @return `null` if the answer has no valid `tag_name`.
 */
fun latestReleaseOf(body: ByteArray?): String? {
    if (body == null) return null
    val release = runCatching { releaseJson.decodeFromString(Release.serializer(), body.decodeToString()) }.getOrNull()
    return release?.let { releaseVersion(it.tagName) }
}

/** Reads at most [MAX_RELEASE_ANSWER_BYTES] of [answer] and returns its release version, see [latestReleaseOf]. */
fun readReleaseAnswer(answer: InputStream): String? = answer.use { latestReleaseOf(it.readAtMost(MAX_RELEASE_ANSWER_BYTES)) }

/**
 * Asks GitHub for the newest published release. Blocking, at most 10 seconds to connect and 10 for the answer.
 *
 * @return the version, or `null` if GitHub answered with anything but a valid release (404 without releases, 403
 *   or 429 when the rate limit of 60 requests per hour and address is used up).
 * @throws java.io.IOException if GitHub cannot be reached.
 */
fun fetchLatestRelease(): String? {
    val request = HttpRequest.newBuilder(URI(LATEST_RELEASE_API))
        .timeout(Duration.ofSeconds(10))
        .header("Accept", "application/vnd.github+json")
        .GET()
        .build()
    val response = http.send(request, HttpResponse.BodyHandlers.ofInputStream())
    return response.body().use { body -> if (response.statusCode() == 200) readReleaseAnswer(body) else null }
}

/**
 * Tells whether a newer Dirl release exists. There is no timer: a page shown to a logged in user calls
 * [checkIfDue], which asks GitHub in the background if the last question is at least
 * [UPDATE_CHECK_INTERVAL_MILLIS] ago. Nobody using Dirl means no questions. Nothing is ever downloaded, only the
 * version number is read.
 *
 * Only while the vault is unlocked and the setting [bayern.kickner.dirl.vault.VaultSettings.updateCheck] is on.
 * A sealed vault cannot tell whether the check was turned off, so it does not ask.
 *
 * @param vault For the setting.
 * @param clock Unix milliseconds.
 * @param current The running version, [BuildConfig.VERSION].
 * @param fetchLatest Asks GitHub, see [fetchLatestRelease]. Tests replace it.
 */
class UpdateCheck(
    private val vault: Vault,
    private val clock: () -> Long,
    private val current: String = BuildConfig.VERSION,
    private val fetchLatest: () -> String?,
) {
    /** Newest release GitHub named, `null` before the first successful answer. */
    @Volatile
    var latest: String? = null
        private set

    /** Unix milliseconds of the last question to GitHub, `null` before the first. */
    @Volatile
    var lastAttempt: Long? = null
        private set

    /** Whether the update check is on. `false` while the vault is not unlocked. */
    val enabled: Boolean get() = vault.content?.settings?.updateCheck == true

    /**
     * Asks GitHub in [scope] if the check is on and the last question is at least [UPDATE_CHECK_INTERVAL_MILLIS]
     * ago. Returns at once, the answer shows from the next page on. A failure waits the same hour, so an
     * unreachable GitHub is not asked on every page.
     *
     * @return the running question, `null` if none was due.
     */
    fun checkIfDue(scope: CoroutineScope): Job? {
        if (enabled.not()) return null
        val now = clock()
        synchronized(this) {
            val last = lastAttempt
            if (last != null && now - last < UPDATE_CHECK_INTERVAL_MILLIS) return null
            lastAttempt = now
        }
        return scope.launch(Dispatchers.IO) {
            runCatching(fetchLatest)
                .onSuccess { version -> if (version != null) latest = version }
                .onFailure { staticLog(KLogger.Level.DEBUG, TAG) { "Update check failed: ${it.message}" } }
        }
    }

    /** The newer release to show, `null` if there is none or the check is off. */
    fun available(): String? = latest?.takeIf { enabled && isNewerVersion(it, current) }
}
