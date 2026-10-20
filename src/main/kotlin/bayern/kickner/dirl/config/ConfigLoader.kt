package bayern.kickner.dirl.config

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotnexlib.ResultOf2
import java.io.File
import java.net.URI

/** Strict JSON for the config file: unknown keys are errors, so a typo never silently falls back to a default. */
private val configJson = Json {
    ignoreUnknownKeys = false
    explicitNulls = false
}

/**
 * Reads and validates the config file.
 *
 * @return the config, or every problem found at once so a broken file can be fixed in one go. Messages never
 *   contain the client secret.
 */
fun loadConfig(file: File): ResultOf2<AppConfig, List<String>> {
    if (file.isFile.not()) return ResultOf2.Failure(listOf("Config file ${file.absolutePath} does not exist"))

    val parsed = runCatching { configJson.decodeFromString(AppConfig.serializer(), file.readText()) }
    val config = parsed.getOrElse {
        val reason = if (it is SerializationException) it.message ?: "invalid JSON" else it.toString()
        return ResultOf2.Failure(listOf("Cannot parse ${file.absolutePath}: $reason"))
    }

    val issues = validateConfig(config)
    return if (issues.isEmpty()) ResultOf2.Success(config) else ResultOf2.Failure(issues)
}

/**
 * Checks everything that parses fine but cannot work. `http` is only accepted for loopback hosts, which keeps
 * local development possible without weakening a real deployment.
 *
 * @return all issues found, empty if the config is usable.
 */
fun validateConfig(config: AppConfig): List<String> = buildList {
    if (config.port !in 1..65535) add("port must be between 1 and 65535, is ${config.port}")

    checkUrl("publicUrl", config.publicUrl)?.let(::add)
    if (config.publicUrl.endsWith("/")) add("publicUrl must not end with a slash")
    originProblems(config.publicUrl).forEach(::add)

    checkUrl("oidc.issuer", config.oidc.issuer)?.let(::add)
    if (config.oidc.clientId.isBlank()) add("oidc.clientId must not be blank")
    if (config.oidc.clientSecret.isBlank()) add("oidc.clientSecret must not be blank, register Dirl as a confidential client")
    if ("openid" !in config.oidc.scopes) add("oidc.scopes must contain \"openid\"")

    if (config.session.idleTimeoutMinutes < 1) add("session.idleTimeoutMinutes must be at least 1")
    if (config.session.maxAgeHours < 1) add("session.maxAgeHours must be at least 1")
    if (config.dataDir.isBlank()) add("dataDir must not be blank")
}

/**
 * The origin check compares the browser's `Origin` header exactly with the origin of `publicUrl`. Browsers send the
 * host in lower case and leave out the default port, so any other spelling would reject every form and terminal.
 */
private fun originProblems(publicUrl: String): List<String> {
    val uri = runCatching { URI(publicUrl) }.getOrNull() ?: return emptyList()
    val host = uri.host ?: return emptyList()
    val defaultPort = when (uri.scheme) {
        "https" -> 443
        "http" -> 80
        else -> return emptyList()
    }
    return listOfNotNull(
        "publicUrl must not contain the default port $defaultPort, browsers leave it out of the Origin header".takeIf { uri.port == defaultPort },
        "publicUrl must use a lower case host name, browsers send it that way in the Origin header".takeIf { host != host.lowercase() },
    )
}

/** Returns an error message if [value] is not an absolute `https` URL (or `http` on a loopback host). */
private fun checkUrl(name: String, value: String): String? {
    val uri = runCatching { URI(value) }.getOrNull()
    val valid = uri != null && uri.host != null && (uri.scheme == "https" || (uri.scheme == "http" && isLoopback(uri.host)))
    return if (valid) null else "$name must be an absolute https URL (http only for localhost), is \"$value\""
}

/** True for host names that never leave the machine. */
internal fun isLoopback(host: String): Boolean =
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1" || host.endsWith(".localhost")
