package bayern.kickner.dirl

import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.auth.AccessControl
import bayern.kickner.dirl.auth.OidcClient
import bayern.kickner.dirl.auth.SessionStore
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.UnlockMode
import bayern.kickner.dirl.config.loadConfig
import bayern.kickner.dirl.ssh.ConnectionManager
import bayern.kickner.dirl.ssh.MetricsPoller
import bayern.kickner.dirl.ssh.Presence
import bayern.kickner.dirl.vault.Vault
import bayern.kickner.dirl.vault.VaultState
import bayern.kickner.dirl.vault.VaultStore
import bayern.kickner.dirl.web.Dirl
import bayern.kickner.dirl.web.dirlModule
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.slf4j.slf4jBridge
import bayern.kickner.klogger.staticLog
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Dispatchers
import kotnexlib.ArgsInterpreter
import kotnexlib.ResultOf2
import java.io.File
import java.net.BindException
import kotlin.system.exitProcess
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private const val TAG = "Main"

/** Default location of the config file. */
const val DEFAULT_CONFIG_PATH = "/etc/dirl/config.json"

/** Exit code for a rejected config or a port that cannot be bound (`EX_CONFIG` from sysexits.h). */
const val EXIT_CONFIG = 78

/**
 * Entry point.
 *
 * Arguments are `key=value` pairs and bare words:
 * - `config=<path>` config file, default [DEFAULT_CONFIG_PATH].
 * - `check` only validates the config and exits.
 *
 * Exit codes: `0` success, `1` unexpected failure, [EXIT_CONFIG] for a broken config or an unusable port.
 */
fun main(args: Array<String>) {
    val arguments = ArgsInterpreter(args)
    val configFile = File(arguments.getValue("config") ?: DEFAULT_CONFIG_PATH)

    val config = when (val loaded = loadConfig(configFile)) {
        is ResultOf2.Success -> loaded.value
        is ResultOf2.Failure -> {
            System.err.println("Config rejected:")
            loaded.value.forEach { System.err.println("  - $it") }
            exitProcess(EXIT_CONFIG)
        }
    }
    if (args.contains("check")) {
        println("Config ${configFile.absolutePath} is valid")
        exitProcess(0)
    }

    val dataDir = File(config.dataDir)
    configureLogging(File(dataDir, "logs"))
    staticLog(KLogger.Level.INFO, TAG) { "Dirl $appVersion starting on ${config.host}:${config.port}, public URL ${config.publicUrl}" }

    val dirl = createDirl(config, dataDir)
    if (dirl.access.isBootstrap) {
        staticLog(KLogger.Level.WARN, TAG) { "No vault yet. The first user the identity provider lets through can create it. Do that now." }
    }
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    dirl.metrics.start(scope)
    if (config.unlockMode == UnlockMode.KEYFILE && dirl.vault.state == VaultState.Sealed) {
        val result = dirl.vault.unlockWithKeyFile()
        if (result is ResultOf2.Failure) staticLog(KLogger.Level.ERROR, TAG) { "Automatic unlock with the key file failed: ${result.value}" }
    }

    Runtime.getRuntime().addShutdownHook(Thread { dirl.connections.disconnectAll() })

    runCatching {
        embeddedServer(CIO, port = config.port, host = config.host) { dirlModule(dirl) }.start(wait = true)
    }.onFailure {
        val bindFailed = it is BindException || it.cause is BindException
        staticLog(KLogger.Level.CRASH, TAG) { "Server stopped: ${it.stackTraceToString()}" }
        exitProcess(if (bindFailed) EXIT_CONFIG else 1)
    }
}

/**
 * Creates all services. Nothing connects anywhere yet, the vault starts sealed or uninitialized.
 *
 * @param clock Unix milliseconds for every service, injectable for tests.
 */
fun createDirl(config: AppConfig, dataDir: File, clock: () -> Long = System::currentTimeMillis): Dirl {
    val audit = AuditLog(File(dataDir, "audit.jsonl"))
    val keyFile = if (config.unlockMode == UnlockMode.KEYFILE) File(config.keyFile) else null
    val vault = Vault(VaultStore(dataDir), audit, keyFile, clock)
    val connections = ConnectionManager(vault, audit, clock)
    val presence = Presence(clock)
    return Dirl(
        config = config,
        vault = vault,
        audit = audit,
        access = AccessControl(config.oidc, vault, File(dataDir, "access.json"), audit, clock),
        sessions = SessionStore(config.session.idleTimeoutMinutes.minutes, config.session.maxAgeHours.hours, clock),
        oidc = OidcClient(config.oidc, "${config.publicUrl}/auth/callback", clock = clock),
        connections = connections,
        presence = presence,
        metrics = MetricsPoller(vault, connections, presence, clock = clock),
    )
}

/**
 * Console plus a rotating file in [logDir]. Libraries log through SLF4J into Klogger: sshj and Ktor only from WARN
 * and INFO on, because sshj logs every packet type at DEBUG. Terminal data, passphrases and keys are never logged.
 */
private fun configureLogging(logDir: File) {
    KLogger.configure {
        logToConsole()
        logToFile(File(logDir, "app.log"), maxFileSize = 5L * 1024 * 1024)
        slf4jBridge {
            minLevel = KLogger.Level.INFO
            level("net.schmizz", KLogger.Level.WARN)
            level("com.hierynomus", KLogger.Level.WARN)
        }
    }
}
