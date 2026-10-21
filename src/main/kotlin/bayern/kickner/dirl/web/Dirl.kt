package bayern.kickner.dirl.web

import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.auth.AccessControl
import bayern.kickner.dirl.auth.OidcClient
import bayern.kickner.dirl.auth.SessionStore
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.ssh.ConnectionManager
import bayern.kickner.dirl.ssh.MetricsPoller
import bayern.kickner.dirl.ssh.Presence
import bayern.kickner.dirl.vault.Vault
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.http.content.staticResources
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.pingPeriod
import kotlin.time.Duration.Companion.seconds

/**
 * Everything the routes need, created once in `Main.kt`.
 *
 * @property config The loaded config.
 * @property vault Encrypted store.
 * @property audit Audit log.
 * @property access Who may log in.
 * @property sessions Browser sessions.
 * @property oidc Login.
 * @property connections SSH connections.
 * @property presence Whether anybody uses Dirl, connections only exist while somebody does.
 * @property metrics Latest status per host.
 */
class Dirl(
    val config: AppConfig,
    val vault: Vault,
    val audit: AuditLog,
    val access: AccessControl,
    val sessions: SessionStore,
    val oidc: OidcClient,
    val connections: ConnectionManager,
    val presence: Presence,
    val metrics: MetricsPoller,
) {
    /** The only `Origin` accepted for form posts and WebSockets. */
    val publicOrigin: String = originOf(config.publicUrl)
}

/** Maximum WebSocket frame size. Ktor's default is unlimited, which lets one client exhaust the heap. */
const val MAX_FRAME_BYTES = 1L * 1024 * 1024

/** The Ktor module: plugins, guards and all routes. */
fun Application.dirlModule(dirl: Dirl) {
    install(WebSockets) {
        // Ping is off by default. 20 s keeps idle connections open through the reverse proxy's idle timeout
        pingPeriod = 20.seconds
        timeoutMillis = 15.seconds.inWholeMilliseconds
        maxFrameSize = MAX_FRAME_BYTES
        masking = false
    }
    installGuards(dirl)
    installErrorPages()

    routing {
        staticResources("/static", "static")
        get("/healthz") { call.respondText("ok") }

        authRoutes(dirl)
        vaultRoutes(dirl)
        settingsRoutes(dirl)
        hostRoutes(dirl)
        keyRoutes(dirl)
        snippetRoutes(dirl)
        terminalRoutes(dirl)
        presenceRoutes(dirl)
        fileRoutes(dirl)
    }
}
