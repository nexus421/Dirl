package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.audit.AuditAction
import bayern.kickner.dirl.audit.AuditLog
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.PinnedHostKey
import bayern.kickner.dirl.vault.Vault
import bayern.kickner.dirl.vault.VaultState
import bayern.kickner.klogger.infoLog
import bayern.kickner.klogger.warnLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotnexlib.ResultOf2
import net.schmizz.keepalive.KeepAliveProvider
import net.schmizz.keepalive.KeepAliveRunner
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import net.schmizz.sshj.userauth.UserAuthException
import java.security.PublicKey
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** State of the one long-lived connection per host, shown in the overview. */
sealed interface ConnectionState {
    /** Never tried, or reset by the user. */
    data object Idle : ConnectionState

    /** A connect attempt is running. */
    data object Connecting : ConnectionState

    /** Connected and authenticated. @property since Unix milliseconds. */
    data class Connected(val since: Long) : ConnectionState

    /**
     * The last attempt failed for a reason other than authentication. Retried automatically after [retryAt].
     *
     * @property reason For the UI.
     * @property failures Consecutive failures, drives the backoff.
     * @property retryAt Unix milliseconds.
     */
    data class Failed(val reason: String, val failures: Int, val retryAt: Long) : ConnectionState

    /**
     * The server rejected the key. Retried after [retryAt] until [MAX_AUTH_FAILURES] is reached.
     *
     * @property failures Consecutive authentication failures.
     * @property retryAt Unix milliseconds.
     */
    data class AuthFailed(val failures: Int, val retryAt: Long) : ConnectionState

    /**
     * No more automatic attempts until the user resets the connection in the UI.
     *
     * @property reason For the UI.
     */
    data class Stopped(val reason: String) : ConnectionState

    /**
     * First contact: the host key is not pinned yet and waits for confirmation in the UI.
     *
     * @property keyType Offered key type, e.g. `ssh-ed25519`.
     * @property fingerprint `SHA256:` fingerprint to compare with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
     */
    data class HostKeyUnknown(val keyType: String, val fingerprint: String) : ConnectionState

    /**
     * The server presented a different key than the pinned one. Blocked hard, never accepted automatically.
     *
     * @property expected The pinned fingerprint.
     * @property actual What the server presented.
     */
    data class HostKeyMismatch(val expected: String, val actual: String) : ConnectionState
}

/** Authentication failures in a row before a host is [ConnectionState.Stopped]. */
const val MAX_AUTH_FAILURES = 3

/**
 * Wait time after [failures] consecutive failures: 30 s, doubled per failure, at most 15 min.
 */
fun backoffDelayMillis(failures: Int): Long {
    val base = 30.seconds.inWholeMilliseconds
    val max = 15.minutes.inWholeMilliseconds
    val shift = (failures - 1).coerceIn(0, 10)
    return min(base shl shift, max)
}

/**
 * Keeps exactly one SSH connection per host. Terminals, SFTP and metrics open channels on it.
 *
 * Failed connects back off from 30 s to 15 min. After [MAX_AUTH_FAILURES] rejected logins in a row the host is
 * stopped until reset in the UI, so fail2ban on the target does not ban Dirl's address. There is no TCP ping: a bare
 * TCP connect without SSH handshake shows up as `kex_exchange_identification` error in the target's log, which
 * aggressive fail2ban filters count as an attack. Liveness comes from SSH keepalives and the metrics poll instead.
 *
 * Jump host connections are managed connections of their own, kept alive like every other. The tunnel for a target
 * is a direct-tcpip channel on the jump host's connection. When the jump connection dies, the targets behind it
 * die as well and reconnect through the backoff.
 *
 * Sealing the vault closes every connection.
 *
 * @property vault Source of hosts and keys, also notifies about sealing.
 * @property audit Receives host key events and stopped connections.
 * @property clock Unix milliseconds.
 */
class ConnectionManager(
    private val vault: Vault,
    private val audit: AuditLog,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Entry {
        val mutex = Mutex()

        @Volatile
        var state: ConnectionState = ConnectionState.Idle

        @Volatile
        var client: SSHClient? = null
        var failures = 0
        var authFailures = 0
    }

    private val entries = ConcurrentHashMap<String, Entry>()

    init {
        vault.listeners += { state -> if (state !is VaultState.Unlocked) disconnectAll() }
    }

    /** Current state of [hostId] without touching the connection. */
    fun state(hostId: String): ConnectionState = entries[hostId]?.state ?: ConnectionState.Idle

    /**
     * Returns the live connection to [hostId], connecting (through its jump hosts) if needed. Respects the backoff:
     * while a retry is not due yet, the current state is returned as failure without a network attempt.
     */
    suspend fun connection(hostId: String): ResultOf2<SSHClient, ConnectionState> {
        val content = vault.content ?: return ResultOf2.Failure(ConnectionState.Stopped("Vault is sealed"))
        val route = when (val r = resolveRoute(content, hostId)) {
            is ResultOf2.Success -> r.value
            is ResultOf2.Failure -> return ResultOf2.Failure(ConnectionState.Stopped(r.value))
        }
        val host = route.last()
        val entry = entries.computeIfAbsent(hostId) { Entry() }

        return entry.mutex.withLock {
            val existing = entry.client
            if (existing != null && existing.isConnected && existing.isAuthenticated) return@withLock ResultOf2.Success(existing)

            val blocked = when (val s = entry.state) {
                is ConnectionState.Stopped, is ConnectionState.HostKeyMismatch, is ConnectionState.HostKeyUnknown -> true
                is ConnectionState.Failed -> clock() < s.retryAt
                is ConnectionState.AuthFailed -> clock() < s.retryAt
                else -> false
            }
            if (blocked) return@withLock ResultOf2.Failure(entry.state)

            val jumpClient = host.jumpHostId?.let { jumpId ->
                when (val jump = connection(jumpId)) {
                    is ResultOf2.Success -> jump.value
                    is ResultOf2.Failure -> return@withLock fail(entry, host, "Jump host unavailable: ${describe(jump.value)}")
                }
            }
            entry.state = ConnectionState.Connecting
            connect(entry, host, jumpClient)
        }
    }

    /**
     * Pins the host key the user confirmed. [fingerprint] is what the user saw, it must still match the key the
     * server offered, otherwise nothing is pinned. Resets the connection so the next access connects with the pin.
     *
     * @return true if the key was pinned.
     */
    fun pinHostKey(hostId: String, fingerprint: String, actor: Actor): Boolean {
        val offered = entries[hostId]?.state as? ConnectionState.HostKeyUnknown ?: return false
        if (offered.fingerprint != fingerprint) return false
        val pin = PinnedHostKey(offered.keyType, offered.fingerprint, clock())
        val updated = vault.update { content ->
            content.copy(hosts = content.hosts.map { if (it.id == hostId) it.copy(pinnedHostKey = pin) else it })
        } ?: return false
        audit.record(actor, AuditAction.HOST_KEY_PINNED, updated.host(hostId)?.name, fingerprint)
        reset(hostId)
        return true
    }

    /** Closes the connection of [hostId] and clears its failure counters and stop state. */
    fun reset(hostId: String) {
        entries.remove(hostId)?.client?.let { closeQuietly(it) }
    }

    /** Closes the connection of [hostId] and of every host tunneling through it, e.g. after an edit. */
    fun drop(hostId: String) {
        reset(hostId)
        vault.content?.hosts?.filter { it.jumpHostId == hostId }?.forEach { drop(it.id) }
    }

    /** Closes every connection, called when the vault is sealed and at shutdown. */
    fun disconnectAll() {
        entries.keys.toList().forEach(::reset)
        infoLog { "All SSH connections closed" }
    }

    private suspend fun connect(entry: Entry, host: Host, jump: SSHClient?): ResultOf2<SSHClient, ConnectionState> {
        val key = vault.content?.key(host.keyId) ?: return fail(entry, host, "Key missing")
        val verifier = PinningVerifier(host.pinnedHostKey)
        val client = newClient(verifier)

        val outcome = withContext(Dispatchers.IO) {
            runCatching {
                if (jump == null) client.connect(host.address, host.port)
                else client.connectVia(jump.newDirectConnection(host.address, host.port))
                client.authPublickey(host.username, client.loadKeys(key.privateKeyPem, null, null))
            }
        }

        val error = outcome.exceptionOrNull()
        if (error == null) {
            entry.client = client
            // reset() does not wait for a running connect, it only drops the entry from the map. A client finished
            // after that would belong to nobody and stay open, even after sealing. Setting the client first and
            // checking second means either reset() sees the client and closes it, or this check sees the drop.
            if (entries[host.id] !== entry) {
                closeQuietly(client)
                infoLog { "Connection to ${host.name} was reset while connecting, closed" }
                return ResultOf2.Failure(ConnectionState.Idle)
            }
            entry.failures = 0
            entry.authFailures = 0
            entry.state = ConnectionState.Connected(clock())
            infoLog { "Connected to ${host.name}" }
            return ResultOf2.Success(client)
        }

        closeQuietly(client)
        val seen = verifier.seen
        val pinned = host.pinnedHostKey
        return when {
            seen != null && pinned == null -> {
                entry.state = ConnectionState.HostKeyUnknown(seen.first, seen.second)
                ResultOf2.Failure(entry.state)
            }

            seen != null && pinned != null && verifier.accepted.not() -> {
                entry.state = ConnectionState.HostKeyMismatch(pinned.fingerprint, seen.second)
                audit.record(Actor.SYSTEM, AuditAction.HOST_KEY_MISMATCH, host.name, "expected ${pinned.fingerprint}, got ${seen.second}")
                warnLog { "Host key of ${host.name} changed, connection blocked" }
                ResultOf2.Failure(entry.state)
            }

            error is UserAuthException -> authFailed(entry, host)
            else -> fail(entry, host, failureReason(error))
        }
    }

    private fun authFailed(entry: Entry, host: Host): ResultOf2<SSHClient, ConnectionState> {
        entry.authFailures++
        val stop = entry.authFailures >= MAX_AUTH_FAILURES
        entry.state = if (stop) ConnectionState.Stopped("Login rejected $MAX_AUTH_FAILURES times, check authorized_keys")
        else ConnectionState.AuthFailed(entry.authFailures, clock() + backoffDelayMillis(entry.authFailures))
        if (stop) audit.record(Actor.SYSTEM, AuditAction.CONNECTION_STOPPED, host.name, "authentication failed $MAX_AUTH_FAILURES times")
        warnLog { "Authentication to ${host.name} failed (${entry.authFailures} of $MAX_AUTH_FAILURES)" }
        return ResultOf2.Failure(entry.state)
    }

    private fun fail(entry: Entry, host: Host, reason: String): ResultOf2<SSHClient, ConnectionState> {
        entry.failures++
        entry.state = ConnectionState.Failed(reason, entry.failures, clock() + backoffDelayMillis(entry.failures))
        warnLog { "Connection to ${host.name} failed (${entry.failures} in a row): $reason" }
        return ResultOf2.Failure(entry.state)
    }

    private fun newClient(verifier: HostKeyVerifier): SSHClient {
        // KEEP_ALIVE detects dead connections. The default HEARTBEAT only sends packets and never notices anything.
        val config = DefaultConfig().apply { keepAliveProvider = KeepAliveProvider.KEEP_ALIVE }
        return SSHClient(config).apply {
            addHostKeyVerifier(verifier)
            connectTimeout = 10_000
            timeout = 30_000
            connection.keepAlive.keepAliveInterval = 15
            (connection.keepAlive as? KeepAliveRunner)?.maxAliveCount = 4
        }
    }

    private fun closeQuietly(client: SSHClient) {
        runCatching { client.disconnect() }
    }
}

/**
 * Turns a connect exception into a reason a user can act on. A connection closed during the identification exchange
 * usually means the server refused this source address: OpenSSH 9.8 and later do that on their own for a while
 * after failed logins (`PerSourcePenalties`), fail2ban or `MaxStartups` look the same.
 */
fun failureReason(error: Throwable): String {
    val message = error.message ?: error.javaClass.simpleName
    return when {
        message.contains("identification", ignoreCase = true) ->
            "the server dropped the connection before the handshake, usually a temporary block after failed logins (OpenSSH PerSourcePenalties or fail2ban)"
        error is java.net.ConnectException -> "connection refused, is sshd running on that port?"
        error is java.net.UnknownHostException -> "unknown host name"
        error is java.net.SocketTimeoutException -> "timed out"
        else -> message
    }
}

/** One line description of a state for messages and the UI. */
fun describe(state: ConnectionState): String = when (state) {
    ConnectionState.Idle -> "not connected"
    ConnectionState.Connecting -> "connecting"
    is ConnectionState.Connected -> "connected"
    is ConnectionState.Failed -> "failed: ${state.reason}"
    is ConnectionState.AuthFailed -> "login rejected (${state.failures} of $MAX_AUTH_FAILURES)"
    is ConnectionState.Stopped -> "stopped: ${state.reason}"
    is ConnectionState.HostKeyUnknown -> "host key not confirmed yet"
    is ConnectionState.HostKeyMismatch -> "HOST KEY CHANGED"
}

/**
 * Accepts exactly the pinned key and records whatever the server offered, so an unknown key can be shown for
 * confirmation and a changed key can be reported.
 *
 * No algorithm preference is returned: forcing the pinned key type would select the deprecated `ssh-rsa` signature
 * for RSA host keys, which current OpenSSH refuses.
 */
private class PinningVerifier(private val pinned: PinnedHostKey?) : HostKeyVerifier {
    /** Key type and fingerprint the server offered, `null` until the key exchange ran. */
    @Volatile
    var seen: Pair<String, String>? = null

    /** True if the offered key matched the pin. */
    @Volatile
    var accepted = false

    override fun verify(hostname: String, port: Int, key: PublicKey): Boolean {
        val type = net.schmizz.sshj.common.KeyType.fromKey(key).toString()
        val fp = fingerprint(key)
        seen = type to fp
        accepted = pinned != null && pinned.fingerprint == fp && pinned.keyType == type
        return accepted
    }

    override fun findExistingAlgorithms(hostname: String, port: Int): List<String> = emptyList()
}
