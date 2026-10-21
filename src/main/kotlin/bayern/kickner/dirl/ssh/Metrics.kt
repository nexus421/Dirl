package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.readAtMost
import bayern.kickner.dirl.vault.Vault
import bayern.kickner.dirl.vault.VaultState
import bayern.kickner.klogger.debugLog
import bayern.kickner.klogger.warnLog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull
import kotnexlib.ResultOf2
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The one command run every minute on each host while somebody uses Dirl. `LC_ALL=C` keeps the output parseable,
 * `df -l` skips network and FUSE mounts and `timeout 5` keeps a dead mount from hanging the channel. `/proc/stat` is
 * read twice, one second apart, so every poll yields the CPU usage on its own, also the first one after an arrival.
 */
const val METRICS_COMMAND =
    "LC_ALL=C sh -c 'cat /proc/uptime /proc/loadavg; head -n1 /proc/stat; sleep 1; head -n1 /proc/stat; " +
        "grep -E \"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\" /proc/meminfo; " +
        "timeout 5 df -PlkT -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs'"

/** Upper bound of the metrics command's output. Real output is a few KiB even with many mounts. */
const val MAX_METRICS_OUTPUT = 256 * 1024

/**
 * Cumulative CPU counters from the first line of `/proc/stat`, in jiffies.
 *
 * @property total user + nice + system + idle + iowait + irq + softirq + steal. Guest time is already part of user.
 * @property busy total minus idle minus iowait.
 */
data class CpuTimes(val total: Long, val busy: Long)

/**
 * One mounted file system from `df`.
 *
 * @property device Source device, e.g. `/dev/sda1`. Bind mounts and btrfs subvolumes share it.
 * @property mount Mount point.
 * @property fsType File system type.
 * @property totalKiB Size in KiB.
 * @property usedKiB Used space in KiB.
 */
data class DiskUsage(val device: String, val mount: String, val fsType: String, val totalKiB: Long, val usedKiB: Long)

/**
 * The parsed output of [METRICS_COMMAND].
 *
 * @property cpuPercent CPU usage during the second between the two readings, `null` if it could not be computed.
 */
data class RawMetrics(
    val uptimeSeconds: Double,
    val load1: Double,
    val load5: Double,
    val load15: Double,
    val cpuPercent: Double?,
    val memTotalKiB: Long,
    val memAvailableKiB: Long,
    val swapTotalKiB: Long,
    val swapFreeKiB: Long,
    val disks: List<DiskUsage>,
)

/**
 * The latest status of a host.
 *
 * @property time Unix milliseconds.
 * @property cpuPercent CPU usage during one second of the poll, `null` if it could not be computed.
 * @property memUsedKiB `MemTotal - MemAvailable`.
 */
data class MetricsSample(
    val time: Long,
    val cpuPercent: Double?,
    val memUsedKiB: Long,
    val memTotalKiB: Long,
    val swapUsedKiB: Long,
    val swapTotalKiB: Long,
    val load1: Double,
    val uptimeSeconds: Double,
    val disks: List<DiskUsage>,
)

/**
 * Parses the output of [METRICS_COMMAND].
 *
 * @return the values, or a reason for the log. Hosts restricted with `command="/bin/false"` (pure jump hosts)
 *   produce no output and end up here.
 */
fun parseMetrics(output: String): ResultOf2<RawMetrics, String> = runCatching {
    val lines = output.lines().filter { it.isNotBlank() }
    require(lines.size >= 3) { "too little output" }

    val uptime = lines[0].trim().split(Regex("\\s+"))[0].toDouble()
    val load = lines[1].trim().split(Regex("\\s+"))
    val cpuLines = lines.filter { it.startsWith("cpu ") }
    require(cpuLines.isNotEmpty()) { "no cpu line from /proc/stat" }
    val cpuBefore = cpuTimesOf(cpuLines.first())
    val cpuAfter = cpuTimesOf(cpuLines.last())

    val mem = lines.mapNotNull { line ->
        val match = Regex("^(\\w+):\\s+(\\d+) kB").find(line) ?: return@mapNotNull null
        match.groupValues[1] to match.groupValues[2].toLong()
    }.toMap()

    val dfHeader = lines.indexOfFirst { it.startsWith("Filesystem") }
    val disks = if (dfHeader < 0) emptyList() else lines.drop(dfHeader + 1).mapNotNull { line ->
        val cols = line.trim().split(Regex("\\s+"))
        if (cols.size < 7) return@mapNotNull null
        DiskUsage(device = cols[0], mount = cols.drop(6).joinToString(" "), fsType = cols[1], totalKiB = cols[2].toLong(), usedKiB = cols[3].toLong())
    }.let(::dedupeDisks)

    RawMetrics(
        uptimeSeconds = uptime,
        load1 = load[0].toDouble(), load5 = load[1].toDouble(), load15 = load[2].toDouble(),
        cpuPercent = if (cpuLines.size < 2) null else cpuPercent(cpuBefore, cpuAfter),
        memTotalKiB = mem.getValue("MemTotal"),
        memAvailableKiB = mem.getValue("MemAvailable"),
        swapTotalKiB = mem["SwapTotal"] ?: 0,
        swapFreeKiB = mem["SwapFree"] ?: 0,
        disks = disks,
    )
}.fold(
    onSuccess = { ResultOf2.Success(it) },
    onFailure = { ResultOf2.Failure("Cannot parse metrics: ${it.message}") },
)

/** The counters of a `cpu ` line from `/proc/stat`. */
private fun cpuTimesOf(line: String): CpuTimes {
    val fields = line.trim().split(Regex("\\s+")).drop(1).map { it.toLong() }
    val total = fields.take(8).sum()
    val idle = fields[3] + fields.getOrElse(4) { 0 }
    return CpuTimes(total, total - idle)
}

/**
 * Keeps one entry per device and size, the one with the shortest mount point. Bind mounts, LXC host mounts and btrfs
 * subvolumes otherwise show the same file system many times.
 */
fun dedupeDisks(disks: List<DiskUsage>): List<DiskUsage> =
    disks.groupBy { it.device to it.totalKiB }.values.map { same -> same.minBy { it.mount.length } }.sortedBy { it.mount }

/** CPU usage in percent between two counter readings, `null` if the counters went backwards (reboot). */
fun cpuPercent(previous: CpuTimes, current: CpuTimes): Double? {
    val total = current.total - previous.total
    val busy = current.busy - previous.busy
    if (total <= 0 || busy < 0) return null
    return busy * 100.0 / total
}

/**
 * Polls every host once per [interval] while somebody uses Dirl ([Presence]) and keeps the latest sample per host in
 * memory. There is no history and nothing is persisted.
 *
 * The poll goes through [ConnectionManager.connection], so it also connects every host when somebody arrives and
 * triggers the reconnects with backoff. Once nobody uses Dirl any more, the next round closes all connections with
 * [ConnectionManager.closeAll] and forgets the samples, so stale values are never shown as current. While the vault
 * is sealed it does nothing.
 *
 * A host whose previous poll still runs (a hanging host: connect, login and command can take a minute together) is
 * skipped instead of piling up waiting polls.
 *
 * @property vault Source of the host list.
 * @property connections Connection per host.
 * @property presence Whether anybody uses Dirl.
 * @property interval Time between rounds.
 * @property clock Unix milliseconds.
 */
class MetricsPoller(
    private val vault: Vault,
    private val connections: ConnectionManager,
    private val presence: Presence,
    private val interval: Duration = 1.minutes,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val latest = ConcurrentHashMap<String, MetricsSample>()
    private val polled = ConcurrentHashMap.newKeySet<String>()
    private val running = ConcurrentHashMap.newKeySet<String>()
    private val trigger = Channel<Unit>(Channel.CONFLATED)

    init {
        // Poll right after an unlock or an arrival instead of waiting up to a full interval with an empty overview.
        vault.listeners += { state -> if (state is VaultState.Unlocked) pollNow() }
        presence.arrivals += ::pollNow
    }

    /** Starts the poll loop in [scope]. */
    fun start(scope: CoroutineScope): Job = scope.launch(Dispatchers.IO) {
        while (isActive) {
            runCatching { round(this) }.onFailure { warnLog { "Status round failed: ${it.message}" } }
            withTimeoutOrNull(interval) { trigger.receive() }
        }
    }

    /**
     * One round: with somebody present, starts a poll in [scope] for every host whose previous poll is done.
     * Otherwise closes all connections and forgets the samples. Tests run it directly.
     *
     * @return the number of polls started.
     */
    fun round(scope: CoroutineScope): Int {
        val hosts = vault.content?.hosts ?: return 0
        if (presence.present.not()) {
            connections.closeAll()
            forgetAll()
            return 0
        }
        var started = 0
        hosts.forEach { host ->
            if (running.add(host.id).not()) return@forEach
            started++
            scope.launch {
                try {
                    // An unexpected error of one host must not end the loop: no more polls and no more closing.
                    runCatching {
                        // Pure jump hosts run no commands, the poll only keeps their connection alive.
                        if (host.jumpOnly) connections.connection(host.id) else pollHost(host.id)
                    }.onFailure { if (it !is CancellationException) warnLog { "Status poll of ${host.name} failed: ${it.message}" } }
                } finally {
                    running.remove(host.id)
                }
            }
        }
        return started
    }

    /** Runs the next round right away, e.g. after an unlock or when somebody arrives. */
    fun pollNow() {
        trigger.trySend(Unit)
    }

    /** The most recent sample of [hostId], if any. */
    fun latest(hostId: String): MetricsSample? = latest[hostId]

    /**
     * True once a poll of [hostId] finished since the host was last forgotten, with or without a usable sample. A host
     * whose output never parses (no `/proc`, `command="/bin/false"`) must not look like it is still loading forever.
     */
    fun polled(hostId: String): Boolean = hostId in polled

    /** Forgets everything about [hostId], e.g. after it was deleted. */
    fun forget(hostId: String) {
        latest.remove(hostId)
        polled.remove(hostId)
    }

    private fun forgetAll() {
        latest.clear()
        polled.clear()
    }

    private suspend fun pollHost(hostId: String) {
        val client = (connections.connection(hostId) as? ResultOf2.Success)?.value ?: return
        val output = withTimeoutOrNull(20.seconds) {
            runCatching {
                client.startSession().use { session ->
                    val command = session.exec(METRICS_COMMAND)
                    // The normal output is a few KiB, anything beyond the limit is dropped as unusable.
                    runInterruptible { command.inputStream.readAtMost(MAX_METRICS_OUTPUT)?.decodeToString() }
                }
            }.getOrNull()
        }
        // Nobody is there any more: a late result would show up as current value on the next arrival.
        if (presence.present.not()) return
        polled += hostId
        if (output == null) return

        when (val parsed = parseMetrics(output)) {
            is ResultOf2.Failure -> debugLog { "No metrics for host $hostId: ${parsed.value}" }
            is ResultOf2.Success -> record(hostId, parsed.value)
        }
    }

    private fun record(hostId: String, raw: RawMetrics) {
        latest[hostId] = MetricsSample(
            time = clock(),
            cpuPercent = raw.cpuPercent,
            memUsedKiB = raw.memTotalKiB - raw.memAvailableKiB,
            memTotalKiB = raw.memTotalKiB,
            swapUsedKiB = raw.swapTotalKiB - raw.swapFreeKiB,
            swapTotalKiB = raw.swapTotalKiB,
            load1 = raw.load1,
            uptimeSeconds = raw.uptimeSeconds,
            disks = raw.disks,
        )
    }
}
