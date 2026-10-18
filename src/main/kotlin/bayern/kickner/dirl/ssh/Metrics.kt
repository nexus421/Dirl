package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.readAtMost
import bayern.kickner.dirl.vault.Vault
import bayern.kickner.dirl.vault.VaultState
import bayern.kickner.klogger.debugLog
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
 * The one command run every minute on each host. `LC_ALL=C` keeps the output parseable, `df -l` skips network and
 * FUSE mounts and `timeout 5` keeps a dead mount from hanging the channel.
 */
const val METRICS_COMMAND =
    "LC_ALL=C sh -c 'cat /proc/uptime /proc/loadavg; head -n1 /proc/stat; " +
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

/** The parsed output of [METRICS_COMMAND], before the CPU delta is computed. */
data class RawMetrics(
    val uptimeSeconds: Double,
    val load1: Double,
    val load5: Double,
    val load15: Double,
    val cpu: CpuTimes,
    val memTotalKiB: Long,
    val memAvailableKiB: Long,
    val swapTotalKiB: Long,
    val swapFreeKiB: Long,
    val disks: List<DiskUsage>,
)

/**
 * One point of a host's history.
 *
 * @property time Unix milliseconds.
 * @property cpuPercent CPU usage since the previous sample, `null` for the first sample after a (re)connect.
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
    val cpuLine = lines.first { it.startsWith("cpu ") }
    val cpuFields = cpuLine.trim().split(Regex("\\s+")).drop(1).map { it.toLong() }
    val total = cpuFields.take(8).sum()
    val idle = cpuFields[3] + cpuFields.getOrElse(4) { 0 }

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
        cpu = CpuTimes(total, total - idle),
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
 * Polls every host once per [interval] and keeps the last [capacity] samples per host in memory (24 h at one per
 * minute). Nothing is persisted, a restart starts with empty history.
 *
 * The poll goes through [ConnectionManager.connection], so it also keeps connections alive and triggers the
 * reconnects with backoff. While the vault is sealed it does nothing.
 *
 * @property vault Source of the host list.
 * @property connections Connection per host.
 * @property interval Time between polls.
 * @property capacity Samples kept per host.
 * @property clock Unix milliseconds.
 */
class MetricsPoller(
    private val vault: Vault,
    private val connections: ConnectionManager,
    private val interval: Duration = 1.minutes,
    private val capacity: Int = 1440,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val history = ConcurrentHashMap<String, ArrayDeque<MetricsSample>>()
    private val lastCpu = ConcurrentHashMap<String, CpuTimes>()
    private val trigger = Channel<Unit>(Channel.CONFLATED)

    init {
        // Poll right after an unlock instead of waiting up to a full interval with an empty overview.
        vault.listeners += { state -> if (state is VaultState.Unlocked) pollNow() }
    }

    /** Starts the poll loop in [scope]. */
    fun start(scope: CoroutineScope): Job = scope.launch(Dispatchers.IO) {
        while (isActive) {
            // Pure jump hosts run no commands, the poll only keeps their connection alive.
            vault.content?.hosts?.forEach { host -> launch { if (host.jumpOnly) connections.connection(host.id) else pollHost(host.id) } }
            withTimeoutOrNull(interval) { trigger.receive() }
        }
    }

    /** Runs the next poll right away, e.g. after an unlock. */
    fun pollNow() {
        trigger.trySend(Unit)
    }

    /** The most recent sample of [hostId], if any. */
    fun latest(hostId: String): MetricsSample? = history[hostId]?.let { synchronized(it) { it.lastOrNull() } }

    /** A copy of the history of [hostId], oldest first. */
    fun history(hostId: String): List<MetricsSample> = history[hostId]?.let { synchronized(it) { it.toList() } } ?: emptyList()

    /** Forgets everything about [hostId], e.g. after it was deleted. */
    fun forget(hostId: String) {
        history.remove(hostId)
        lastCpu.remove(hostId)
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
        } ?: return

        when (val parsed = parseMetrics(output)) {
            is ResultOf2.Failure -> debugLog { "No metrics for host $hostId: ${parsed.value}" }
            is ResultOf2.Success -> record(hostId, parsed.value)
        }
    }

    private fun record(hostId: String, raw: RawMetrics) {
        val previous = lastCpu.put(hostId, raw.cpu)
        val sample = MetricsSample(
            time = clock(),
            cpuPercent = previous?.let { cpuPercent(it, raw.cpu) },
            memUsedKiB = raw.memTotalKiB - raw.memAvailableKiB,
            memTotalKiB = raw.memTotalKiB,
            swapUsedKiB = raw.swapTotalKiB - raw.swapFreeKiB,
            swapTotalKiB = raw.swapTotalKiB,
            load1 = raw.load1,
            uptimeSeconds = raw.uptimeSeconds,
            disks = raw.disks,
        )
        val buffer = history.computeIfAbsent(hostId) { ArrayDeque(capacity) }
        synchronized(buffer) {
            if (buffer.size >= capacity) buffer.removeFirst()
            buffer.addLast(sample)
        }
    }
}
