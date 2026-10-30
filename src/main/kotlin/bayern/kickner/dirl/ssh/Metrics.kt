package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.cleanText
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
import net.schmizz.sshj.SSHClient
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The one command run every minute on each host while somebody uses Dirl. Every part starts with a marker line
 * (`@@name`), so a part that is missing on a host (no systemd, no `who`, no zram) leaves only its own value unknown.
 *
 * `LC_ALL=C` keeps the output parseable, `df -l` skips network and FUSE mounts and `timeout 5` keeps a dead mount or
 * a hanging systemd from blocking the channel. `/proc/stat` is read twice, one second apart, so every poll yields the
 * CPU usage on its own, also the first one after an arrival. The load averages come from the kernel, one reading is
 * enough. A reboot is needed like Debian tells it: `/vmlinuz` points to the newest installed kernel, else the last
 * `vmlinuz-*` installed in `/boot`, and `/run/reboot-required` flags it as well. The exit code of `systemctl` is part
 * of the output, without systemd as init its list is not trusted. zram counts only devices that are active swap.
 */
const val METRICS_COMMAND =
    "LC_ALL=C sh -c '" +
        "echo @@uptime; cat /proc/uptime; " +
        "echo @@load; cat /proc/loadavg; " +
        "echo @@cpu; head -n1 /proc/stat; sleep 1; head -n1 /proc/stat; " +
        "echo @@cores; nproc 2>/dev/null; " +
        "echo @@mem; grep -E \"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\" /proc/meminfo; " +
        "echo @@df; timeout 5 df -PlkT -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs; " +
        "echo @@vmlinuz; test -e /vmlinuz && readlink -f /vmlinuz; " +
        "echo @@boot; ls -tc /boot 2>/dev/null | grep \"^vmlinuz-\" | head -n1; " +
        "echo @@rebootflag; if test -e /run/reboot-required; then echo yes; else echo no; fi; " +
        "echo @@failed; timeout 5 systemctl list-units --state=failed --no-legend --plain 2>/dev/null; r=\$?; " +
        "echo @@failedrc; echo \$r; " +
        "echo @@os; grep -E \"^PRETTY_NAME=\" /etc/os-release 2>/dev/null; " +
        "echo @@kernel; uname -r; " +
        "echo @@users; command -v who >/dev/null && who | wc -l; " +
        "echo @@zram; for d in \$(grep -o \"^/dev/zram[0-9]*\" /proc/swaps 2>/dev/null); do cat /sys/block/\$(basename \$d)/mm_stat 2>/dev/null; done" +
        "'"

/** Upper bound of the metrics command's output. Real output is a few KiB even with many mounts. */
const val MAX_METRICS_OUTPUT = 256 * 1024

/** Upper bound for text from a server (system name, kernel, unit names), longer text is cut. */
const val MAX_METRIC_TEXT = 100

/** At most this many failed units are kept, the count shows them all only up to here. */
const val MAX_FAILED_UNITS = 50

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
 * Whether the host needs a reboot.
 *
 * @property needed `true` if a newer kernel is installed than the one running, or the system set
 *   `/run/reboot-required`.
 * @property newerKernel The installed kernel that differs from the running one, `null` if only the flag says so.
 */
data class RebootStatus(val needed: Boolean, val newerKernel: String?)

/**
 * zram used as swap, all such devices added up, from `/sys/block/zramN/mm_stat`.
 *
 * @property origBytes Data stored, uncompressed.
 * @property comprBytes The same data compressed.
 * @property memUsedBytes RAM zram really takes for it, with overhead.
 */
data class ZramUsage(val origBytes: Long, val comprBytes: Long, val memUsedBytes: Long)

/**
 * The parsed output of [METRICS_COMMAND]. Values after [disks] are `null` when the host could not tell.
 *
 * @property cpuPercent CPU usage during the second between the two readings, `null` if it could not be computed.
 * @property cores Number of CPUs this system may use (`nproc`).
 * @property reboot See [rebootStatus].
 * @property failedUnits Names of failed systemd units, at most [MAX_FAILED_UNITS]. `null` without systemd.
 * @property osName `PRETTY_NAME` from `/etc/os-release`.
 * @property kernel The running kernel (`uname -r`).
 * @property loggedInUsers Logins with a terminal (`who`), Dirl's own terminals included.
 * @property zram `null` if no zram device is used as swap.
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
    val cores: Int? = null,
    val reboot: RebootStatus? = null,
    val failedUnits: List<String>? = null,
    val osName: String? = null,
    val kernel: String? = null,
    val loggedInUsers: Int? = null,
    val zram: ZramUsage? = null,
)

/**
 * The latest status of a host.
 *
 * @property time Unix milliseconds.
 * @property raw Everything the host sent, see [RawMetrics].
 */
data class MetricsSample(val time: Long, val raw: RawMetrics) {
    /** CPU usage during one second of the poll, `null` if it could not be computed. */
    val cpuPercent: Double? get() = raw.cpuPercent

    /** `MemTotal - MemAvailable`. */
    val memUsedKiB: Long get() = raw.memTotalKiB - raw.memAvailableKiB

    /** Total RAM. */
    val memTotalKiB: Long get() = raw.memTotalKiB

    /** `SwapTotal - SwapFree`, includes zram used as swap. */
    val swapUsedKiB: Long get() = raw.swapTotalKiB - raw.swapFreeKiB

    /** Total swap, `0` without swap. */
    val swapTotalKiB: Long get() = raw.swapTotalKiB

    /** Seconds since boot. */
    val uptimeSeconds: Double get() = raw.uptimeSeconds

    /** Mounted file systems, see [dedupeDisks]. */
    val disks: List<DiskUsage> get() = raw.disks
}

private val markerLine = Regex("@@([a-z]+)")
private val whitespace = Regex("\\s+")

/** The lines of each `@@name` part. Lines before the first marker are dropped, a repeated marker wins. */
private fun sectionsOf(output: String): Map<String, List<String>> {
    val sections = mutableMapOf<String, MutableList<String>>()
    var current: MutableList<String>? = null
    output.lines().forEach { line ->
        val marker = markerLine.matchEntire(line.trim())
        if (marker != null) current = mutableListOf<String>().also { sections[marker.groupValues[1]] = it }
        else if (line.isNotBlank()) current?.add(line)
    }
    return sections
}

/**
 * Whether a reboot is needed, the same way an admin script on Debian decides it: the newest installed kernel is the
 * target of `/vmlinuz`, else the last `vmlinuz-*` installed in `/boot`. It differs from the running one, or
 * `/run/reboot-required` exists.
 *
 * @param running `uname -r`.
 * @param vmlinuzTarget Where `/vmlinuz` points, `null` if it does not exist.
 * @param newestInBoot The newest `vmlinuz-*` file name in `/boot` by ctime.
 * @param flagged Whether `/run/reboot-required` exists, `null` if unknown.
 * @return `null` if it cannot be told: no installed kernel visible (a container) and no flag.
 */
fun rebootStatus(running: String?, vmlinuzTarget: String?, newestInBoot: String?, flagged: Boolean?): RebootStatus? {
    fun versionOf(fileName: String?) = fileName?.takeIf { it.startsWith("vmlinuz-") }?.removePrefix("vmlinuz-")?.ifEmpty { null }
    val newest = versionOf(vmlinuzTarget?.substringAfterLast('/')) ?: versionOf(newestInBoot)
    return when {
        running != null && newest != null && newest != running -> RebootStatus(needed = true, newerKernel = newest)
        flagged == true -> RebootStatus(needed = true, newerKernel = null)
        running != null && newest != null -> RebootStatus(needed = false, newerKernel = null)
        else -> null
    }
}

/**
 * Parses the output of [METRICS_COMMAND]. Uptime, load, memory and CPU are required like before, the rest is
 * optional and `null` if a host does not deliver it.
 *
 * @return the values, or a reason for the log. Hosts restricted with `command="/bin/false"` (pure jump hosts)
 *   produce no output and end up here.
 */
fun parseMetrics(output: String): ResultOf2<RawMetrics, String> = runCatching {
    val sections = sectionsOf(output)
    fun required(name: String) = sections[name]?.takeIf { it.isNotEmpty() } ?: error("no $name in the output")
    fun single(name: String) = sections[name]?.firstOrNull()?.trim()

    val uptime = required("uptime")[0].trim().split(whitespace)[0].toDouble()
    val load = required("load")[0].trim().split(whitespace)
    val cpuLines = required("cpu").filter { it.startsWith("cpu ") }
    require(cpuLines.isNotEmpty()) { "no cpu line from /proc/stat" }
    val cpuBefore = cpuTimesOf(cpuLines.first())
    val cpuAfter = cpuTimesOf(cpuLines.last())

    val mem = required("mem").mapNotNull { line ->
        val match = Regex("^(\\w+):\\s+(\\d+) kB").find(line) ?: return@mapNotNull null
        match.groupValues[1] to match.groupValues[2].toLong()
    }.toMap()

    val dfLines = sections["df"].orEmpty()
    val dfHeader = dfLines.indexOfFirst { it.startsWith("Filesystem") }
    val disks = if (dfHeader < 0) emptyList() else dfLines.drop(dfHeader + 1).mapNotNull { line ->
        val cols = line.trim().split(whitespace)
        if (cols.size < 7) return@mapNotNull null
        DiskUsage(device = cols[0], mount = cols.drop(6).joinToString(" "), fsType = cols[1], totalKiB = cols[2].toLong(), usedKiB = cols[3].toLong())
    }.let(::dedupeDisks)

    val kernel = single("kernel")?.let { cleanText(it, MAX_METRIC_TEXT) }
    val flagged = when (single("rebootflag")) {
        "yes" -> true
        "no" -> false
        else -> null
    }
    // Without systemd as init or without systemctl the exit code is not 0, then the list means nothing.
    val failedUnits = if (single("failedrc") != "0") null else sections["failed"].orEmpty()
        .mapNotNull { line -> cleanText(line, MAX_METRIC_TEXT)?.substringBefore(' ') }
        .take(MAX_FAILED_UNITS)
    val zram = sections["zram"].orEmpty()
        .mapNotNull { line -> line.trim().split(whitespace).take(3).mapNotNull { it.toLongOrNull() }.takeIf { it.size == 3 } }
        .takeIf { it.isNotEmpty() }
        ?.let { devices -> ZramUsage(devices.sumOf { it[0] }, devices.sumOf { it[1] }, devices.sumOf { it[2] }) }

    RawMetrics(
        uptimeSeconds = uptime,
        load1 = load[0].toDouble(), load5 = load[1].toDouble(), load15 = load[2].toDouble(),
        cpuPercent = if (cpuLines.size < 2) null else cpuPercent(cpuBefore, cpuAfter),
        memTotalKiB = mem.getValue("MemTotal"),
        memAvailableKiB = mem.getValue("MemAvailable"),
        swapTotalKiB = mem["SwapTotal"] ?: 0,
        swapFreeKiB = mem["SwapFree"] ?: 0,
        disks = disks,
        cores = single("cores")?.toIntOrNull()?.takeIf { it in 1..65536 },
        reboot = rebootStatus(kernel, single("vmlinuz"), single("boot"), flagged),
        failedUnits = failedUnits,
        osName = single("os")?.removePrefix("PRETTY_NAME=")?.trim()?.removeSurrounding("\"")?.let { cleanText(it, MAX_METRIC_TEXT) },
        kernel = kernel,
        loggedInUsers = single("users")?.toIntOrNull()?.takeIf { it >= 0 },
        zram = zram,
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

/** How long [roundTripMillis] waits for the answer. */
private val ROUND_TRIP_TIMEOUT = 5.seconds

/**
 * The time an SSH request to the server and its answer take, in milliseconds, or `null` without an answer within
 * [ROUND_TRIP_TIMEOUT]. It goes through the existing connection, through the jump hosts as well, so it is what the
 * host feels like from Dirl, not from the browser. Needs no rights, unlike ICMP ping.
 *
 * The request is OpenSSH's `keepalive@openssh.com`, which sshj also sends to keep connections alive. OpenSSH answers
 * it with a failure, any answer counts.
 */
suspend fun roundTripMillis(client: SSHClient): Double? = runCatching {
    runInterruptible {
        val start = System.nanoTime()
        val promise = client.connection.sendGlobalRequest("keepalive@openssh.com", true, ByteArray(0))
        runCatching { promise.tryRetrieve(ROUND_TRIP_TIMEOUT.inWholeMilliseconds, TimeUnit.MILLISECONDS) }
        val millis = (System.nanoTime() - start) / 1_000_000.0
        // A lost connection fulfills the promise with an error as well, that is no answer.
        millis.takeIf { promise.isFulfilled && client.isConnected }
    }
}.getOrNull()

/**
 * Polls every host once per [interval] while somebody uses Dirl ([Presence]) and keeps the latest sample and the round
 * trip ([roundTripMillis]) per host in memory. There is no history and nothing is persisted.
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
    private val latency = ConcurrentHashMap<String, Double>()
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
                        // Pure jump hosts run no commands, the poll only keeps their connection alive and measures it.
                        if (host.jumpOnly) measure(host.id, (connections.connection(host.id) as? ResultOf2.Success)?.value)
                        else pollHost(host.id)
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

    /** The round trip of the latest poll of [hostId] in milliseconds, see [roundTripMillis]. `null` if unknown. */
    fun latencyMillis(hostId: String): Double? = latency[hostId]

    /**
     * True once a poll of [hostId] finished since the host was last forgotten, with or without a usable sample. A host
     * whose output never parses (no `/proc`, `command="/bin/false"`) must not look like it is still loading forever.
     */
    fun polled(hostId: String): Boolean = hostId in polled

    /** Forgets everything about [hostId], e.g. after it was deleted. */
    fun forget(hostId: String) {
        latest.remove(hostId)
        latency.remove(hostId)
        polled.remove(hostId)
    }

    private fun forgetAll() {
        latest.clear()
        latency.clear()
        polled.clear()
    }

    /** Measures the round trip of [client], forgets the old value if there is no connection or no answer. */
    private suspend fun measure(hostId: String, client: SSHClient?) {
        val millis = client?.let { roundTripMillis(it) }
        if (presence.present.not()) return
        if (millis == null) latency.remove(hostId) else latency[hostId] = millis
    }

    private suspend fun pollHost(hostId: String) {
        val client = (connections.connection(hostId) as? ResultOf2.Success)?.value
        measure(hostId, client)
        if (client == null) return
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

    /** Keeps [millis] as the latest round trip of [hostId]. Internal so web tests can show one without a server. */
    internal fun recordLatency(hostId: String, millis: Double) {
        latency[hostId] = millis
    }

    /** Keeps [raw] as the latest sample of [hostId]. Internal so web tests can show a sample without a server. */
    internal fun record(hostId: String, raw: RawMetrics) {
        latest[hostId] = MetricsSample(time = clock(), raw = raw)
    }
}
