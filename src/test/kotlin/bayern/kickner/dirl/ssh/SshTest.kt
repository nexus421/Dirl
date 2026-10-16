package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.VaultContent
import kotnexlib.ResultOf2
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SshTest {

    @Test
    fun `a BouncyCastle Ed25519 key loads in sshj with the same public key`() {
        val generated = generateEd25519Key("test")
        assertTrue(generated.privateKeyPem.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----"))
        val imported = (importPrivateKey("again", generated.privateKeyPem) as ResultOf2.Success).value
        assertEquals(generated.publicKey, imported.publicKey)
    }

    @Test
    fun `garbage is not imported`() {
        assertIs<ResultOf2.Failure<String>>(importPrivateKey("x", "not a key"))
    }

    @Test
    fun `authorized_keys lines restrict targets and jump hosts`() {
        val key = generateEd25519Key("k")
        val jump = Host(id = "j", name = "jump", address = "203.0.113.1", username = "u", keyId = key.id, jumpOnly = true)
        val target = Host(id = "t", name = "db", address = "10.0.0.5", username = "u", keyId = key.id, jumpHostId = "j")
        val hosts = listOf(jump, target)
        val from = "from=\"192.0.2.9\""

        assertEquals("restrict,pty,$from ${key.publicKey} dirl", authorizedKeysLine(target, key, hosts, "192.0.2.9"))
        assertEquals(
            "restrict,port-forwarding,permitopen=\"10.0.0.5:22\",command=\"/bin/false\",$from ${key.publicKey} dirl",
            authorizedKeysLine(jump, key, hosts, "192.0.2.9"),
        )
        // A jump host that is also a terminal target keeps its PTY and gets forwarding only to its targets.
        assertEquals(
            "restrict,pty,port-forwarding,permitopen=\"10.0.0.5:22\",$from ${key.publicKey} dirl",
            authorizedKeysLine(jump.copy(jumpOnly = false), key, hosts, "192.0.2.9"),
        )
        // Two targets with the same address need only one permitopen.
        val twin = target.copy(id = "t2", name = "db2")
        assertEquals(1, Regex("permitopen").findAll(authorizedKeysLine(jump, key, hosts + twin, null)).count())
        // Without targets a pure jump host must not get port-forwarding, it would allow every destination.
        assertEquals("restrict,command=\"/bin/false\",$from ${key.publicKey} dirl", authorizedKeysLine(jump, key, listOf(jump), "192.0.2.9"))
    }

    @Test
    fun `routes reject cycles and too many hops`() {
        val keys = listOf(generateEd25519Key("k"))
        fun h(id: String, jump: String?) = Host(id = id, name = id, address = "a", username = "u", keyId = keys[0].id, jumpHostId = jump)

        val chain = VaultContent(hosts = listOf(h("a", null), h("b", "a"), h("c", "b")), keys = keys)
        assertEquals(listOf("a", "b", "c"), (resolveRoute(chain, "c") as ResultOf2.Success).value.map { it.id })

        val tooLong = chain.copy(hosts = chain.hosts + h("d", "c"))
        assertIs<ResultOf2.Failure<String>>(resolveRoute(tooLong, "d"))

        val cycle = VaultContent(hosts = listOf(h("a", "b"), h("b", "a")), keys = keys)
        assertIs<ResultOf2.Failure<String>>(resolveRoute(cycle, "a"))
    }

    @Test
    fun `backoff grows from 30 seconds to 15 minutes`() {
        assertEquals(30_000, backoffDelayMillis(1))
        assertEquals(60_000, backoffDelayMillis(2))
        assertEquals(15 * 60_000, backoffDelayMillis(10))
    }

    @Test
    fun `metrics output is parsed`() {
        val output = """
            12345.67 23456.78
            0.15 0.10 0.05 1/123 4567
            cpu  100 0 50 800 50 0 0 0 0 0
            MemTotal:        2048000 kB
            MemAvailable:    1024000 kB
            SwapTotal:        512000 kB
            SwapFree:         256000 kB
            Filesystem     Type 1024-blocks    Used Available Capacity Mounted on
            /dev/sda1      ext4    10000000 2500000   7500000      25% /
            /dev/sdb1      xfs     20000000 1000000  19000000       5% /srv/my data
        """.trimIndent()
        val raw = (parseMetrics(output) as ResultOf2.Success).value
        assertEquals(1000, raw.cpu.total)
        assertEquals(150, raw.cpu.busy)
        assertEquals(1024000, raw.memAvailableKiB)
        assertEquals(listOf("/", "/srv/my data"), raw.disks.map { it.mount })
        assertEquals(0.15, raw.load1)

        assertEquals(50.0, cpuPercent(CpuTimes(1000, 150), CpuTimes(1200, 250)))
        assertNull(cpuPercent(CpuTimes(1000, 150), CpuTimes(10, 5)))
        assertIs<ResultOf2.Failure<String>>(parseMetrics(""))
    }

    @Test
    fun `bind mounts and subvolumes of one file system are shown once`() {
        val disks = listOf(
            DiskUsage("/dev/nvme0n1p2", "/run/host/var/log", "btrfs", 100, 80),
            DiskUsage("/dev/nvme0n1p2", "/", "btrfs", 100, 80),
            DiskUsage("/dev/nvme0n1p1", "/boot", "vfat", 10, 1),
        )
        assertEquals(listOf("/", "/boot"), dedupeDisks(disks).map { it.mount })
    }

    @Test
    fun `charts contain only numbers and fixed text`() {
        val samples = listOf(10.0, 55.5, 99.0).mapIndexed { i, cpu ->
            MetricsSample(1_000_000L + i * 60_000, cpu, 1, 2, 0, 0, 0.1, 1.0, emptyList())
        }
        val svg = bayern.kickner.dirl.web.renderChart(samples, bayern.kickner.dirl.web.ChartMetric.CPU, 1_000_000L + 180_000)
        assertTrue(svg.contains("<polyline"))
        // A short history spans the whole width: the first point sits at the left edge.
        assertTrue(svg.contains("points=\"0.0,"), svg)
        assertTrue(bayern.kickner.dirl.web.renderChart(emptyList(), bayern.kickner.dirl.web.ChartMetric.CPU, 0).contains("<polyline").not())
    }
}
