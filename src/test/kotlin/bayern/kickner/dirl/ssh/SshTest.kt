package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.readAtMost
import bayern.kickner.dirl.vault.DEFAULT_OVERVIEW
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.OverviewMetric
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
        val jump = Host(id = "j", name = "jump", address = "203.0.113.1", username = "u", keyId = key.id, jumpOnly = true, sourceAddressForTargets = "10.0.0.1")
        val target = Host(id = "t", name = "db", address = "10.0.0.5", username = "u", keyId = key.id, jumpHostId = "j")
        val hosts = listOf(jump, target)
        val from = "from=\"192.0.2.9\""

        // The target sees the connection coming from the jump host, not from Dirl.
        assertEquals("restrict,pty,from=\"10.0.0.1\" ${key.publicKey} dirl", authorizedKeysLine(target, key, hosts, "192.0.2.9"))
        assertEquals("restrict,pty,from=\"<JUMP-HOST-IP>\" ${key.publicKey} dirl", authorizedKeysLine(target, key, listOf(jump.copy(sourceAddressForTargets = null), target), "192.0.2.9"))
        // In a chain every hop is limited to the hop before it.
        val inner = Host(id = "i", name = "inner", address = "10.0.0.7", username = "u", keyId = key.id, jumpHostId = "j", sourceAddressForTargets = "172.16.0.1")
        val deepest = Host(id = "d", name = "deep", address = "172.16.0.9", username = "u", keyId = key.id, jumpHostId = "i")
        assertTrue(authorizedKeysLine(inner, key, hosts + inner + deepest, "192.0.2.9").contains("from=\"10.0.0.1\""))
        assertTrue(authorizedKeysLine(deepest, key, hosts + inner + deepest, "192.0.2.9").contains("from=\"172.16.0.1\""))
        assertEquals(
            "restrict,port-forwarding,permitopen=\"10.0.0.5:22\",permitlisten=\"127.0.0.1:1\",command=\"/bin/false\",$from ${key.publicKey} dirl",
            authorizedKeysLine(jump, key, hosts, "192.0.2.9"),
        )
        // A jump host that is also a terminal target keeps its PTY and gets forwarding only to its targets.
        assertEquals(
            "restrict,pty,port-forwarding,permitopen=\"10.0.0.5:22\",permitlisten=\"127.0.0.1:1\",$from ${key.publicKey} dirl",
            authorizedKeysLine(jump.copy(jumpOnly = false), key, hosts, "192.0.2.9"),
        )
        // Two targets with the same address need only one permitopen.
        val twin = target.copy(id = "t2", name = "db2")
        assertEquals(1, Regex("permitopen").findAll(authorizedKeysLine(jump, key, hosts + twin, null)).count())
        // Without targets a pure jump host must not get port-forwarding, it would allow every destination.
        assertEquals("restrict,command=\"/bin/false\",$from ${key.publicKey} dirl", authorizedKeysLine(jump, key, listOf(jump), "192.0.2.9"))
        // OpenSSH only accepts IPv6 in permitopen inside brackets, without them it rejects the whole line.
        val v6 = target.copy(id = "t6", address = "fd00::5")
        assertTrue(authorizedKeysLine(jump, key, listOf(jump, v6), null).contains("permitopen=\"[fd00::5]:22\""))
    }

    @Test
    fun `IPv6 addresses are stored without brackets`() {
        val key = generateEd25519Key("k")
        val content = VaultContent(keys = listOf(key))
        fun form(address: String) = io.ktor.http.parametersOf(
            "name" to listOf("v6"), "address" to listOf(address), "port" to listOf("22"), "username" to listOf("root"), "keyId" to listOf(key.id),
        )
        assertEquals("fd00::5", (bayern.kickner.dirl.web.parseHostForm(form("[fd00::5]"), null, content) as ResultOf2.Success).value.address)
        assertEquals("fd00::5", (bayern.kickner.dirl.web.parseHostForm(form("fd00::5"), null, content) as ResultOf2.Success).value.address)
        assertIs<ResultOf2.Failure<List<String>>>(bayern.kickner.dirl.web.parseHostForm(form("[fd00::5"), null, content))
    }

    @Test
    fun `the address seen by hosts behind a jump host is optional and cannot break out of from=`() {
        val key = generateEd25519Key("k")
        val content = VaultContent(keys = listOf(key))
        fun parse(forTargets: String) = bayern.kickner.dirl.web.parseHostForm(io.ktor.http.parametersOf(
            "name" to listOf("jump"), "address" to listOf("203.0.113.1"), "port" to listOf("22"), "username" to listOf("root"),
            "keyId" to listOf(key.id), "sourceAddressForTargets" to listOf(forTargets),
        ), null, content)
        assertEquals(null, (parse(" ") as ResultOf2.Success).value.sourceAddressForTargets)
        assertEquals("10.0.0.1", (parse(" 10.0.0.1 ") as ResultOf2.Success).value.sourceAddressForTargets)
        assertEquals("10.0.0.0/24,fd00::1", (parse("10.0.0.0/24, fd00::1") as ResultOf2.Success).value.sourceAddressForTargets)
        // A quote would end from="..." and could append options such as command= to the line.
        for (bad in listOf("10.0.0.1\",command=\"sh", "10.0.0.1/24")) assertIs<ResultOf2.Failure<List<String>>>(parse(bad), bad)
    }

    @Test
    fun `source addresses are normalized to a list OpenSSH accepts`() {
        fun ok(input: String) = (normalizeSourceAddress(input) as ResultOf2.Success).value
        fun bad(input: String) = (normalizeSourceAddress(input) as ResultOf2.Failure).value
        assertNull(ok(""))
        assertNull(ok(" , "))
        // OpenSSH refuses the whole line for a space after a comma or an empty entry, see SshIntegrationTest.
        assertEquals("192.168.1.10,203.0.113.5", ok(" 192.168.1.10, 203.0.113.5 "))
        assertEquals("192.168.1.10,203.0.113.5", ok("192.168.1.10 203.0.113.5"))
        assertEquals("192.168.1.10,203.0.113.5", ok("192.168.1.10,,203.0.113.5,"))
        assertEquals("10.0.0.0/8,fd00::/8,!10.0.0.9,10.1.*,host-?.lan", ok("10.0.0.0/8, fd00::/8, !10.0.0.9, 10.1.*, host-?.lan"))
        assertEquals("fd00::1,!fd00::2", ok("[fd00::1], ![fd00::2]"))
        assertEquals("0.0.0.0/0", ok("0.0.0.0/0"))

        // A quote or a newline would end from="..." and could append options such as command= to the line.
        assertTrue(bad("10.0.0.1\",command=\"sh").contains("is not an address"))
        assertTrue(bad("10.0.0.1\nx\"").contains("is not an address"))
        assertTrue(bad("10.0.0.1/24").contains("Did you mean 10.0.0.0/24?"), bad("10.0.0.1/24"))
        assertTrue(bad("!10.0.0.1/24").contains("Did you mean !10.0.0.0/24?"))
        assertTrue(bad("fd00::1/64").contains("Did you mean fd00:0:0:0:0:0:0:0/64?"), bad("fd00::1/64"))
        assertTrue(bad("10.0.0.0/33").contains("between 0 and 32"))
        assertTrue(bad("fd00::/129").contains("between 0 and 128"))
        assertTrue(bad("10.0.0.256/32").contains("does not start with an IP address"))
        assertTrue(bad("10.0.0/24").contains("does not start with an IP address"))
        assertTrue(bad("10.0.0.*/24").contains("is not an address"))
        assertTrue(bad("!10.0.0.1, !10.0.0.2").contains("matches nothing"))
        assertTrue(bad("1.2.3.4,".repeat(70)).contains("at most 500"))
    }

    @Test
    fun `without the source restriction the authorized_keys lines have no from=`() {
        val key = generateEd25519Key("k")
        val jump = Host(id = "j", name = "jump", address = "203.0.113.1", username = "u", keyId = key.id, jumpOnly = true, sourceAddressForTargets = "10.0.0.1")
        val target = Host(id = "t", name = "db", address = "10.0.0.5", username = "u", keyId = key.id, jumpHostId = "j")
        val hosts = listOf(jump, target)
        assertEquals("restrict,pty ${key.publicKey} dirl", authorizedKeysLine(target, key, hosts, "192.0.2.9", restrictSource = false))
        assertEquals(
            "restrict,port-forwarding,permitopen=\"10.0.0.5:22\",permitlisten=\"127.0.0.1:1\",command=\"/bin/false\" ${key.publicKey} dirl",
            authorizedKeysLine(jump, key, hosts, "192.0.2.9", restrictSource = false),
        )
        assertEquals("restrict,command=\"/bin/false\" ${key.publicKey} dirl", authorizedKeysLine(jump, key, listOf(jump), null, restrictSource = false))
    }

    @Test
    fun `the overview choice of the host form only counts when the form showed it`() {
        val key = generateEd25519Key("k")
        val content = VaultContent(keys = listOf(key))
        fun parse(existing: Host?, vararg extra: Pair<String, List<String>>) = (bayern.kickner.dirl.web.parseHostForm(
            io.ktor.http.parametersOf(mapOf("name" to listOf("web"), "address" to listOf("10.0.0.5"), "port" to listOf("22"), "username" to listOf("root"), "keyId" to listOf(key.id)) + extra),
            existing, content,
        ) as ResultOf2.Success).value.overview
        assertEquals(DEFAULT_OVERVIEW, parse(null), "a form without the choice gives a new host the default")
        val existing = Host(id = "h", name = "web", address = "10.0.0.5", username = "root", keyId = key.id, overview = setOf(OverviewMetric.UPTIME))
        assertEquals(setOf(OverviewMetric.UPTIME), parse(existing), "and keeps the choice of an existing one")
        assertEquals(setOf(OverviewMetric.LOAD, OverviewMetric.ZRAM), parse(existing, "overviewShown" to listOf("1"), "overview" to listOf("ZRAM", "LOAD", "NOT_A_METRIC")))
        assertEquals(emptySet(), parse(existing, "overviewShown" to listOf("1")), "nothing ticked is a valid choice")
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
    fun `saving a jump host must not make the chain of a host behind it too long`() {
        val key = generateEd25519Key("k")
        fun h(id: String, jump: String? = null) = Host(id = id, name = id, address = "10.0.0.1", username = "root", keyId = key.id, jumpHostId = jump)
        // t goes through j, which is fine with one jump host. Giving j the jump host k (behind l) makes it three for t.
        val content = VaultContent(hosts = listOf(h("l"), h("k", "l"), h("j"), h("t", "j")), keys = listOf(key))
        fun save(jump: String) = bayern.kickner.dirl.web.parseHostForm(io.ktor.http.parametersOf(
            "name" to listOf("j"), "address" to listOf("10.0.0.1"), "port" to listOf("22"), "username" to listOf("root"),
            "keyId" to listOf(key.id), "jumpHostId" to listOf(jump),
        ), content.host("j"), content)

        val refused = assertIs<ResultOf2.Failure<List<String>>>(save("k"))
        assertTrue(refused.value.single().contains("t"), refused.value.single())
        // One jump host for j keeps t at two, that is allowed.
        assertIs<ResultOf2.Success<Host>>(save("l"))
        // A chain that was already broken before does not block saving a host it does not go through.
        val alreadyBroken = content.copy(hosts = content.hosts + h("x", "t") + h("y", "x"))
        val unrelated = bayern.kickner.dirl.web.parseHostForm(io.ktor.http.parametersOf(
            "name" to listOf("l2"), "address" to listOf("10.0.0.2"), "port" to listOf("22"), "username" to listOf("root"), "keyId" to listOf(key.id),
        ), content.host("l"), alreadyBroken)
        assertIs<ResultOf2.Success<Host>>(unrelated)
    }

    @Test
    fun `backoff grows from 30 seconds to 15 minutes`() {
        assertEquals(30_000, backoffDelayMillis(1))
        assertEquals(60_000, backoffDelayMillis(2))
        assertEquals(15 * 60_000, backoffDelayMillis(10))
    }

    /** Real output of [METRICS_COMMAND] on Debian 12 (a Crostini container), one failed unit, no zram. */
    private val realMetrics = """
        @@uptime
        7015.26 7015.26
        @@load
        0.54 0.50 0.37 1/1189 26615
        @@cpu
        cpu  248622 6 38212 10879058 19826 0 1011 2303 0 0
        cpu  248653 6 38218 10880615 19826 0 1011 2303 0 0
        @@cores
        16
        @@mem
        MemTotal:       14725120 kB
        MemAvailable:    6768156 kB
        SwapTotal:             0 kB
        SwapFree:              0 kB
        @@df
        Filesystem     Type     1024-blocks     Used Available Capacity Mounted on
        /dev/vdc       btrfs       62914560 32382564  27889404      54% /
        /dev/vdb       ext4           69008    67756         0     100% /opt/google/cros-containers
        /dev/vdc       btrfs       62914560 32382564  27889404      54% /dev/kvm
        @@vmlinuz
        @@boot
        @@rebootflag
        no
        @@failed
        systemd-binfmt.service loaded failed failed Set Up Additional Binary Formats
        @@failedrc
        0
        @@os
        PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
        @@kernel
        6.6.147-09705-g825c4d3a5018
        @@users
        0
        @@zram
    """.trimIndent()

    @Test
    fun `metrics output is parsed`() {
        val raw = (parseMetrics(realMetrics) as ResultOf2.Success).value
        assertEquals(7015.26, raw.uptimeSeconds)
        assertEquals(listOf(0.54, 0.50, 0.37), listOf(raw.load1, raw.load5, raw.load15))
        // Between the two readings: 1594 jiffies in total, 37 of them busy (idle and iowait do not count).
        assertEquals(37 * 100.0 / 1594, raw.cpuPercent)
        assertEquals(16, raw.cores)
        assertEquals(6768156, raw.memAvailableKiB)
        assertEquals(0, raw.swapTotalKiB)
        assertEquals(listOf("/", "/opt/google/cros-containers"), raw.disks.map { it.mount }, "the btrfs bind mount is shown once")
        assertNull(raw.reboot, "no kernel under /boot and no flag: cannot tell, like in a container")
        assertEquals(listOf("systemd-binfmt.service"), raw.failedUnits)
        assertEquals("Debian GNU/Linux 12 (bookworm)", raw.osName)
        assertEquals("6.6.147-09705-g825c4d3a5018", raw.kernel)
        assertEquals(0, raw.loggedInUsers)
        assertNull(raw.zram, "no zram swap")

        assertEquals(50.0, cpuPercent(CpuTimes(1000, 150), CpuTimes(1200, 250)))
        assertNull(cpuPercent(CpuTimes(1000, 150), CpuTimes(10, 5)))
        assertIs<ResultOf2.Failure<String>>(parseMetrics(""))
    }

    /** [realMetrics] with [section] replaced by [lines], or removed with `null`. */
    private fun withSection(section: String, lines: List<String>?): String {
        val out = mutableListOf<String>()
        var skipping = false
        realMetrics.lines().forEach { line ->
            if (line.startsWith("@@")) {
                skipping = line == "@@$section"
                if (skipping && lines != null) { out += line; out += lines }
                if (skipping.not()) out += line
            } else if (skipping.not()) out += line
        }
        return out.joinToString("\n")
    }

    @Test
    fun `a missing optional part leaves only that value unknown`() {
        fun parsed(text: String) = (parseMetrics(text) as ResultOf2.Success).value
        // No systemd as init or no systemctl at all: the exit code is not 0, the list is not trusted.
        assertNull(parsed(withSection("failedrc", listOf("127"))).failedUnits)
        assertNull(parsed(withSection("failedrc", null)).failedUnits)
        assertEquals(emptyList(), parsed(withSection("failed", emptyList())).failedUnits, "no failed unit is a known zero")
        assertNull(parsed(withSection("os", emptyList())).osName)
        assertNull(parsed(withSection("kernel", null)).kernel)
        assertNull(parsed(withSection("users", emptyList())).loggedInUsers, "who is missing")
        assertNull(parsed(withSection("cores", listOf("many"))).cores)
        assertNull(parsed(withSection("rebootflag", null)).reboot)
        assertEquals(RebootStatus(needed = true, newerKernel = null), parsed(withSection("rebootflag", listOf("yes"))).reboot)
        val noDisks = parsed(withSection("df", null))
        assertEquals(emptyList(), noDisks.disks)
        assertEquals(16, noDisks.cores, "everything else stays")
    }

    @Test
    fun `a reboot is needed when a newer kernel is installed or the system flags it`() {
        val running = "6.12.38+deb13-amd64"
        // Like the admin's script: /vmlinuz points to the newest kernel, else the last one installed in /boot.
        assertEquals(RebootStatus(true, "6.12.41+deb13-amd64"), rebootStatus(running, "/boot/vmlinuz-6.12.41+deb13-amd64", null, false))
        assertEquals(RebootStatus(false, null), rebootStatus(running, "/boot/vmlinuz-$running", "vmlinuz-6.1.0-old", false))
        assertEquals(RebootStatus(true, "6.12.41+deb13-amd64"), rebootStatus(running, null, "vmlinuz-6.12.41+deb13-amd64", false), "fallback to /boot")
        assertEquals(RebootStatus(false, null), rebootStatus(running, "/vmlinuz", "vmlinuz-$running", false), "no versioned target, /boot decides")
        assertEquals(RebootStatus(true, null), rebootStatus(running, "/boot/vmlinuz-$running", null, true), "the flag counts even with the right kernel")
        assertEquals(RebootStatus(true, "6.12.41+deb13-amd64"), rebootStatus(running, "/boot/vmlinuz-6.12.41+deb13-amd64", null, true), "a newer kernel is named even when the flag is set too, like the script")
        assertEquals(RebootStatus(true, null), rebootStatus(running, null, null, true), "a container with the flag")
        assertNull(rebootStatus(running, null, null, false), "a container without kernels and without flag")
        assertNull(rebootStatus(null, "/boot/vmlinuz-6.12.41", null, null), "without the running kernel nothing compares")
        assertNull(rebootStatus(running, null, "config-6.12", false), "only vmlinuz- files are kernels")

        val parsed = (parseMetrics(withSection("vmlinuz", listOf("/boot/vmlinuz-6.12.41+deb13-amd64"))
            .replace("6.6.147-09705-g825c4d3a5018", running)) as ResultOf2.Success).value
        assertEquals(RebootStatus(true, "6.12.41+deb13-amd64"), parsed.reboot)
    }

    @Test
    fun `uptime, load, memory and CPU are required like before`() {
        listOf("uptime", "load", "mem", "cpu").forEach { section ->
            assertIs<ResultOf2.Failure<String>>(parseMetrics(withSection(section, null)), section)
            assertIs<ResultOf2.Failure<String>>(parseMetrics(withSection(section, listOf("garbage"))), section)
        }
        // The output of the command before 0.3.0, without markers, is no valid output any more.
        assertIs<ResultOf2.Failure<String>>(parseMetrics("12345.67 23456.78\n0.15 0.10 0.05 1/123 4567\ncpu  100 0 50 800 50 0 0 0 0 0"))
    }

    @Test
    fun `zram devices used as swap are added up`() {
        val raw = (parseMetrics(withSection("zram", listOf(
            "1073741824 357913941 377487360 0 380000000 1234 0 12 12",
            "1073741824 357913941 377487360 0 380000000 1234 0 12",
            "not a stat line",
            "12 34",
        ))) as ResultOf2.Success).value
        assertEquals(ZramUsage(origBytes = 2147483648, comprBytes = 715827882, memUsedBytes = 754974720), raw.zram)
    }

    @Test
    fun `text from the server is cleaned and capped`() {
        fun parsed(section: String, vararg lines: String) = (parseMetrics(withSection(section, lines.toList())) as ResultOf2.Success).value
        assertEquals("Evil OS", parsed("os", "PRETTY_NAME=\"Evil\u0007\u001b[31m\u202e OS\"").osName, "control and direction characters are dropped")
        assertEquals(MAX_METRIC_TEXT, parsed("os", "PRETTY_NAME=\"" + "x".repeat(5000) + "\"").osName!!.length)
        assertEquals("Plain", parsed("os", "PRETTY_NAME=Plain").osName, "the value may be unquoted")
        assertEquals(MAX_METRIC_TEXT, parsed("kernel", "k".repeat(5000)).kernel!!.length)
        val many = parsed("failed", *Array(500) { "unit$it.service loaded failed failed Something" }).failedUnits!!
        assertEquals(MAX_FAILED_UNITS, many.size)
        assertEquals(listOf("a.service"), parsed("failed", "a.service\u0000 loaded failed failed X", "   ").failedUnits)
        assertNull(parsed("users", "-3").loggedInUsers)
        assertNull(parsed("cores", "0").cores)
    }

    @Test
    fun `reads from remote servers stop at the limit`() {
        assertEquals(10, ByteArray(10).inputStream().readAtMost(10)?.size)
        assertNull(ByteArray(11).inputStream().readAtMost(10))
        // An endless stream ends at the limit instead of filling the heap.
        val endless = object : java.io.InputStream() { override fun read() = 'x'.code }
        assertNull(endless.readAtMost(MAX_METRICS_OUTPUT))
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
    fun `the SFTP packet limit passes packets unchanged and refuses an oversized length before its content`() {
        fun packet(content: ByteArray) = java.nio.ByteBuffer.allocate(4 + content.size).putInt(content.size).put(content).array()
        val stream = packet(ByteArray(300) { it.toByte() }) + packet(ByteArray(0)) + packet("tail".toByteArray())
        // Read in odd chunks, so headers and contents are split across reads.
        for (chunk in listOf(1, 3, 7, 4096)) {
            val limited = SftpPacketLimit(stream.inputStream(), 300)
            val out = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(chunk)
            while (true) {
                val n = limited.read(buffer, 0, chunk)
                if (n < 0) break
                out.write(buffer, 0, n)
            }
            assertTrue(out.toByteArray().contentEquals(stream), "chunk $chunk")
        }
        assertEquals(stream[0].toInt() and 0xff, SftpPacketLimit(stream.inputStream(), 300).read())

        // One byte over the limit fails as soon as the fourth length byte is read, the content is never touched.
        val tooLarge = packet(ByteArray(301))
        val limited = SftpPacketLimit(tooLarge.inputStream(), 300)
        assertEquals(3, limited.read(ByteArray(3), 0, 3))
        val error = runCatching { limited.read(ByteArray(1), 0, 1) }.exceptionOrNull()
        assertTrue(error is java.io.IOException && error.message.orEmpty().contains("301 bytes"), "was: $error")
        // The largest length a header can carry, 4 GiB, is refused as well and not read as a negative number.
        val maxHeader = byteArrayOf(-1, -1, -1, -1)
        assertTrue(runCatching { SftpPacketLimit(maxHeader.inputStream(), 300).read(ByteArray(4), 0, 4) }.isFailure)
    }
}
