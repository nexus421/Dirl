package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.readAtMost
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
        assertEquals("10.0.0.0/24,fd00::1", (parse("10.0.0.0/24,fd00::1") as ResultOf2.Success).value.sourceAddressForTargets)
        // A quote would end from="..." and could append options such as command= to the line.
        for (bad in listOf("10.0.0.1\",command=\"sh", "10.0.0.1 x", "a\nb")) assertIs<ResultOf2.Failure<List<String>>>(parse(bad), bad)
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

    @Test
    fun `metrics output is parsed`() {
        val output = """
            12345.67 23456.78
            0.15 0.10 0.05 1/123 4567
            cpu  100 0 50 800 50 0 0 0 0 0
            cpu  150 0 100 900 50 0 0 0 0 0
            MemTotal:        2048000 kB
            MemAvailable:    1024000 kB
            SwapTotal:        512000 kB
            SwapFree:         256000 kB
            Filesystem     Type 1024-blocks    Used Available Capacity Mounted on
            /dev/sda1      ext4    10000000 2500000   7500000      25% /
            /dev/sdb1      xfs     20000000 1000000  19000000       5% /srv/my data
        """.trimIndent()
        val raw = (parseMetrics(output) as ResultOf2.Success).value
        // Between the two readings: 200 jiffies in total, 100 of them busy.
        assertEquals(50.0, raw.cpuPercent)
        assertEquals(1024000, raw.memAvailableKiB)
        assertEquals(listOf("/", "/srv/my data"), raw.disks.map { it.mount })
        assertEquals(0.15, raw.load1)

        assertEquals(50.0, cpuPercent(CpuTimes(1000, 150), CpuTimes(1200, 250)))
        assertNull(cpuPercent(CpuTimes(1000, 150), CpuTimes(10, 5)))
        assertIs<ResultOf2.Failure<String>>(parseMetrics(""))
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
