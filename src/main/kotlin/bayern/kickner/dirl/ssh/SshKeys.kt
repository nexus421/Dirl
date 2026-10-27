package bayern.kickner.dirl.ssh

import bayern.kickner.dirl.newId
import bayern.kickner.dirl.secureRandom
import bayern.kickner.dirl.vault.Host
import bayern.kickner.dirl.vault.SshKey
import kotnexlib.ResultOf2
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil
import java.net.InetAddress
import java.security.MessageDigest
import java.security.PublicKey
import java.util.Base64

/** Comment appended to public key lines, so the key is recognizable in `authorized_keys`. */
const val KEY_COMMENT = "dirl"

/**
 * Generates a new Ed25519 key pair with BouncyCastle and returns it in OpenSSH format, the same format imported keys
 * are stored in.
 *
 * @param name Display name of the key.
 * @param now Unix milliseconds for [SshKey.createdAt].
 */
fun generateEd25519Key(name: String, now: Long = System.currentTimeMillis()): SshKey {
    val keyPair = Ed25519KeyPairGenerator()
        .apply { init(Ed25519KeyGenerationParameters(secureRandom)) }
        .generateKeyPair()
    val blob = OpenSSHPrivateKeyUtil.encodePrivateKey(keyPair.private)
    val pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
        Base64.getMimeEncoder(70, "\n".toByteArray()).encodeToString(blob) +
        "\n-----END OPENSSH PRIVATE KEY-----\n"
    val publicKey = "ssh-ed25519 " + Base64.getEncoder().encodeToString(OpenSSHPublicKeyUtil.encodePublicKey(keyPair.public))
    return SshKey(newId(), name, pem, publicKey, now)
}

/**
 * Imports an unencrypted private key in any format sshj reads (OpenSSH, PEM, PuTTY). The public key is derived from
 * it. Passphrase-protected keys are rejected: the vault encrypts the key anyway, decrypt it once with
 * `ssh-keygen -p -N "" -f key` before importing.
 *
 * @return the key, or a reason to show to the user.
 */
fun importPrivateKey(name: String, pem: String, now: Long = System.currentTimeMillis()): ResultOf2<SshKey, String> {
    val normalized = pem.trim().replace("\r\n", "\n") + "\n"
    val publicKey = runCatching { SSHClient().loadKeys(normalized, null, null).public }
        .getOrElse { return ResultOf2.Failure("Cannot read the private key. Is it unencrypted? (${it.message})") }
    return ResultOf2.Success(SshKey(newId(), name, normalized, publicKeyLine(publicKey), now))
}

/** Public key in `authorized_keys` format without comment, e.g. `ssh-ed25519 AAAA...`. */
fun publicKeyLine(key: PublicKey): String =
    KeyType.fromKey(key).toString() + " " + Base64.getEncoder().encodeToString(publicKeyBlob(key))

/** SSH wire encoding of a public key. */
fun publicKeyBlob(key: PublicKey): ByteArray = Buffer.PlainBuffer().putPublicKey(key).compactData

/** Fingerprint in the format of `ssh-keygen -lf`, e.g. `SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU`. */
fun fingerprint(key: PublicKey): String =
    "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(publicKeyBlob(key)))

/**
 * Limits TCP remote forwarding (`ssh -R`) to port 1 on loopback, which no forward Dirl needs. OpenSSH has no way to
 * say "none" here, `permitlisten="none"` makes it reject the whole line. Remote forwarding to Unix sockets cannot be
 * limited in `authorized_keys` at all, docs/security.md shows the `sshd_config` setting for it.
 */
private const val NO_REMOTE_FORWARDING = "permitlisten=\"127.0.0.1:1\""

/**
 * The `authorized_keys` line for [host] that limits what a stolen Dirl key can do.
 *
 * - A normal target gets `restrict,pty`: commands, a terminal and SFTP work, port forwarding, agent and X11
 *   forwarding do not.
 * - A jump host that is also used as terminal additionally gets `port-forwarding` with one `permitopen` per host
 *   behind it.
 * - A pure jump host ([Host.jumpOnly]) gets `restrict,port-forwarding,permitopen=...,command="/bin/false"`: it can
 *   only forward to the hosts that use it, nothing else. Without any host behind it, it gets no forwarding at all,
 *   because `port-forwarding` without `permitopen` would allow every destination.
 * - Both jump variants also get [NO_REMOTE_FORWARDING], because `port-forwarding` enables TCP remote forwarding
 *   (`ssh -R`) as well and `permitopen` does not limit it. Unix socket remote forwarding needs a server setting.
 *
 * Every line is limited with `from=` to the address the host sees the connection coming from: [sourceAddress] for
 * hosts Dirl reaches directly, [Host.sourceAddressForTargets] of the jump host for hosts behind one. A missing
 * address is written as placeholder. With [restrictSource] off the lines have no `from=` at all.
 *
 * @param host The host the line is for.
 * @param key The key [host] logs in with.
 * @param allHosts All hosts, to find the ones tunneling through [host] and the jump host of [host].
 * @param sourceAddress The address hosts reached directly see Dirl coming from, `null` writes a placeholder.
 * @param restrictSource `false` leaves `from=` out, see [bayern.kickner.dirl.vault.VaultSettings.sshSourceUnrestricted].
 */
fun authorizedKeysLine(host: Host, key: SshKey, allHosts: List<Host>, sourceAddress: String?, restrictSource: Boolean = true): String {
    val origin = when {
        restrictSource.not() -> null
        host.jumpHostId == null -> sourceAddress ?: "<DIRL-IP>"
        else -> allHosts.firstOrNull { it.id == host.jumpHostId }?.sourceAddressForTargets ?: "<JUMP-HOST-IP>"
    }
    val from = origin?.let { ",from=\"$it\"" }.orEmpty()
    // OpenSSH needs IPv6 addresses in brackets here, without them it rejects the whole line.
    val permits = allHosts.filter { it.jumpHostId == host.id }
        .map { "permitopen=\"${if (':' in it.address) "[${it.address}]" else it.address}:${it.port}\"" }.distinct().joinToString(",")
    val options = when {
        host.jumpOnly && permits.isEmpty() -> "restrict,command=\"/bin/false\"$from"
        host.jumpOnly -> "restrict,port-forwarding,$permits,$NO_REMOTE_FORWARDING,command=\"/bin/false\"$from"
        permits.isEmpty() -> "restrict,pty$from"
        else -> "restrict,pty,port-forwarding,$permits,$NO_REMOTE_FORWARDING$from"
    }
    return "$options ${key.publicKey} $KEY_COMMENT"
}

/** One entry of a `from="..."` list without CIDR: an address, a host name or a wildcard pattern, `!` excludes it. */
private val sourceEntryPattern = Regex("^!?[A-Za-z0-9.:*?-]+$")

/** One CIDR entry of a `from="..."` list, the address is checked separately. */
private val sourceCidrPattern = Regex("^(!?)([0-9A-Fa-f.:]+)/([0-9]{1,3})$")

/** Upper bound for a whole `from="..."` list, a handful of IPv6 ranges fit. */
private const val MAX_SOURCE_ADDRESS_LENGTH = 500

/**
 * Turns what a user typed as source address into the `from="..."` list OpenSSH needs: entries separated by commas,
 * without spaces. Users may separate entries with commas, spaces or both, empty entries are dropped and brackets
 * around IPv6 addresses removed. An empty input is `null`.
 *
 * Every entry that is left must be one OpenSSH accepts, because a single bad entry makes it refuse the whole line
 * without telling the client why. Verified against OpenSSH 10.2: a space after a comma, an empty entry, a CIDR prefix
 * that is too long and a CIDR range with host bits set (`10.0.0.1/24`) all do that. A list that only excludes (`!`)
 * matches nothing, so it is rejected as well.
 *
 * @return The normalized list, or a message for the user why the input cannot be used.
 */
fun normalizeSourceAddress(input: String): ResultOf2<String?, String> {
    val entries = input.split(',', ' ', '\t').map { it.trim() }.filter { it.isNotEmpty() }
        .map { if (it.startsWith("![")) "!" + it.drop(2).removeSuffix("]") else it.removeSurrounding("[", "]") }
    if (entries.isEmpty()) return ResultOf2.Success(null)
    for (entry in entries) {
        val cidr = sourceCidrPattern.matchEntire(entry)
        if (cidr == null) {
            if (sourceEntryPattern.matches(entry).not())
                return ResultOf2.Failure("\"$entry\" is not an address, CIDR range, host name or wildcard pattern.")
            continue
        }
        val (negation, address, prefixText) = cidr.destructured
        val bytes = ipLiteralBytes(address) ?: return ResultOf2.Failure("\"$entry\" does not start with an IP address.")
        val prefix = prefixText.toInt()
        if (prefix > bytes.size * 8) return ResultOf2.Failure("\"$entry\": the prefix length must be between 0 and ${bytes.size * 8}.")
        val network = bytes.copyOf()
        for (bit in prefix until bytes.size * 8) network[bit / 8] = (network[bit / 8].toInt() and (0x80 ushr (bit % 8)).inv()).toByte()
        if (network.contentEquals(bytes).not()) {
            val suggestion = "$negation${InetAddress.getByAddress(network).hostAddress}/$prefix"
            return ResultOf2.Failure("\"$entry\" has host bits set, which makes OpenSSH refuse the key. Did you mean $suggestion?")
        }
    }
    if (entries.all { it.startsWith("!") })
        return ResultOf2.Failure("The list only excludes addresses, so it matches nothing. Add at least one address without \"!\".")
    val normalized = entries.joinToString(",")
    if (normalized.length > MAX_SOURCE_ADDRESS_LENGTH) return ResultOf2.Failure("The source address may be at most $MAX_SOURCE_ADDRESS_LENGTH characters long.")
    return ResultOf2.Success(normalized)
}

/** The bytes of an IPv4 or IPv6 literal, `null` for anything else. Never resolves a name. */
private fun ipLiteralBytes(address: String): ByteArray? {
    // InetAddress parses literals with a colon as IPv6 and fails instead of resolving, IPv4 is parsed here because
    // InetAddress would look up anything that is not a valid dotted quad as a host name.
    if (':' in address) return runCatching { InetAddress.getByName(address).address }.getOrNull()
    val parts = address.split('.')
    if (parts.size != 4) return null
    return parts.map { part -> part.takeIf { it.length in 1..3 && it.all(Char::isDigit) }?.toInt()?.takeIf { it <= 255 } ?: return null }
        .map { it.toByte() }.toByteArray()
}

/** Fingerprint of a public key line (`ssh-ed25519 AAAA...`), or `unknown` if the line cannot be parsed. */
fun fingerprintOfLine(publicKeyLine: String): String = runCatching {
    val blob = Base64.getDecoder().decode(publicKeyLine.trim().split(Regex("\\s+"))[1])
    "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(blob))
}.getOrDefault("unknown")
