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
 * address is written as placeholder.
 *
 * @param host The host the line is for.
 * @param key The key [host] logs in with.
 * @param allHosts All hosts, to find the ones tunneling through [host] and the jump host of [host].
 * @param sourceAddress The address hosts reached directly see Dirl coming from, `null` writes a placeholder.
 */
fun authorizedKeysLine(host: Host, key: SshKey, allHosts: List<Host>, sourceAddress: String?): String {
    val origin = if (host.jumpHostId == null) sourceAddress ?: "<DIRL-IP>"
    else allHosts.firstOrNull { it.id == host.jumpHostId }?.sourceAddressForTargets ?: "<JUMP-HOST-IP>"
    val from = "from=\"$origin\""
    // OpenSSH needs IPv6 addresses in brackets here, without them it rejects the whole line.
    val permits = allHosts.filter { it.jumpHostId == host.id }
        .map { "permitopen=\"${if (':' in it.address) "[${it.address}]" else it.address}:${it.port}\"" }.distinct().joinToString(",")
    val options = when {
        host.jumpOnly && permits.isEmpty() -> "restrict,command=\"/bin/false\",$from"
        host.jumpOnly -> "restrict,port-forwarding,$permits,$NO_REMOTE_FORWARDING,command=\"/bin/false\",$from"
        permits.isEmpty() -> "restrict,pty,$from"
        else -> "restrict,pty,port-forwarding,$permits,$NO_REMOTE_FORWARDING,$from"
    }
    return "$options ${key.publicKey} $KEY_COMMENT"
}

/** What `from="..."` in `authorized_keys` accepts: addresses, CIDR, host names, wildcards, negation, lists. */
val SOURCE_ADDRESS_PATTERN = Regex("^[A-Za-z0-9.:/*?,!\\[\\]-]{1,200}$")

/** Fingerprint of a public key line (`ssh-ed25519 AAAA...`), or `unknown` if the line cannot be parsed. */
fun fingerprintOfLine(publicKeyLine: String): String = runCatching {
    val blob = Base64.getDecoder().decode(publicKeyLine.trim().split(Regex("\\s+"))[1])
    "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(blob))
}.getOrDefault("unknown")
