package bayern.kickner.dirl.vault

import bayern.kickner.dirl.audit.Actor
import bayern.kickner.dirl.config.AppConfig
import bayern.kickner.dirl.config.OidcConfig
import bayern.kickner.dirl.createDirl
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The files in the data directory that hold the vault, its backups, the audit log and the access list are readable by
 * the owner only, whatever the umask of the process. docs/security.md promises it. Skipped without POSIX permissions.
 */
class FilePermissionsTest {
    @Test
    fun `vault, backups, audit log and access list are only readable by the owner`() {
        assumeTrue("posix" in FileSystems.getDefault().supportedFileAttributeViews(), "no POSIX permissions here")
        val dataDir = Files.createTempDirectory("dirl-modes").toFile()
        val dirl = createDirl(
            AppConfig(publicUrl = "https://ssh.example.com", dataDir = dataDir.absolutePath, oidc = OidcConfig(issuer = "https://id.example.com", clientId = "dirl", clientSecret = "secret")),
            dataDir,
        )
        val actor = Actor("user-1", "Ada")
        dirl.vault.setup("correct horse battery staple extra".toCharArray(), actor)
        // Every write keeps the previous file as a backup, four writes fill all three backups.
        repeat(4) { round -> dirl.vault.update { it.copy(snippets = it.snippets + Snippet("s$round", "Snippet $round", "echo $round", null)) } }
        dirl.access.allow("user-2", "Bob", actor)

        val expected = listOf("vault.json", "vault.json.1", "vault.json.2", "vault.json.3", "audit.jsonl", "access.json")
        val modes = expected.associateWith { name ->
            val file = File(dataDir, name)
            if (file.isFile) Files.getPosixFilePermissions(file.toPath()) else null
        }
        assertEquals(expected.associateWith { setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE) }, modes)
        dataDir.deleteRecursively()
    }
}
