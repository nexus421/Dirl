package bayern.kickner.dirl.dev

import java.io.File

/** Port of the Dirl dev server. */
const val DEV_PORT = 18080

/** Port of the mock OIDC provider next to it. */
const val DEV_OIDC_PORT = 18081

/** Suggested vault passphrase for the throwaway dev vault in `build/dev`. Never use it for a real vault. */
const val DEV_PASSPHRASE = "dirl dev vault passphrase only"

/**
 * Starts Dirl for local UI development with the [MockOidcProvider] instead of a real provider. Run it with
 * `./gradlew devRun` and open `http://localhost:18080`. Data lives in `build/dev/data`, delete it to start over.
 */
fun main() {
    val oidc = MockOidcProvider(DEV_OIDC_PORT)
    val dir = File("build/dev").apply { mkdirs() }
    val config = File(dir, "config.json")
    config.writeText(
        """
        {
          "port": $DEV_PORT,
          "publicUrl": "http://localhost:$DEV_PORT",
          "dataDir": "${File(dir, "data").absolutePath}",
          "oidc": { "issuer": "${oidc.issuer}", "clientId": "dirl-dev", "clientSecret": "${oidc.clientSecret}", "forceReauth": false }
        }
        """.trimIndent()
    )
    println("Mock OIDC provider at ${oidc.issuer}, users: ${oidc.users.joinToString { "${it.name} (${it.sub})" }}")
    bayern.kickner.dirl.main(arrayOf("config=${config.absolutePath}"))
}
